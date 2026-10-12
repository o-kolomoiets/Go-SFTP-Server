// SPDX-License-Identifier: Apache-2.0

// Package sandbox confines gosftpd with Landlock on Linux (ADR 0011). Once
// the listeners are bound and everything gosftpd opens at start is open,
// Start applies a ruleset computed from the configuration: the process can
// then reach only its mounts, its configuration and key files, its audit
// log, /proc/self and the files that name resolution reads. A ruleset
// cannot be lifted; a reload checks what the new configuration uses
// against the rules kept from the start (Ruleset.Check). On other systems
// Start applies nothing.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// Rights is a set of Landlock file system access rights, with the
// kernel's bit values (LANDLOCK_ACCESS_FS_*).
type Rights uint64

// The rights gosftpd grants. It handles every right of ABI 5; the others
// (execute, make_char, make_sock, make_fifo, make_block, make_sym and
// ioctl_dev) are never granted.
const (
	WriteFile  Rights = 1 << 1
	ReadFile   Rights = 1 << 2
	ReadDir    Rights = 1 << 3
	RemoveDir  Rights = 1 << 4
	RemoveFile Rights = 1 << 5
	MakeDir    Rights = 1 << 7
	MakeReg    Rights = 1 << 8
	Refer      Rights = 1 << 13
	Truncate   Rights = 1 << 14
)

// Rights of the rows of ADR 0011's table.
const (
	// MountRW is a writable mount's: refer lets renames cross
	// directories (versions, client renames).
	MountRW = ReadFile | ReadDir | WriteFile | Truncate | MakeReg | MakeDir | RemoveFile | RemoveDir | Refer
	// MountRO is a read-only mount's; a read-only {user} mount with
	// create = true adds MakeDir.
	MountRO = ReadFile | ReadDir
	// coverRights let a -cover build write its counters at exit.
	coverRights = ReadFile | ReadDir | WriteFile | MakeReg | RemoveFile
)

var rightNames = []struct {
	r    Rights
	name string
}{
	{ReadFile, "read_file"},
	{ReadDir, "read_dir"},
	{WriteFile, "write_file"},
	{Truncate, "truncate"},
	{MakeReg, "make_reg"},
	{MakeDir, "make_dir"},
	{RemoveFile, "remove_file"},
	{RemoveDir, "remove_dir"},
	{Refer, "refer"},
}

// String lists the rights by their kernel names, in the order of ADR
// 0011's table, such as "read_file,read_dir".
func (r Rights) String() string {
	var names []string
	for _, n := range rightNames {
		if r&n.r != 0 {
			names = append(names, n.name)
			r &^= n.r
		}
	}
	if r != 0 {
		names = append(names, "0x"+strconv.FormatUint(uint64(r), 16))
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// Values of the landlock field of server.start besides "v2" to "v5".
const (
	StatusOff         = "off"
	StatusUnavailable = "unavailable" // no Landlock, or disabled at boot
	StatusBlocked     = "blocked"     // a seccomp filter, or a probe that did not finish
	StatusNotApplied  = "not_applied" // ABI 1 only, exec hooks, a rule on /
)

// The ABI that gosftpd asks for and the least it uses. ABI 5 handles
// truncate (from ABI 3) and ioctl_dev (from ABI 5); later ABIs add only
// resolve_unix (9), which would cut off the sd_notify socket, so a change
// of the pin is a conscious one. ABI 1 has no refer: every rename between
// directories would fail with EXDEV.
const (
	maxABI = 5
	minABI = 2
)

// Hint follows a permission error on a path that the ruleset applied at
// start does not cover.
const Hint = "outside the Landlock ruleset applied at start; restart gosftpd"

// seccompHint tells what to do about a seccomp filter that blocks the
// Landlock calls.
const seccompHint = `allow landlock_create_ruleset, landlock_add_rule and landlock_restrict_self in SystemCallFilter=, or set server.landlock = "off"`

// Reasons for not applying Landlock.
const (
	reasonNoLandlock = "no Landlock in the kernel"
	reasonDisabled   = "disabled at boot"
	reasonNotListed  = "no Landlock in the kernel, or disabled at boot (not in /sys/kernel/security/lsm)"
	reasonBlocked    = "blocked by a seccomp filter"
	reasonKilled     = "killed by a seccomp filter"
	reasonHung       = "did not finish within 5 s: a filter that kills the calling thread"
	reasonExecHooks  = "exec hooks configured"
	reasonABI1       = "ABI 1 only"
	reasonRoot       = "a rule would be placed on /"
	reasonNotLinux   = "Landlock exists only on Linux"
)

// MountDir is a mount's directory as the mount holds it open: for a {user}
// mount, the parent of {user}.
type MountDir struct {
	// Name is the mount's name in config.Config.Mounts.
	Name string
	// FD is an O_PATH|O_DIRECTORY descriptor of the directory, checked to
	// be the one the mount's os.Root holds. The rule is added through
	// /proc/self/fd/FD, so that a directory swapped for a symlink after
	// it was opened cannot redirect it. A negative FD adds it by path.
	FD int
	// Dev and Ino are the descriptor's.
	Dev, Ino uint64
}

// Options configure Start.
type Options struct {
	// Config is the validated configuration; Config.Server.Landlock is
	// the mode.
	Config *config.Config
	// Mounts are the open mount directories, one for each mount of
	// Config.
	Mounts []MountDir
	Log    *slog.Logger
}

// Result is what Start did.
type Result struct {
	// Status is the landlock field of server.start: "v2" to "v5", "off",
	// "unavailable", "blocked" or "not_applied"; "" on systems without
	// Landlock, where server.start has no such field.
	Status string
	// Ruleset is what was applied, for reloads; nil when nothing was.
	Ruleset *Ruleset
}

// RequiredError is returned by Start when server.landlock is "required"
// and Landlock cannot be applied for a reason that a restart does not
// change: the start fails with exit status 2.
type RequiredError struct{ skip skip }

func (e *RequiredError) Error() string { return e.skip.text() + `; server.landlock is "required"` }

// Preview returns the start warnings that Start would log for c, for
// config validate --check-fs. The rules are computed without the mount
// table: a mount directory is found by its path. Nothing is returned where
// Start would not compute rules because of the configuration (off, exec
// hooks) or on systems without Landlock; a rule that would be placed on /
// is a *RootError. The kernel is not asked.
func Preview(c *config.Config) ([]string, error) {
	in, ok := previewInput()
	if !ok || c.Server.Landlock == config.LandlockOff || c.ExecHook() >= 0 {
		return nil, nil
	}
	in.Config = c
	plan, err := Compute(in)
	return plan.Warnings, err
}

// Start applies Landlock as server.landlock says: "off" never, "auto"
// where it can be used (it logs why not elsewhere), "required" or fail
// with a *RequiredError. Every failure once Landlock can be used fails the
// start in both modes, with an error "landlock: failed: ...".
//
// Call it once, after the listeners are bound, the ambient capabilities
// cleared, the host keys, mounts, audit output and TLS roots loaded, and
// before any background goroutine starts and READY=1. Tests never call it
// in their own process: the ruleset cannot be lifted.
func Start(ctx context.Context, o Options) (Result, error) {
	return start(ctx, o, host)
}

// kernel is what Start asks of the system; tests replace it.
type kernel interface {
	// supported reports whether the system can have Landlock at all.
	supported() bool
	// lsm returns /sys/kernel/security/lsm, the active security modules.
	lsm() (string, error)
	// filtered reports whether a seccomp filter is installed.
	filtered() (bool, error)
	// probe tries the Landlock calls in a child, under the filter.
	probe(ctx context.Context) probeResult
	// abi queries the Landlock ABI version.
	abi() (int, error)
	// input returns what the rules need of the process: the file system,
	// the home directory, /proc/self held open, the coverage directory.
	input() (Input, error)
	// apply adds the rules to a ruleset and restricts every thread.
	apply(rules []Rule) error
	// selfCheck must find that / cannot be opened for reading.
	selfCheck() error
	// releaseTerminal gives up the controlling terminal when one of fd 0
	// to 2 is it and the process does not lead its session.
	releaseTerminal() error
}

func start(ctx context.Context, o Options, k kernel) (Result, error) {
	c := o.Config
	mode := c.Server.Landlock
	if mode == config.LandlockOff {
		if !k.supported() {
			return Result{}, nil
		}
		return Result{Status: StatusOff}, nil
	}
	if !k.supported() {
		if mode == config.LandlockRequired {
			return Result{}, &RequiredError{skip{status: StatusUnavailable, reason: reasonNotLinux}}
		}
		return Result{}, nil
	}
	if c.ExecHook() >= 0 {
		return skipped(ctx, o, skip{status: StatusNotApplied, reason: reasonExecHooks})
	}
	abi, s, err := available(ctx, k)
	if err != nil {
		return failed(ctx, o.Log, err)
	}
	if s != nil {
		return skipped(ctx, o, *s)
	}

	in, err := k.input()
	if err != nil {
		return failed(ctx, o.Log, err)
	}
	in.Config, in.Mounts = c, o.Mounts
	if in.Mounts == nil {
		in.Mounts = []MountDir{} // never stat'ed by path: Start has them open
	}
	plan, err := Compute(in)
	if re, ok := errors.AsType[*RootError](err); ok {
		return skipped(ctx, o, skip{status: StatusNotApplied, reason: reasonRoot, key: re.Key})
	}
	if err != nil {
		return failed(ctx, o.Log, err)
	}
	for _, w := range plan.Warnings {
		o.Log.WarnContext(ctx, "landlock", "detail", w)
	}
	for _, r := range plan.Rules {
		o.Log.DebugContext(ctx, "landlock rule", "path", r.Path, "rights", r.Rights.String(), "dir", r.Dir, "for", strings.Join(r.For, ","))
	}
	// A later first use would find no zone file and fall back to UTC
	// silently (expiry-time in authorized_keys).
	_ = time.Local.String()
	if err := k.apply(plan.Rules); err != nil {
		return failed(ctx, o.Log, err)
	}
	if err := k.selfCheck(); err != nil {
		return failed(ctx, o.Log, fmt.Errorf("self-check: %w", err))
	}
	if err := k.releaseTerminal(); err != nil {
		return failed(ctx, o.Log, fmt.Errorf("giving up the controlling terminal: %w", err))
	}
	applied := min(abi, maxABI)
	logApplied(ctx, o.Log, applied, abi)
	if probeBuild {
		logProbe(ctx, o.Log)
	}
	return Result{Status: "v" + strconv.Itoa(applied), Ruleset: newRuleset(plan.Rules, in)}, nil
}

// available decides whether Landlock can be used and returns the kernel's
// ABI. A skip says why not; an error fails the start.
func available(ctx context.Context, k kernel) (int, *skip, error) {
	// Nothing else is tried: securityfs names the active modules.
	if list, err := k.lsm(); err == nil && !lists(list, "landlock") {
		return 0, &skip{status: StatusUnavailable, reason: reasonNotListed}, nil
	}
	// A filter that kills unlisted calls would kill gosftpd at its first
	// Landlock call, so a child tries them first.
	filtered, err := k.filtered()
	if err != nil {
		return 0, nil, fmt.Errorf("reading the seccomp mode: %w", err)
	}
	if filtered {
		s, err := classify(k.probe(ctx))
		if err != nil || s != nil {
			return 0, s, err
		}
	}
	abi, err := k.abi()
	switch {
	case errors.Is(err, syscall.ENOSYS):
		return 0, &skip{status: StatusUnavailable, reason: reasonNoLandlock}, nil
	case errors.Is(err, syscall.EOPNOTSUPP):
		return 0, &skip{status: StatusUnavailable, reason: reasonDisabled}, nil
	case errors.Is(err, syscall.EPERM):
		return 0, &skip{status: StatusBlocked, reason: reasonBlocked, hint: seccompHint}, nil
	case err != nil:
		return 0, nil, fmt.Errorf("querying the ABI: %w", err)
	case abi < minABI:
		return abi, &skip{status: StatusNotApplied, reason: reasonABI1, abi: abi}, nil
	}
	return abi, nil, nil
}

// lists reports whether the comma-separated list holds name.
func lists(list, name string) bool {
	for m := range strings.SplitSeq(strings.TrimSpace(list), ",") {
		if m == name {
			return true
		}
	}
	return false
}

// skip says why Landlock is not applied.
type skip struct {
	status string // StatusUnavailable, StatusBlocked or StatusNotApplied
	reason string
	hint   string // what to do, for a seccomp filter
	key    string // the configuration key that needs a rule on /
	abi    int    // the kernel's ABI, when known
}

// text is the skip as a sentence: "landlock: not available: REASON (HINT)".
func (s skip) text() string {
	msg := "landlock: not available: "
	if s.status == StatusNotApplied {
		msg = "landlock: not applied: "
	}
	msg += s.reason
	if s.key != "" {
		msg += " (" + s.key + ")"
	}
	if s.hint != "" {
		msg += " (" + s.hint + ")"
	}
	return msg
}

// skipped ends Start without Landlock: in "auto" with a log line, in
// "required" with a *RequiredError.
func skipped(ctx context.Context, o Options, s skip) (Result, error) {
	if o.Config.Server.Landlock == config.LandlockRequired {
		return Result{}, &RequiredError{s}
	}
	args := []any{"reason", s.reason}
	if s.key != "" {
		args = append(args, "key", s.key)
	}
	if s.abi > 0 {
		args = append(args, "kernel_abi", s.abi)
	}
	if s.hint != "" {
		args = append(args, "hint", s.hint)
	}
	switch s.status {
	case StatusBlocked:
		o.Log.WarnContext(ctx, "landlock: not available", args...)
	case StatusUnavailable:
		o.Log.InfoContext(ctx, "landlock: not available", args...)
	default:
		o.Log.InfoContext(ctx, "landlock: not applied", args...)
	}
	return Result{Status: s.status}, nil
}

// failed ends Start with a failure, in "auto" as in "required": the
// default mode never runs unsandboxed because of an error.
func failed(ctx context.Context, log *slog.Logger, err error) (Result, error) {
	log.ErrorContext(ctx, "landlock: failed", "err", err)
	return Result{}, fmt.Errorf("landlock: failed: %w", err)
}

// logProbe logs, in a binary built with -tags landlockprobe, the result of
// opening /etc/passwd once the ruleset is applied: "permission denied",
// which the systemd CI job looks for in the journal.
func logProbe(ctx context.Context, log *slog.Logger) {
	f, err := os.Open("/etc/passwd")
	if err == nil {
		_ = f.Close()
	}
	log.InfoContext(ctx, "landlock probe", "err", err)
}

// logApplied logs the ABI applied; each has a message of its own, which
// the systemd and interop checks look for.
func logApplied(ctx context.Context, log *slog.Logger, applied, kernelABI int) {
	switch applied {
	case 2:
		log.InfoContext(ctx, "landlock: ABI v2 applied", "kernel_abi", kernelABI)
	case 3:
		log.InfoContext(ctx, "landlock: ABI v3 applied", "kernel_abi", kernelABI)
	case 4:
		log.InfoContext(ctx, "landlock: ABI v4 applied", "kernel_abi", kernelABI)
	default:
		log.InfoContext(ctx, "landlock: ABI v5 applied", "kernel_abi", kernelABI)
	}
}
