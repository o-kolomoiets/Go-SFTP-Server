// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// fakeKernel answers Start's questions as a test says.
type fakeKernel struct {
	notLinux  bool
	lsmList   string
	lsmErr    error
	filter    bool
	filterErr error
	probed    probeResult
	abiV      int
	abiErr    error
	m         *memFS
	applyErr  error
	checkErr  error
	ttyErr    error
	calls     []string
	rules     []Rule
}

func (k *fakeKernel) call(name string) { k.calls = append(k.calls, name) }

func (k *fakeKernel) supported() bool { return !k.notLinux }

func (k *fakeKernel) lsm() (string, error) { k.call("lsm"); return k.lsmList, k.lsmErr }

func (k *fakeKernel) filtered() (bool, error) { k.call("filtered"); return k.filter, k.filterErr }

func (k *fakeKernel) probe(context.Context) probeResult { k.call("probe"); return k.probed }

func (k *fakeKernel) abi() (int, error) { k.call("abi"); return k.abiV, k.abiErr }

func (k *fakeKernel) input() (Input, error) {
	k.call("input")
	return Input{FS: k.m, ProcSelfFD: -1}, nil
}

func (k *fakeKernel) apply(rules []Rule) error {
	k.call("apply")
	k.rules = rules
	return k.applyErr
}

func (k *fakeKernel) selfCheck() error { k.call("selfCheck"); return k.checkErr }

func (k *fakeKernel) releaseTerminal() error { k.call("releaseTerminal"); return k.ttyErr }

const probeOK = "abi 7\nruleset ok\nrule ok\nrestrict ok\n"

// TestStart: the mode decides what each reason not to apply Landlock does;
// every failure once Landlock can be used fails the start.
func TestStart(t *testing.T) {
	t.Parallel()
	applied := []string{"lsm", "filtered", "abi", "input", "apply", "selfCheck", "releaseTerminal"}
	cases := []struct {
		name   string
		kernel func(k *fakeKernel)
		config func(c *config.Config)
		status string
		// err is a part of the error, "" for none; required marks a
		// *RequiredError (exit status 2), any other error is a failure
		// (exit status 1).
		err      string
		required bool
		log      string
		calls    []string
	}{
		{name: "ABI 7", status: "v5", log: `level=INFO msg="landlock: ABI v5 applied" kernel_abi=7`, calls: applied},
		{name: "ABI 5", kernel: func(k *fakeKernel) { k.abiV = 5 }, status: "v5", log: `msg="landlock: ABI v5 applied" kernel_abi=5`},
		{name: "ABI 4", kernel: func(k *fakeKernel) { k.abiV = 4 }, status: "v4", log: `msg="landlock: ABI v4 applied" kernel_abi=4`},
		{name: "ABI 3", kernel: func(k *fakeKernel) { k.abiV = 3 }, status: "v3", log: `msg="landlock: ABI v3 applied" kernel_abi=3`},
		{name: "ABI 2", kernel: func(k *fakeKernel) { k.abiV = 2 }, status: "v2", log: `msg="landlock: ABI v2 applied" kernel_abi=2`},
		{
			name: "securityfs lists Landlock", kernel: func(k *fakeKernel) { k.lsmList, k.lsmErr = "capability,landlock,yama\n", nil },
			status: "v5", calls: applied,
		},
		{name: "ABI 1", kernel: func(k *fakeKernel) { k.abiV = 1 }, status: StatusNotApplied, log: `level=INFO msg="landlock: not applied" reason="ABI 1 only" kernel_abi=1`},
		{
			name: "no Landlock in securityfs", kernel: func(k *fakeKernel) { k.lsmList, k.lsmErr = "lockdown,capability,yama,apparmor\n", nil },
			status: StatusUnavailable, log: `level=INFO msg="landlock: not available" reason="no Landlock in the kernel, or disabled at boot (not in /sys/kernel/security/lsm)"`,
			calls: []string{"lsm"},
		},
		{
			name: "ENOSYS", kernel: func(k *fakeKernel) { k.abiErr = syscall.ENOSYS }, status: StatusUnavailable,
			log: `level=INFO msg="landlock: not available" reason="no Landlock in the kernel"`,
		},
		{
			name: "EOPNOTSUPP", kernel: func(k *fakeKernel) { k.abiErr = syscall.EOPNOTSUPP }, status: StatusUnavailable,
			log: `level=INFO msg="landlock: not available" reason="disabled at boot"`,
		},
		{
			name: "EPERM", kernel: func(k *fakeKernel) { k.abiErr = syscall.EPERM }, status: StatusBlocked,
			log: `level=WARN msg="landlock: not available" reason="blocked by a seccomp filter" hint="allow landlock_create_ruleset, landlock_add_rule and landlock_restrict_self in SystemCallFilter=, or set server.landlock = \"off\""`,
		},
		{name: "another errno", kernel: func(k *fakeKernel) { k.abiErr = syscall.EINVAL }, err: "landlock: failed: querying the ABI:"},
		{
			name: "filter, probe ok", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{output: probeOK} },
			status: "v5", calls: []string{"lsm", "filtered", "probe", "abi", "input", "apply", "selfCheck", "releaseTerminal"},
		},
		{
			name: "probe ENOSYS", kernel: func(k *fakeKernel) {
				k.filter, k.probed = true, probeResult{output: "abi errno " + strconv.Itoa(int(syscall.ENOSYS))}
			},
			status: StatusUnavailable, log: `reason="no Landlock in the kernel"`, calls: []string{"lsm", "filtered", "probe"},
		},
		{
			name: "probe EOPNOTSUPP", kernel: func(k *fakeKernel) {
				k.filter, k.probed = true, probeResult{output: "abi errno " + strconv.Itoa(int(syscall.EOPNOTSUPP))}
			},
			status: StatusUnavailable, log: `level=INFO msg="landlock: not available" reason="disabled at boot"`,
		},
		{
			name: "probe EPERM", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{output: "abi errno 1\n"} },
			status: StatusBlocked, log: `level=WARN msg="landlock: not available" reason="blocked by a seccomp filter" hint=`,
		},
		{
			name: "probe killed", kernel: func(k *fakeKernel) {
				k.filter, k.probed = true, probeResult{output: "abi 7\n", exitCode: -1, signal: "bad system call"}
			},
			status: StatusBlocked, log: `level=WARN msg="landlock: not available" reason="killed by a seccomp filter" hint=`,
		},
		{
			name: "probe trapped", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{exitCode: 2} },
			status: StatusBlocked, log: `reason="killed by a seccomp filter"`,
		},
		{
			name: "probe hangs", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{timedOut: true, exitCode: -1} },
			status: StatusBlocked, log: `level=WARN msg="landlock: not available" reason="did not finish within 5 s: a filter that kills the calling thread" hint=`,
		},
		{
			name: "probe without output", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{} },
			status: StatusBlocked, log: `reason="blocked by a seccomp filter"`,
		},
		{
			name: "probe cannot start", kernel: func(k *fakeKernel) { k.filter, k.probed = true, probeResult{err: fs.ErrPermission} },
			err: "landlock: failed: probe child: permission denied", log: `level=ERROR msg="landlock: failed" err="probe child: permission denied"`,
		},
		{name: "seccomp mode unreadable", kernel: func(k *fakeKernel) { k.filterErr = fs.ErrNotExist }, err: "landlock: failed: reading the seccomp mode"},
		{
			name: "exec hooks",
			config: func(c *config.Config) {
				c.Hooks = []*config.Hook{{Exec: &config.HookExec{Argv: []string{"/bin/true"}}}}
			},
			status: StatusNotApplied, log: `level=INFO msg="landlock: not applied" reason="exec hooks configured"`, calls: []string{},
		},
		{
			name: "a rule on /", config: func(c *config.Config) { c.AddMount("root", native("/")) },
			status: StatusNotApplied, log: `level=INFO msg="landlock: not applied" reason="a rule would be placed on /" key=mounts.root.path`,
		},
		{
			name: "restrict fails", kernel: func(k *fakeKernel) { k.applyErr = errors.New("landlock_add_rule: bad") },
			err: "landlock: failed: landlock_add_rule: bad", log: `level=ERROR msg="landlock: failed" err="landlock_add_rule: bad"`,
		},
		{
			name: "self-check fails", kernel: func(k *fakeKernel) { k.checkErr = errors.New("/ can still be opened") },
			err: "landlock: failed: self-check: / can still be opened", calls: []string{"lsm", "filtered", "abi", "input", "apply", "selfCheck"},
		},
		{
			name: "terminal", kernel: func(k *fakeKernel) { k.ttyErr = syscall.ENOTTY },
			err: "landlock: failed: giving up the controlling terminal",
		},
		{
			name: "a mount swapped", kernel: func(k *fakeKernel) { k.m.remove("/srv/sftp/inbox").dirs("/srv/sftp/inbox") },
			err: "is no longer the directory the mount opened",
		},
		{name: "not Linux", kernel: func(k *fakeKernel) { k.notLinux = true }, calls: []string{}},
	}
	for _, mode := range []string{config.LandlockAuto, config.LandlockRequired} {
		for _, tc := range cases {
			k := &fakeKernel{lsmErr: fs.ErrNotExist, abiV: 7}
			k.m = newMemFS(t).files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
			c := newConfig("/etc/gosftpd/config.toml")
			c.Server.Landlock = mode
			if tc.config != nil {
				tc.config(c)
			}
			in := input(t, k.m, c)
			if tc.kernel != nil {
				tc.kernel(k)
			}
			var log bytes.Buffer
			res, err := start(t.Context(), Options{Config: c, Mounts: in.Mounts, Log: slog.New(slog.NewTextHandler(&log, nil))}, k)
			name := mode + ", " + tc.name

			// In "required" every reason not to apply is an error with
			// exit status 2, and nothing is logged for it.
			skip := tc.err == "" && tc.status != "" && !strings.HasPrefix(tc.status, "v")
			if mode == config.LandlockRequired && (skip || tc.name == "not Linux") {
				if re, ok := errors.AsType[*RequiredError](err); !ok || !strings.HasSuffix(re.Error(), `; server.landlock is "required"`) {
					t.Errorf("%s: err = %v, want a *RequiredError", name, err)
				}
				if res.Status != "" || res.Ruleset != nil || strings.Contains(log.String(), "landlock: not") {
					t.Errorf("%s: %+v\n%s", name, res, log.String())
				}
				continue
			}

			switch _, required := errors.AsType[*RequiredError](err); {
			case tc.err == "" && err != nil:
				t.Errorf("%s: err = %v", name, err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Errorf("%s: err = %v, want %q", name, err, tc.err)
			case required:
				t.Errorf("%s: a failure is a *RequiredError: %v", name, err)
			}
			if res.Status != tc.status {
				t.Errorf("%s: Status = %q, want %q", name, res.Status, tc.status)
			}
			if (res.Ruleset != nil) != strings.HasPrefix(tc.status, "v") {
				t.Errorf("%s: Ruleset = %v", name, res.Ruleset)
			}
			if tc.log != "" && !strings.Contains(log.String(), tc.log) {
				t.Errorf("%s: log:\n%s\nwant %q", name, log.String(), tc.log)
			}
			if tc.calls != nil && !slices.Equal(k.calls, tc.calls) {
				t.Errorf("%s: calls %v, want %v", name, k.calls, tc.calls)
			}
		}
	}
}

func TestStartOff(t *testing.T) {
	t.Parallel()
	for _, linux := range []bool{true, false} {
		k := &fakeKernel{notLinux: !linux}
		c := newConfig("/etc/gosftpd/config.toml")
		c.Server.Landlock = config.LandlockOff
		var log bytes.Buffer
		res, err := start(t.Context(), Options{Config: c, Log: slog.New(slog.NewTextHandler(&log, nil))}, k)
		want := ""
		if linux {
			want = StatusOff
		}
		if err != nil || res.Status != want || res.Ruleset != nil || len(k.calls) != 0 || log.Len() != 0 {
			t.Errorf("Linux %v: %+v, %v, calls %v, log %q", linux, res, err, k.calls, log.String())
		}
	}
}

// TestStartRuleset: the rules applied are those kept for reloads, and the
// start warnings are logged.
func TestStartRuleset(t *testing.T) {
	t.Parallel()
	k := &fakeKernel{lsmErr: fs.ErrNotExist, abiV: 6}
	k.m = newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/notes.txt").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	in := input(t, k.m, c)
	var log bytes.Buffer
	res, err := start(t.Context(), Options{Config: c, Mounts: in.Mounts, Log: slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))}, k)
	if err != nil {
		t.Fatal(err)
	}
	if got := describe(res.Ruleset.Rules()); !slices.Equal(got, describe(k.rules)) || len(got) != 2 {
		t.Errorf("kept %v, applied %v", got, describe(k.rules))
	}
	for _, want := range []string{
		`level=WARN msg=landlock detail="configuration: Landlock covers only the file config.toml in`,
		`level=DEBUG msg="landlock rule" path=`,
		`msg="landlock: ABI v5 applied" kernel_abi=6`,
	} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log:\n%s\nwant %q", log.String(), want)
		}
	}
	if probeBuild && !strings.Contains(log.String(), `msg="landlock probe"`) {
		t.Errorf("no probe line in a landlockprobe build:\n%s", log.String())
	}
}
