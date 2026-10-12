// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

var host kernel = linuxKernel{}

type linuxKernel struct{}

func (linuxKernel) supported() bool { return true }

func (linuxKernel) lsm() (string, error) {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	return string(b), err
}

// filtered reports whether /proc/self/status shows a seccomp filter
// ("Seccomp: 2").
func (linuxKernel) filtered() (bool, error) {
	v, err := statusField("Seccomp")
	return v == "2", err
}

func (linuxKernel) abi() (int, error) { return abiVersion() }

// abiVersion queries the ABI itself: go-landlock's BestEffort applies
// nothing, and says nothing, without Landlock, with Landlock disabled at
// boot, under a seccomp filter returning EPERM, and on ABI 1.
func abiVersion() (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0, errno
	}
	return int(v), nil
}

// probe starts the probe child from /proc/self/exe; it inherits the
// seccomp filter. A filter that kills only the calling thread leaves it
// hanging, so it is killed after probeTimeout.
func (linuxKernel) probe(ctx context.Context) probeResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
	defer cancel()
	var out limitedBuffer
	cmd := exec.CommandContext(ctx, "/proc/self/exe", probeArg)
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	r := probeResult{output: out.String()}
	if ctx.Err() != nil {
		r.timedOut = true
		return r
	}
	ee, exited := errors.AsType[*exec.ExitError](err)
	switch {
	case exited:
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			r.exitCode, r.signal = -1, ws.Signal().String()
		} else {
			r.exitCode = ee.ExitCode()
		}
	case err != nil:
		r.err = err
	}
	return r
}

// probeChild makes the four Landlock calls on one thread, printing each
// result, and restricts that thread. Its exit status is 0 also when a
// call fails: the output says which.
func probeChild(w io.Writer) int {
	runtime.LockOSThread()
	report := func(step string, errno syscall.Errno) bool {
		if errno != 0 {
			fmt.Fprintf(w, "%s errno %d\n", step, int(errno))
			return false
		}
		fmt.Fprintf(w, "%s ok\n", step)
		return true
	}
	// Nothing to read from the child's memory, and no privileges to gain:
	// landlock_restrict_self needs no_new_privs without CAP_SYS_ADMIN.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		report("setup", errnoOf(err))
		return 0
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		report("setup", errnoOf(err))
		return 0
	}
	v, err := abiVersion()
	if err != nil {
		report("abi", errnoOf(err))
		return 0
	}
	fmt.Fprintf(w, "abi %d\n", v)
	attr := unix.LandlockRulesetAttr{Access_fs: unix.LANDLOCK_ACCESS_FS_READ_FILE}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if !report("ruleset", errno) {
		return 0
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		report("rule", errnoOf(err))
		return 0
	}
	rule := unix.LandlockPathBeneathAttr{Allowed_access: unix.LANDLOCK_ACCESS_FS_READ_FILE, Parent_fd: int32(root)} //nolint:gosec // a descriptor fits
	_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
	if !report("rule", errno) {
		return 0
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	report("restrict", errno)
	return 0
}

func errnoOf(err error) syscall.Errno {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		return errno
	}
	return syscall.EINVAL
}

// limitedBuffer keeps the first 4 KiB written to it: the probe prints a
// few short lines.
type limitedBuffer struct{ b bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }

// procSelfFD is /proc/self held open for the life of the process: a rule
// added on /proc/self by path is lost once the kernel reclaims the dentry
// of /proc/<pid>.
var procSelfFD = -1

func (linuxKernel) input() (Input, error) {
	if procSelfFD < 0 {
		fd, err := unix.Open("/proc/self", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return Input{}, fmt.Errorf("opening /proc/self: %w", err)
		}
		procSelfFD = fd
	}
	return Input{FS: osFS{}, Home: homeDir(), Linux: true, ProcSelfFD: procSelfFD, CoverDir: coverDir()}, nil
}

// previewInput is input for Preview, which opens nothing.
func previewInput() (Input, bool) {
	return Input{FS: osFS{}, Home: homeDir(), Linux: true, ProcSelfFD: -1}, true
}

// homeDir returns the home directory of the user running gosftpd: $HOME,
// which systemd sets from the user database, else the database's.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// coverDir returns where a -cover build writes its counters: the
// -test.gocoverdir flag in a test binary, else $GOCOVERDIR. Only the
// build information decides that this is a -cover build.
func coverDir() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var flagValue string
	if f := flag.Lookup("test.gocoverdir"); f != nil {
		flagValue = f.Value.String()
	}
	return coverDirOf(bi.Settings, flagValue, os.Getenv("GOCOVERDIR"))
}

// apply opens each rule's path, checks that it is still what the rules
// were computed from, and restricts every thread with go-landlock's ABI 5
// in best-effort mode (truncate and ioctl_dev need ABI 3 and 5).
func (linuxKernel) apply(rules []Rule) error {
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	opts := make([]landlock.Rule, 0, len(rules))
	for _, r := range rules {
		flags := unix.O_PATH | unix.O_CLOEXEC
		if r.Dir {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(r.Open, flags, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", r.Path, err)
		}
		fds = append(fds, fd)
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return fmt.Errorf("%s: %w", r.Path, err)
		}
		if dev, ino := devIno(&st); dev != r.Dev || ino != r.Ino {
			return fmt.Errorf("%s changed while the rules were computed", r.Path)
		}
		opts = append(opts, landlock.PathAccess(landlock.AccessFSSet(r.Rights), "/proc/self/fd/"+strconv.Itoa(fd)))
	}
	return landlock.V5.BestEffort().RestrictPaths(opts...)
}

// selfCheck: / must not open for reading once the ruleset is enforced.
// O_PATH would not do: Landlock does not check it.
func (linuxKernel) selfCheck() error {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return errors.New("/ can still be opened")
	}
	if !errors.Is(err, unix.EACCES) {
		return fmt.Errorf("opening /: %w", err)
	}
	return nil
}

// releaseTerminal gives up gosftpd's controlling terminal when fd 0, 1 or
// 2 is it and gosftpd does not lead its session (a session leader would
// hang up its foreground job). A descriptor opened before the ruleset is
// not checked by Landlock: TIOCSTI on it would type commands into the
// shell that started serve. Afterwards it fails with EPERM, and Ctrl-C
// still reaches the process group.
func (linuxKernel) releaseTerminal() error {
	sid, err := unix.Getsid(0)
	if err != nil || sid == unix.Getpid() {
		return err
	}
	for fd := range 3 {
		if tsid, err := unix.IoctlGetInt(fd, unix.TIOCGSID); err != nil || tsid != sid {
			continue // not a terminal, or not ours
		}
		return unix.IoctlSetInt(fd, unix.TIOCNOTTY, 0)
	}
	return nil
}

// ClearAmbient clears the ambient capability set of every thread when
// /proc/self/status shows one: with AmbientCapabilities=CAP_NET_BIND_SERVICE
// (port 22), exec hooks would inherit the capability. Capabilities are per
// thread and a child inherits its forking thread's, so a plain prctl would
// clear one thread only. It returns the set that was cleared. Call it after
// the listeners are bound and before any hook can run; an error fails the
// start.
func ClearAmbient() (uint64, error) {
	v, err := statusField("CapAmb")
	if err != nil {
		return 0, err
	}
	set, err := strconv.ParseUint(v, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("CapAmb %q: %w", v, err)
	}
	if set == 0 {
		return 0, nil
	}
	if err := llsyscall.AllThreadsPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("clearing the ambient capabilities: %w", err)
	}
	return set, nil
}

// statusField returns a field of /proc/self/status.
func statusField(name string) (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), name+":"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("/proc/self/status has no %s", name)
}

// osFS is the real file system.
type osFS struct{}

func (osFS) Lstat(path string) (Info, error) { return infoOf(os.Lstat(path)) }

func (osFS) Stat(path string) (Info, error) { return infoOf(os.Stat(path)) }

func (osFS) ReadDir(path string) ([]string, error) {
	d, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}

func (osFS) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }

func infoOf(fi os.FileInfo, err error) (Info, error) {
	if err != nil {
		return Info{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Info{}, fmt.Errorf("%s: no device and inode", fi.Name())
	}
	dev, ino := devIno(st)
	return Info{Dev: dev, Ino: ino, Mode: fi.Mode().Type()}, nil
}

// devIno returns a stat's device and inode as uint64: their types differ
// between architectures.
func devIno(st *syscall.Stat_t) (dev, ino uint64) {
	return uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // uint32 on some architectures
}
