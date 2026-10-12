// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// The test binary never sandboxes its own process: the ruleset cannot be
// lifted. Every sandboxed test re-executes the binary for itself, with
// childEnv naming the role of the child. Children never use t.TempDir,
// whose clean-up the ruleset would refuse.
const (
	childEnv  = "GOSFTPD_SANDBOX_CHILD"
	dirEnv    = "GOSFTPD_SANDBOX_DIR"
	filterEnv = "GOSFTPD_SANDBOX_FILTER"
	// requireEnv makes a test fail instead of skipping where Landlock,
	// passwordless sudo or setpriv is missing; CI sets it.
	requireEnv = "GOSFTPD_TEST_REQUIRE_SANDBOX"
)

// helperMain serves a child that reports its ambient capabilities and
// exits.
func helperMain() {
	if os.Getenv(childEnv) == "capamb" {
		v, err := statusField("CapAmb")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(v)
		os.Exit(0)
	}
}

func role() string { return os.Getenv(childEnv) }

// missing skips the test for a missing precondition, or fails it when
// GOSFTPD_TEST_REQUIRE_SANDBOX=1.
func missing(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(requireEnv) == "1" {
		t.Fatalf("%s, and %s=1", why, requireEnv)
	}
	t.Skip(why)
}

// needLandlock returns the kernel's ABI, or skips the test below ABI 2.
func needLandlock(t *testing.T) int {
	t.Helper()
	v, err := abiVersion()
	if err != nil || v < minABI {
		missing(t, fmt.Sprintf("no usable Landlock: ABI %d, %v", v, err))
	}
	return v
}

// childArgs re-run the current top-level test, passing coverage on.
func childArgs(t *testing.T) []string {
	t.Helper()
	name, _, _ := strings.Cut(t.Name(), "/")
	args := []string{"-test.run=^" + name + "$", "-test.v", "-test.count=1", "-test.timeout=2m"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	return args
}

// child returns the command that re-executes the test binary for the
// current test in role.
func child(t *testing.T, role string, env ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, childArgs(t)...)
	cmd.Env = append(append(os.Environ(), childEnv+"="+role), env...)
	return cmd
}

func TestRightsAreTheKernels(t *testing.T) {
	t.Parallel()
	for r, k := range map[Rights]uint64{
		WriteFile: unix.LANDLOCK_ACCESS_FS_WRITE_FILE, ReadFile: unix.LANDLOCK_ACCESS_FS_READ_FILE,
		ReadDir: unix.LANDLOCK_ACCESS_FS_READ_DIR, RemoveDir: unix.LANDLOCK_ACCESS_FS_REMOVE_DIR,
		RemoveFile: unix.LANDLOCK_ACCESS_FS_REMOVE_FILE, MakeDir: unix.LANDLOCK_ACCESS_FS_MAKE_DIR,
		MakeReg: unix.LANDLOCK_ACCESS_FS_MAKE_REG, Refer: unix.LANDLOCK_ACCESS_FS_REFER,
		Truncate: unix.LANDLOCK_ACCESS_FS_TRUNCATE,
	} {
		if uint64(r) != k {
			t.Errorf("%s = %#x, the kernel's %#x", r, uint64(r), k)
		}
	}
}

// TestOSFS: the real file system as the rules read it.
func TestOSFS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("d/f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	var o osFS
	f, err1 := o.Stat(filepath.Join(dir, "l"))
	l, err2 := o.Lstat(filepath.Join(dir, "l"))
	r, err3 := o.EvalSymlinks(filepath.Join(dir, "l"))
	names, err4 := o.ReadDir(dir)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, "d", "f"), &st); err != nil {
		t.Fatal(err)
	}
	if dev, ino := devIno(&st); f.Dev != dev || f.Ino != ino || f.IsDir() || l.Mode&fs.ModeSymlink == 0 ||
		r != filepath.Join(dir, "d", "f") || strings.Join(names, ",") != "d,l" && strings.Join(names, ",") != "l,d" {
		t.Errorf("Stat %+v, Lstat %+v, EvalSymlinks %q, ReadDir %v", f, l, r, names)
	}
	if _, err := o.ReadDir(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadDir of a missing directory: %v", err)
	}
}

// TestUnsandboxed runs the steps that are harmless in the test process.
func TestUnsandboxed(t *testing.T) {
	t.Parallel()
	if err := (linuxKernel{}).selfCheck(); err == nil || !strings.Contains(err.Error(), "can still be opened") {
		t.Errorf("selfCheck without a ruleset = %v", err)
	}
	// With an empty set ClearAmbient changes nothing; TestClearAmbient
	// covers the rest in a child of its own.
	if set, err := statusField("CapAmb"); err != nil {
		t.Error(err)
	} else if set == "0000000000000000" {
		if cleared, err := ClearAmbient(); cleared != 0 || err != nil {
			t.Errorf("ClearAmbient with an empty set = %#x, %v", cleared, err)
		}
	}
	if _, err := statusField("NoSuchField"); err == nil {
		t.Error("statusField found a field that does not exist")
	}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" && coverDir() != f.Value.String() {
		t.Errorf("coverDir = %q in a -cover test binary with -test.gocoverdir=%s", coverDir(), f.Value.String())
	}
}

// TestPreview: config validate --check-fs gets the start warnings from the
// real file system, without a mount table; nothing where the
// configuration keeps Start from computing rules.
func TestPreview(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for _, d := range []string{"conf", "data"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(base, "conf", "config.toml")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	c.File, c.Files = file, []string{file}
	c.AddMount("data", filepath.Join(base, "data"))
	c.AddMount("later", filepath.Join(base, "later")) // created at start
	c.Audit.Output = filepath.Join(base, "conf", "audit.jsonl")
	warns, err := Preview(c)
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "audit.output: Landlock covers only the file audit.jsonl in "+filepath.Join(base, "conf")) ||
		!strings.HasSuffix(warns[0], auditRotationWarning) {
		t.Errorf("Preview = %q, %v", warns, err)
	}

	c.Server.Landlock = config.LandlockOff
	if warns, err := Preview(c); warns != nil || err != nil {
		t.Errorf("off: %q, %v", warns, err)
	}
	c.Server.Landlock = config.LandlockAuto
	c.Hooks = []*config.Hook{{Exec: &config.HookExec{Argv: []string{"/bin/true"}}}}
	if warns, err := Preview(c); warns != nil || err != nil {
		t.Errorf("exec hooks: %q, %v", warns, err)
	}
	c.Hooks = nil
	c.AddMount("root", "/")
	if _, err := Preview(c); !errors.As(err, new(*RootError)) {
		t.Errorf("a mount at /: %v", err)
	}
}

// TestProbeChild: without a seccomp filter the probe child makes all four
// calls and Landlock can be used.
func TestProbeChild(t *testing.T) {
	t.Parallel()
	v := needLandlock(t)
	r := linuxKernel{}.probe(t.Context())
	s, err := classify(r)
	if err != nil || s != nil {
		t.Fatalf("classify(%+v) = %+v, %v", r, s, err)
	}
	if want := "abi " + strconv.Itoa(v) + "\nruleset ok\nrule ok\nrestrict ok\n"; r.output != want {
		t.Errorf("output %q, want %q", r.output, want)
	}
}

// TestProbeUnderSeccomp: a filter that kills landlock_create_ruleset with
// SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD or SECCOMP_RET_TRAP,
// or makes it fail with EPERM or ENOSYS, is survived within the probe's
// limit. The filter is installed in a re-executed child, never in the
// test process.
func TestProbeUnderSeccomp(t *testing.T) {
	t.Parallel()
	if role() == "seccomp" {
		seccompChild(t)
		return
	}
	for _, tc := range []struct {
		filter, status, reason string
	}{
		{"kill_process", StatusBlocked, reasonKilled},
		{"kill_thread", StatusBlocked, reasonHung},
		{"trap", StatusBlocked, reasonKilled},
		{"eperm", StatusBlocked, reasonBlocked},
		{"enosys", StatusUnavailable, reasonNoLandlock},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			t.Parallel()
			cmd := child(t, "seccomp", filterEnv+"="+tc.filter)
			start := time.Now()
			out, err := cmd.CombinedOutput()
			d := time.Since(start)
			if err != nil {
				t.Fatalf("the child did not survive: %v\n%s", err, out)
			}
			if bytes.Contains(out, []byte("--- SKIP")) {
				missing(t, "the child skipped:\n"+string(out))
			}
			want := "result: " + tc.status + ": " + tc.reason + "\n"
			if !bytes.Contains(out, []byte(want)) {
				t.Errorf("output:\n%s\nwant %q", out, want)
			}
			// The probe gives up after its limit, which a filter that
			// kills only the calling thread reaches.
			if tc.filter == "kill_thread" && d < probeTimeout || d > probeTimeout+30*time.Second {
				t.Errorf("the child took %v", d)
			}
		})
	}
}

func seccompChild(t *testing.T) {
	t.Helper()
	action := map[string]uint32{
		"kill_process": unix.SECCOMP_RET_KILL_PROCESS,
		"kill_thread":  unix.SECCOMP_RET_KILL_THREAD,
		"trap":         unix.SECCOMP_RET_TRAP,
		"eperm":        unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM),
		"enosys":       unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS),
	}[os.Getenv(filterEnv)]
	if err := installFilter(action); err != nil {
		missing(t, "no seccomp filter: "+err.Error())
	}
	filtered, err := linuxKernel{}.filtered()
	if err != nil || !filtered {
		t.Fatalf("filtered = %v, %v", filtered, err)
	}
	s, err := classify(linuxKernel{}.probe(t.Context()))
	if err != nil || s == nil {
		t.Fatalf("classify = %v, %v", s, err)
	}
	fmt.Printf("result: %s: %s\n", s.status, s.reason)
}

// installFilter installs, on every thread, a seccomp filter that answers
// landlock_create_ruleset with action.
func installFilter(action uint32) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	arch, known := map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}[runtime.GOARCH]
	const (
		load = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	prog := []unix.SockFilter{
		{Code: load, K: 4}, // seccomp_data.arch
		{Code: jeq, Jt: 1, K: arch},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: load, K: 0}, // seccomp_data.nr
		{Code: jeq, Jf: 1, K: unix.SYS_LANDLOCK_CREATE_RULESET},
		{Code: ret, K: action},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
	}
	if !known {
		prog = prog[3:] // the native architecture is the only one here
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// TSYNC puts the filter, and no_new_privs, on every thread.
	if r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return errno
	} else if r != 0 {
		return fmt.Errorf("thread %d was not synchronised", r)
	}
	return nil
}

// TestApply: Start in a re-executed child applies the ruleset of a
// configuration and passes the self-check; afterwards the child reaches
// its configuration, mount, audit log, state and /proc/self, also after
// the kernel dropped its dentries, and nothing else.
func TestApply(t *testing.T) {
	t.Parallel()
	if role() == "apply" {
		applyChild(t)
		return
	}
	v := needLandlock(t)
	base := t.TempDir()
	for name, data := range map[string]string{
		"conf/config.toml": `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["../state/host_key"]
landlock = "required"
[mounts.data]
path = "` + filepath.Join(base, "data") + `"
[users.alice]
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
access = { data = "full" }
[audit]
output = "../log/audit.jsonl"
`,
		"conf/users.d/bob.toml": "[users.bob]\nauthorized_keys = [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\"]\naccess = { data = \"read\" }\n",
		"state/host_key":        "not read here",
		"log/audit.jsonl":       "{}\n",
		"data/kept.txt":         "kept",
		"outside/secret.txt":    "secret",
	} {
		path := filepath.Join(base, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := child(t, "apply", dirEnv+"="+base)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	waitFor(t, &out, "applied\n", exited)
	// The kernel reclaims the dentry of /proc/<pid> unless it is held.
	dropped := dropCaches(t)
	fmt.Fprintln(stdin, dropped)
	if err := <-exited; err != nil {
		t.Fatalf("child: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"landlock: ABI v" + strconv.Itoa(min(v, maxABI)) + " applied",
		`msg="landlock probe" err="open /etc/passwd: permission denied"`,
		"--- PASS: TestApply",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("child output:\n%s\nwant %q", out.String(), want)
		}
	}
}

func applyChild(t *testing.T) {
	t.Helper()
	base := os.Getenv(dirEnv)
	c, err := config.Load(filepath.Join(base, "conf", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(base, "data"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	dev, ino := devIno(&st)
	l := slog.New(slog.NewTextHandler(os.Stdout, nil))
	res, err := Start(t.Context(), Options{Config: c, Mounts: []MountDir{{Name: "data", FD: fd, Dev: dev, Ino: ino}}, Log: l})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Status, "v") || res.Ruleset == nil {
		t.Fatalf("Start = %+v", res)
	}
	logProbe(t.Context(), l) // as a -tags landlockprobe build does

	path := func(p string) string { return filepath.Join(base, p) }
	denied := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("%s: %v, want permission denied", what, err)
		}
	}
	allowed := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	readable := func(p string) error { _, err := os.ReadFile(p); return err }

	allowed("read the configuration", readable(path("conf/config.toml")))
	allowed("read an include", readable(path("conf/users.d/bob.toml")))
	allowed("read the host key", readable(path("state/host_key")))
	allowed("read the mount", readable(path("data/kept.txt")))
	denied("read /etc/passwd", readable("/etc/passwd"))
	denied("read outside", readable(path("outside/secret.txt")))
	denied("list the state directory", func() error { _, err := os.ReadDir(path("state")); return err }())
	denied("write the configuration", os.WriteFile(path("conf/config.toml"), nil, 0o600))
	denied("create in users.d", os.WriteFile(path("conf/users.d/x.toml"), nil, 0o600))
	denied("read the audit log", readable(path("log/audit.jsonl")))
	allowed("create in the audit directory", os.WriteFile(path("log/audit.jsonl.1"), nil, 0o600))
	f, err := os.OpenFile(path("log/audit.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	allowed("append to the audit log", err)
	if err == nil {
		_ = f.Close()
	}
	allowed("upload", os.WriteFile(path("data/new.txt"), []byte("x"), 0o600))
	allowed("mkdir", os.Mkdir(path("data/sub"), 0o700))
	allowed("rename across directories", os.Rename(path("data/new.txt"), path("data/sub/new.txt")))
	allowed("truncate", os.Truncate(path("data/sub/new.txt"), 0))
	allowed("remove", os.RemoveAll(path("data/sub")))
	denied("symlink in the mount", os.Symlink("kept.txt", path("data/link")))
	denied("execute", exec.CommandContext(t.Context(), "/bin/true").Run())
	denied("open /", func() error { f, err := os.Open("/"); f.Close(); return err }())

	procSelf := func(when string) {
		allowed(when+": /proc/self/statm", readable("/proc/self/statm"))
		allowed(when+": /proc/self/mountinfo", readable("/proc/self/mountinfo"))
		_, err := os.ReadDir("/proc/self/fd")
		allowed(when+": /proc/self/fd", err)
	}
	procSelf("at start")
	fmt.Println("applied")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(line) == "true" {
		procSelf("after drop_caches")
	}
}

// dropCaches makes the kernel reclaim dentries, through sudo -n as the
// ambient test; it reports whether it did.
func dropCaches(t *testing.T) bool {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "sudo", "-n", "sh", "-c", "echo 2 > /proc/sys/vm/drop_caches").CombinedOutput()
	if err != nil {
		if os.Getenv(requireEnv) == "1" {
			t.Errorf("drop_caches through sudo -n: %v %s", err, out)
		} else {
			t.Logf("/proc/self after drop_caches not checked: sudo -n: %v %s", err, out)
		}
		return false
	}
	return true
}

// TestClearAmbient: with AmbientCapabilities=CAP_NET_BIND_SERVICE, as
// systemd sets it for port 22, ClearAmbient empties the ambient set of
// every thread and of children started from many goroutines. The test
// re-executes itself as root through sudo -n setpriv, since setpriv raises
// nothing without the inheritable bit and still exits 0.
func TestClearAmbient(t *testing.T) {
	t.Parallel()
	if role() == "ambient" {
		ambientChild(t)
		return
	}
	if out, err := exec.CommandContext(t.Context(), "sudo", "-n", "true").CombinedOutput(); err != nil {
		missing(t, fmt.Sprintf("passwordless sudo is needed: %v %s", err, out))
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		missing(t, "setpriv is needed: "+err.Error())
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{
		"-n", "setpriv", "--reuid=" + strconv.Itoa(os.Getuid()), "--regid=" + strconv.Itoa(os.Getgid()), "--clear-groups",
		"--inh-caps", "+net_bind_service", "--ambient-caps", "+net_bind_service",
		"--", "env", childEnv + "=ambient", exe,
	}, childArgs(t)...)
	out, err := exec.CommandContext(t.Context(), "sudo", args...).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: TestClearAmbient")) {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func ambientChild(t *testing.T) {
	t.Helper()
	const netBindService = "0000000000000400"
	threadsCapAmb := func() map[string]string {
		entries, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		sets := map[string]string{}
		for _, e := range entries {
			data, err := os.ReadFile("/proc/self/task/" + e.Name() + "/status")
			if err != nil {
				continue // the thread ended
			}
			for line := range strings.SplitSeq(string(data), "\n") {
				if v, ok := strings.CutPrefix(line, "CapAmb:"); ok {
					sets[e.Name()] = strings.TrimSpace(v)
				}
			}
		}
		return sets
	}
	// Threads of their own, before and after the clear.
	const n = 16
	var ready, done sync.WaitGroup
	quit := make(chan struct{})
	results := make(chan string, n)
	for range n {
		ready.Add(1)
		done.Go(func() {
			runtime.LockOSThread()
			ready.Done()
			<-quit
			cmd := exec.CommandContext(t.Context(), "/proc/self/exe")
			cmd.Env = append(os.Environ(), childEnv+"=capamb")
			out, err := cmd.Output()
			if err != nil {
				results <- err.Error()
				return
			}
			results <- strings.TrimSpace(string(out))
		})
	}
	ready.Wait()
	for tid, set := range threadsCapAmb() {
		if set != netBindService {
			t.Fatalf("thread %s starts with CapAmb %s, want %s: setpriv raised nothing", tid, set, netBindService)
		}
	}

	cleared, err := ClearAmbient()
	if err != nil || cleared != 0x400 {
		t.Fatalf("ClearAmbient = %#x, %v", cleared, err)
	}
	for tid, set := range threadsCapAmb() {
		if set != "0000000000000000" {
			t.Errorf("thread %s keeps CapAmb %s", tid, set)
		}
	}
	close(quit)
	done.Wait()
	close(results)
	for r := range results {
		if r != "0000000000000000" {
			t.Errorf("a child has CapAmb %s", r)
		}
	}
}

// TestReleaseTerminal: under a pty, a process that does not lead its
// session gives up its controlling terminal: TIOCSTI on fd 2 fails
// afterwards, and SIGINT from the terminal still arrives. The session
// leader is a child of its own, which starts the one that is checked.
func TestReleaseTerminal(t *testing.T) {
	t.Parallel()
	switch role() {
	case "tty-leader":
		cmd := child(t, "tty")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		// Ctrl-C reaches the leader too; it waits for its child.
		signal.Notify(make(chan os.Signal, 1), os.Interrupt)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	case "tty":
		ttyChild(t)
		return
	}
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		missing(t, "no pty: "+err.Error())
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	cmd := child(t, "tty-leader")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tty.Close()
	var out lockedBuffer
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(&out, master) // until EIO: the children closed the terminal
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	waitFor(t, &out, "ready", exited)
	if _, err := master.Write([]byte{0x03}); err != nil { // Ctrl-C
		t.Fatal(err)
	}
	err = <-exited
	select {
	case <-copied:
	case <-time.After(time.Minute):
		t.Fatal("the terminal stays open")
	}
	if err != nil || !strings.Contains(out.String(), "SIGINT arrived") {
		t.Fatalf("children: %v\n%s", err, out.String())
	}
}

func ttyChild(t *testing.T) {
	t.Helper()
	runtime.LockOSThread() // capabilities are per thread
	sid, err := unix.Getsid(0)
	if err != nil || sid == unix.Getpid() {
		t.Fatalf("session %d, %v: the child leads its session", sid, err)
	}
	if tsid, err := unix.IoctlGetInt(2, unix.TIOCGSID); err != nil || tsid != sid {
		t.Fatalf("fd 2 is not the controlling terminal: %d, %v", tsid, err)
	}
	// CAP_SYS_ADMIN, which root has, would allow TIOCSTI on any terminal.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&hdr, &caps[0]); err != nil {
		t.Fatal(err)
	}
	caps[0].Effective &^= 1 << unix.CAP_SYS_ADMIN
	if err := unix.Capset(&hdr, &caps[0]); err != nil {
		t.Fatal(err)
	}
	// With dev.tty.legacy_tiocsti = 0 TIOCSTI fails before too.
	legacy, _ := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if strings.TrimSpace(string(legacy)) == "1" {
		if err := tiocsti(2, ' '); err != nil {
			t.Fatalf("TIOCSTI before: %v", err)
		}
	}

	if err := (linuxKernel{}).releaseTerminal(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.IoctlGetInt(2, unix.TIOCGSID); !errors.Is(err, unix.ENOTTY) {
		t.Errorf("TIOCGSID after: %v, want ENOTTY", err)
	}
	if err := tiocsti(2, 'x'); err == nil || strings.TrimSpace(string(legacy)) == "1" && !errors.Is(err, unix.EPERM) {
		t.Errorf("TIOCSTI after: %v, want EPERM", err)
	}
	if err := (linuxKernel{}).releaseTerminal(); err != nil {
		t.Errorf("again, without a terminal: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	fmt.Println("ready")
	select {
	case <-sigs:
		fmt.Println("SIGINT arrived")
	case <-time.After(time.Minute):
		t.Fatal("no SIGINT")
	}
}

// tiocsti types c into the terminal of fd.
func tiocsti(fd int, c byte) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCSTI, uintptr(unsafe.Pointer(&c))); errno != 0 {
		return errno
	}
	return nil
}

// lockedBuffer collects a child's output while it runs.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitFor waits until the output of a child holds s; it fails the test
// when the child exits first.
func waitFor(t *testing.T, out *lockedBuffer, s string, exited <-chan error) {
	t.Helper()
	deadline := time.After(time.Minute)
	for !strings.Contains(out.String(), s) {
		select {
		case err := <-exited:
			t.Fatalf("the child exited (%v) without %q:\n%s", err, s, out.String())
		case <-deadline:
			t.Fatalf("no %q in:\n%s", s, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}
