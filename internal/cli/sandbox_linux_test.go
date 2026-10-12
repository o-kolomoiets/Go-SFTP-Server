// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
)

// The test process never applies Landlock: a ruleset cannot be lifted.
// A sandboxed test re-executes the test binary for itself; the child
// (serveChild) runs serve with the real sandbox.Start and answers the
// parent's commands, which look at the file system from inside the
// ruleset. Children never use t.TempDir, whose clean-up the ruleset would
// refuse: the parent makes every file.
const (
	// childEnv names the role of a re-executed child, as in the sandbox
	// package's tests.
	childEnv = "GOSFTPD_SANDBOX_CHILD"
	// requireEnv makes a sandboxed test fail instead of skipping where
	// Landlock, passwordless sudo or a mount namespace is missing; CI
	// sets it.
	requireEnv = "GOSFTPD_TEST_REQUIRE_SANDBOX"
	argsEnv    = "GOSFTPD_SANDBOX_ARGS" // serve's arguments, as JSON
	rootEnv    = "GOSFTPD_SANDBOX_ROOT" // a directory the child opens as an os.Root before serving
	swapEnv    = "GOSFTPD_SANDBOX_SWAP" // DIR=TARGET: the child swaps DIR for a link to TARGET before the rules are added
	// replyMark starts the child's answers on its stdout, which also
	// carries the audit log.
	replyMark = "@@ "
)

// missing skips the test for a missing precondition, or fails it when
// GOSFTPD_TEST_REQUIRE_SANDBOX=1.
func missing(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(requireEnv) == "1" {
		t.Fatalf("%s, and %s=1", why, requireEnv)
	}
	t.Skip(why)
}

// needLandlock skips the test without a usable Landlock (ABI 2 or later).
func needLandlock(t *testing.T) {
	t.Helper()
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || v < 2 {
		missing(t, fmt.Sprintf("no usable Landlock: ABI %d, %v", v, errno))
	}
}

// serveChild is the child of a sandboxed test: when this process is one,
// it runs serve under Landlock until the parent stops it, and reports
// true; the test then returns at once. Commands come one per line on
// stdin; each answer is one line on stdout after replyMark:
//
//	reload         reload, as SIGHUP does
//	read PATH      read a file
//	write PATH     open an existing file for writing
//	create PATH    create a file
//	list PATH      list a directory
//	rootread NAME  read a file through the os.Root opened before serving
//	stop           stop serving; the answer is "exit CODE"
//
// A file command answers "ok" or the error.
func serveChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(childEnv) != "serve" {
		return false
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv(argsEnv)), &args); err != nil {
		t.Fatal(err)
	}
	startSandbox = sandbox.Start // in this process only
	if swap := os.Getenv(swapEnv); swap != "" {
		dir, target, _ := strings.Cut(swap, "=")
		startSandbox = func(ctx context.Context, o sandbox.Options) (sandbox.Result, error) {
			// The mount is open; a link to elsewhere takes the place
			// of its directory before the rules are added.
			if err := os.Rename(dir, dir+".orig"); err != nil {
				return sandbox.Result{}, err
			}
			if err := os.Symlink(target, dir); err != nil {
				return sandbox.Result{}, err
			}
			return sandbox.Start(ctx, o)
		}
	}
	var before *os.Root
	if dir := os.Getenv(rootEnv); dir != "" {
		r, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		before = r
	}

	reply := func(s string) { _, _ = os.Stdout.WriteString(replyMark + s + "\n") }
	result := func(err error) {
		if err != nil {
			reply(err.Error())
			return
		}
		reply("ok")
	}
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), hupKey{}, (<-chan os.Signal)(hup)))
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, append([]string{"serve", "--allow-root"}, args...), os.Stdout, os.Stderr) }()
	lines := make(chan string)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			lines <- s.Text()
		}
	}()
	for {
		var line string
		select {
		case code := <-done:
			reply("exit " + strconv.Itoa(code))
			return true
		case l, ok := <-lines:
			if !ok {
				l = "stop"
			}
			line = l
		}
		cmd, arg, _ := strings.Cut(line, " ")
		switch cmd {
		case "reload":
			hup <- syscall.SIGHUP
			reply("ok")
		case "read":
			_, err := os.ReadFile(arg)
			result(err)
		case "write":
			result(closeFile(os.OpenFile(arg, os.O_WRONLY, 0)))
		case "create":
			result(closeFile(os.OpenFile(arg, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)))
		case "list":
			_, err := os.ReadDir(arg)
			result(err)
		case "rootread":
			_, err := before.ReadFile(arg)
			result(err)
		case "stop":
			cancel()
			reply("exit " + strconv.Itoa(<-done))
			return true
		default:
			reply("unknown command " + strconv.Quote(line))
		}
	}
}

func closeFile(f *os.File, err error) error {
	if err != nil {
		return err
	}
	return f.Close()
}

// sandboxOpts start a sandboxed serve.
type sandboxOpts struct {
	args []string // after "serve --allow-root"
	home string   // $HOME; "" keeps the test's
	dir  string   // working directory; "" keeps the test's
	env  []string // more environment
	// stderr, if set, is the child's fd 2, read back through logs.
	stderr *os.File
	logs   func() string
	// bind makes the child run in a mount namespace of its own, through
	// sudo -n unshare, with each pair (source, target) bind-mounted
	// before serve starts; then setpriv makes it this user again.
	bind []string
	// ambient starts the child through sudo -n setpriv as this user with
	// CAP_NET_BIND_SERVICE in its ambient set, as systemd's
	// AmbientCapabilities= does.
	ambient bool
	// failing expects serve to exit before it listens.
	failing bool
}

// sandboxed is gosftpd serve running under Landlock in a re-executed test
// binary.
type sandboxed struct {
	t       *testing.T
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	out     *lockedBuffer // stdout without the answers: the audit log on stdout, test output
	err     *lockedBuffer // stderr: the operational log and the banner
	logs    func() string
	replies chan string
	exited  chan error
	addr    string
	code    int // serve's exit code once known, else -1
}

// splitter sends the lines that start with replyMark to replies and the
// others to out.
type splitter struct {
	partial []byte
	out     *lockedBuffer
	replies chan<- string
}

func (s *splitter) Write(p []byte) (int, error) {
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(s.partial[:i+1])
		s.partial = s.partial[i+1:]
		if r, ok := strings.CutPrefix(line, replyMark); ok {
			s.replies <- strings.TrimSuffix(r, "\n")
			continue
		}
		_, _ = s.out.Write([]byte(line))
	}
}

// childArgs re-run the current top-level test, passing coverage on.
func childArgs(t *testing.T) []string {
	t.Helper()
	name, _, _ := strings.Cut(t.Name(), "/")
	args := []string{"-test.run=^" + name + "$", "-test.v", "-test.count=1", "-test.timeout=5m"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	return args
}

// startSandboxed starts serve under Landlock in a child and waits until it
// listens, or with o.failing until it exits.
func startSandboxed(t *testing.T, o sandboxOpts) *sandboxed {
	t.Helper()
	needLandlock(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal(o.args)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), childEnv+"=serve", argsEnv+"="+string(args), "GOSFTPD_CONFIG=", "GOSFTPD_LISTEN=", "GOSFTPD_LOG_LEVEL=", "GOSFTPD_LOG_FORMAT=")
	if o.home != "" {
		env = append(env, "HOME="+o.home, "XDG_CONFIG_HOME="+filepath.Join(o.home, ".config"))
	}
	env = append(env, o.env...)
	var cmd *exec.Cmd
	switch {
	case o.bind != nil:
		cmd = bindCommand(t, o.bind, env, append([]string{exe}, childArgs(t)...))
	case o.ambient:
		cmd = ambientCommand(t, env, append([]string{exe}, childArgs(t)...))
	default:
		// Not t.Context(), which ends before the clean-up that stops it.
		cmd = exec.CommandContext(context.WithoutCancel(t.Context()), exe, childArgs(t)...)
		cmd.Env = env
	}
	cmd.Dir = o.dir
	sb := &sandboxed{t: t, cmd: cmd, out: &lockedBuffer{}, replies: make(chan string, 16), exited: make(chan error, 1), code: -1}
	cmd.Stdout = &splitter{out: sb.out, replies: sb.replies}
	if o.stderr != nil {
		cmd.Stderr, sb.logs = o.stderr, o.logs
	} else {
		sb.err = &lockedBuffer{}
		cmd.Stderr, sb.logs = sb.err, sb.err.String
	}
	if sb.stdin, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { sb.exited <- cmd.Wait() }()
	t.Cleanup(func() { sb.stop(t) })

	addrRE := regexp.MustCompile(`listen:\s+(127\.0\.0\.1:\d+)`)
	deadline := time.After(time.Minute)
	for sb.addr == "" {
		if m := addrRE.FindStringSubmatch(sb.logs()); m != nil {
			sb.addr = m[1]
			break
		}
		select {
		case r := <-sb.replies:
			if code, ok := strings.CutPrefix(r, "exit "); ok {
				sb.code, _ = strconv.Atoi(code)
				sb.stop(t) // all its output is read once it has exited
				if !o.failing {
					t.Fatalf("serve exited with %s:\n%s", code, sb.logs())
				}
				return sb
			}
		case err := <-sb.exited:
			sb.exited <- err
			t.Fatalf("the child exited (%v):\n%s\n%s", err, sb.out.String(), sb.logs())
		case <-deadline:
			t.Fatalf("no listen address in:\n%s", sb.logs())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if o.failing {
		t.Fatalf("serve started:\n%s", sb.logs())
	}
	return sb
}

// needSudo skips the test without passwordless sudo or one of the tools.
func needSudo(t *testing.T, tools ...string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), "sudo", "-n", "true").CombinedOutput(); err != nil {
		missing(t, fmt.Sprintf("passwordless sudo is needed: %v %s", err, out))
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing(t, tool+" is needed: "+err.Error())
		}
	}
}

// ambientCommand runs argv as this user with CAP_NET_BIND_SERVICE in the
// ambient set, through sudo -n setpriv: setpriv raises nothing without the
// inheritable bit, and still exits 0.
func ambientCommand(t *testing.T, env, argv []string) *exec.Cmd {
	t.Helper()
	needSudo(t, "setpriv")
	args := append([]string{
		"-n", "setpriv", "--reuid=" + strconv.Itoa(os.Getuid()), "--regid=" + strconv.Itoa(os.Getgid()), "--clear-groups",
		"--inh-caps", "+net_bind_service", "--ambient-caps", "+net_bind_service", "--", "env",
	}, env...)
	return exec.CommandContext(context.WithoutCancel(t.Context()), "sudo", append(args, argv...)...)
}

// bindCommand runs argv as root in a mount namespace of its own, with each
// pair of bind (source, then target) bind-mounted, and then as this user
// again.
func bindCommand(t *testing.T, bind, env, argv []string) *exec.Cmd {
	t.Helper()
	needSudo(t, "unshare", "setpriv", "mount")
	const script = `while [ "$1" != -- ]; do mount --bind "$1" "$2" || exit 1; shift 2; done; shift
exec setpriv --reuid="$UID_" --regid="$GID_" --clear-groups -- env "$@"`
	args := append([]string{
		"-n", "env", "UID_=" + strconv.Itoa(os.Getuid()), "GID_=" + strconv.Itoa(os.Getgid()),
		"unshare", "--mount", "--propagation", "private", "sh", "-c", script, "sh",
	}, bind...)
	args = append(append(args, "--"), env...)
	return exec.CommandContext(context.WithoutCancel(t.Context()), "sudo", append(args, argv...)...)
}

// do sends a command and returns the answer.
func (sb *sandboxed) do(t *testing.T, command string) string {
	t.Helper()
	if _, err := io.WriteString(sb.stdin, command+"\n"); err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	select {
	case r := <-sb.replies:
		if code, ok := strings.CutPrefix(r, "exit "); ok {
			t.Fatalf("%s: serve exited with %s:\n%s", command, code, sb.logs())
		}
		return r
	case <-time.After(time.Minute):
		t.Fatalf("%s: no answer:\n%s", command, sb.logs())
	}
	return ""
}

// denied checks that a file command is refused with permission denied.
func (sb *sandboxed) denied(t *testing.T, command string) {
	t.Helper()
	if r := sb.do(t, command); !strings.HasSuffix(r, "permission denied") {
		t.Errorf("%s: %s, want permission denied", command, r)
	}
}

// allowed checks that a file command succeeds.
func (sb *sandboxed) allowed(t *testing.T, command string) {
	t.Helper()
	if r := sb.do(t, command); r != "ok" {
		t.Errorf("%s: %s", command, r)
	}
}

// reloaded counts the reloads that the log reports as ended; a reload logs
// one of these lines after everything else it logs.
func reloaded(log string) int {
	return strings.Count(log, `msg="configuration reloaded"`) + strings.Count(log, `msg="configuration reload failed; the running configuration stays"`)
}

// reload reloads and returns the server.reload event that audit, the
// audit log, gains. It also waits for the end of the reload in the
// operational log: stdout and stderr reach the test through pipes of
// their own, in no fixed order.
func (sb *sandboxed) reload(t *testing.T, audit func() string) map[string]any {
	t.Helper()
	n, logged := len(events(t, audit(), "server.reload")), reloaded(sb.logs())
	sb.do(t, "reload")
	deadline := time.Now().Add(time.Minute)
	for {
		if evs := events(t, audit(), "server.reload"); len(evs) > n && reloaded(sb.logs()) > logged {
			return evs[len(evs)-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no server.reload event; log:\n%s", sb.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stop stops serve once and returns its exit code; the child must then
// pass its test.
func (sb *sandboxed) stop(t *testing.T) int {
	t.Helper()
	if sb.cmd == nil {
		return sb.code
	}
	if sb.code < 0 {
		_, _ = io.WriteString(sb.stdin, "stop\n")
		select {
		case r := <-sb.replies:
			if code, ok := strings.CutPrefix(r, "exit "); ok {
				sb.code, _ = strconv.Atoi(code)
			}
		case <-time.After(time.Minute):
			t.Errorf("serve does not stop:\n%s", sb.logs())
		}
	}
	_ = sb.stdin.Close()
	select {
	case err := <-sb.exited:
		if name, _, _ := strings.Cut(t.Name(), "/"); err != nil || !strings.Contains(sb.out.String(), "--- PASS: "+name) {
			t.Errorf("child: %v\n%s\n%s", err, sb.out.String(), sb.logs())
		}
	case <-time.After(time.Minute):
		_ = sb.cmd.Process.Kill()
		t.Errorf("the child does not exit:\n%s", sb.logs())
	}
	sb.cmd = nil
	return sb.code
}

// audit returns the audit log on the child's stdout.
func (sb *sandboxed) audit() string { return sb.out.String() }

// sftpConn is an SFTP client with its connection.
type sftpConn struct {
	*sftp.Client
	conn *ssh.Client
}

// Close closes the client and the connection; serve's shutdown would wait
// for an open one.
func (c *sftpConn) Close() {
	_ = c.Client.Close()
	_ = c.conn.Close()
}

// sftpClient logs in as user with key.
func sftpClient(t *testing.T, addr, user string, key ssh.Signer) *sftpConn {
	t.Helper()
	conn, err := dialSSH(addr, user, key)
	if err != nil {
		t.Fatalf("login as %s: %v", user, err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	sc := &sftpConn{Client: c, conn: conn}
	t.Cleanup(sc.Close)
	return sc
}

func dialSSH(addr, user string, key ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

// canLogIn reports whether user can log in with key.
func canLogIn(addr, user string, key ssh.Signer) bool {
	c, err := dialSSH(addr, user, key)
	if err == nil {
		c.Close()
	}
	return err == nil
}

// files writes a tree below base: a name ending in / is a directory, any
// other a 0600 file with its content. Directories are 0700.
func files(t *testing.T, base string, tree map[string]string) {
	t.Helper()
	for name, data := range tree {
		path := filepath.Join(base, filepath.FromSlash(name))
		dir := path
		if !strings.HasSuffix(name, "/") {
			dir = filepath.Dir(path)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(name, "/") {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// putFile uploads data to path.
func putFile(c *sftpConn, path, data string) error {
	f, err := c.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// waitLog waits until the log holds s.
func waitLog(t *testing.T, logs func() string, s string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for !strings.Contains(logs(), s) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in:\n%s", s, logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dropCaches makes the kernel reclaim dentries, through sudo -n; it
// reports whether it did.
func dropCaches(t *testing.T) bool {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "sudo", "-n", "sh", "-c", "echo 2 > /proc/sys/vm/drop_caches").CombinedOutput()
	if err != nil {
		missing(t, fmt.Sprintf("drop_caches through sudo -n: %v %s", err, out))
		return false
	}
	return true
}

// checkAuditSchema checks audit lines against the audit schema of
// internal/server/testdata.
func checkAuditSchema(t *testing.T, log string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "server", "testdata", "audit.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Schema  int      `json:"schema"`
		Common  []string `json:"common"`
		Context []string `json:"context"`
		Events  map[string]struct {
			Required []string `json:"required"`
			Optional []string `json:"optional"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(log, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue // test output
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		ev, _ := m["event"].(string)
		spec, ok := schema.Events[ev]
		if !ok {
			t.Errorf("event %q is not in the schema", ev)
			continue
		}
		if m["schema"] != float64(schema.Schema) {
			t.Errorf("%s: schema = %v", ev, m["schema"])
		}
		allowed := map[string]bool{}
		for _, list := range [][]string{schema.Common, schema.Context, spec.Required, spec.Optional} {
			for _, k := range list {
				allowed[k] = true
			}
		}
		for _, list := range [][]string{schema.Common, spec.Required} {
			for _, k := range list {
				if _, ok := m[k]; !ok {
					t.Errorf("%s: missing field %q in %s", ev, k, line)
				}
			}
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("%s: field %q is not in the schema", ev, k)
			}
		}
	}
}
