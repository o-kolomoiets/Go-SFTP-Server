// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
)

// stdinEOFEnv makes this test binary the child of the tests that start
// serve --print-details --stop-on-stdin-eof as gosftpd-gui does: it
// serves the configuration file it names, on the stdin, stdout and stderr
// its parent gave it, with the sandbox step of serve (Landlock, where the
// system has it). The child is this test binary without -test.v: the
// testing package then writes nothing to its stdout.
const stdinEOFEnv = "GOSFTPD_TEST_STDIN_EOF"

// stdinEOFChild runs serve and exits, in the child.
func stdinEOFChild() {
	if path := os.Getenv(stdinEOFEnv); path != "" {
		startSandbox = sandbox.Start // in this process only
		os.Exit(run(context.Background(), []string{"serve", "--allow-root", "--print-details", "--stop-on-stdin-eof", "--log-format", "json", "--config", path}, os.Stdout, os.Stderr))
	}
}

// supervised is gosftpd started as gosftpd-gui starts it: its stdin,
// stdout and stderr are pipes whose other ends the test holds, as the GUI
// does.
type supervised struct {
	cmd     *exec.Cmd
	stdin   *os.File // the write end
	stdout  *os.File // the read end, after the details line
	stderr  *os.File // the read end, read into logs
	logs    *lockedBuffer
	details serveDetails
	exited  chan struct{} // closed once cmd.Wait returned
}

// supervise starts the child of test, which serves the configuration file
// path, and waits for its details line.
func supervise(t *testing.T, test, path string) *supervised {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^"+test+"$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), stdinEOFEnv+"="+path,
		"GOSFTPD_CONFIG=", "GOSFTPD_LISTEN=", "GOSFTPD_LOG_LEVEL=", "GOSFTPD_LOG_FORMAT=")
	s := &supervised{cmd: cmd, logs: &lockedBuffer{}, exited: make(chan struct{})}
	var childEnds [3]*os.File
	for i, end := range []**os.File{&s.stdin, &s.stdout, &s.stderr} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			*end, childEnds[i] = w, r
		} else {
			*end, childEnds[i] = r, w
		}
		t.Cleanup(func() { r.Close(); w.Close() })
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = childEnds[0], childEnds[1], childEnds[2]
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait(); close(s.exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill() // if it still runs
		<-s.exited
	})
	for _, f := range childEnds {
		f.Close()
	}
	go func() { _, _ = io.Copy(s.logs, s.stderr) }()

	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(s.stdout).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		s.details = decodeServeDetails(t, l)
	case <-time.After(time.Minute):
		t.Fatalf("no details line:\n%s", s.logs.String())
	}
	return s
}

// wait waits until the child exits and returns its wait status.
func (s *supervised) wait(t *testing.T) syscall.WaitStatus {
	t.Helper()
	select {
	case <-s.exited:
	case <-time.After(time.Minute):
		t.Fatalf("gosftpd does not exit:\n%s", s.logs.String())
	}
	ws, _ := s.cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ws
}

// TestServeStopOnStdinEOFKilledGUI reproduces a killed gosftpd-gui (ADR
// 0013) with a session open: the kernel closes the write end of the stdin
// of serve --stop-on-stdin-eof and the read ends of its stdout and stderr.
// gosftpd is not killed by SIGPIPE when it next writes to stderr: it drains
// as on SIGTERM, refuses new connections, lets the open session upload
// until it ends, writes server.stop to the audit log and exits 0.
func TestServeStopOnStdinEOFKilledGUI(t *testing.T) {
	stdinEOFChild()
	t.Parallel()
	dir := t.TempDir()
	alice := newSigner(t)
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", alice)
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))
	g := supervise(t, "TestServeStopOnStdinEOFKilledGUI", path)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(g.details.Port))
	c, err := detailsLogin(t, addr, alice, knownHostsCallback(t, g.details.KnownHosts))
	if err != nil {
		t.Fatalf("login with the details: %v\n%s", err, g.logs.String())
	}
	if err := putFile(c, "/before.txt", "before"); err != nil {
		t.Fatal(err)
	}

	// The GUI dies.
	for _, f := range []*os.File{g.stdin, g.stdout, g.stderr} {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, "gosftpd refuses new connections", refused(addr))
	if err := putFile(c, "/during.txt", "during"); err != nil {
		t.Errorf("an upload during the drain: %v", err)
	}
	c.Close()
	ws := g.wait(t)
	if ws.Signaled() {
		t.Fatalf("killed by %v; audit log:\n%s", ws.Signal(), audit())
	}
	if ws.ExitStatus() != exitOK {
		t.Errorf("exit %d", ws.ExitStatus())
	}
	checkDrained(t, audit())
	// On Linux, server.start says what the sandbox step did.
	if start := events(t, audit(), "server.start"); len(start) != 1 || runtime.GOOS == "linux" && start[0]["landlock"] == nil {
		t.Errorf("server.start = %v", start)
	} else {
		t.Logf("landlock: %v", start[0]["landlock"])
	}
	for _, f := range []string{"before.txt", "during.txt"} {
		if _, err := os.Stat(filepath.Join(dir, "data", f)); err != nil {
			t.Error(err)
		}
	}
}

// TestServeStopOnStdinEOFSecondSignal: end of file on stdin counts as the
// first stop signal, so a SIGTERM during the drain that follows ends
// gosftpd at once, as a second SIGTERM does ("Stop now" in the GUI).
func TestServeStopOnStdinEOFSecondSignal(t *testing.T) {
	stdinEOFChild()
	t.Parallel()
	dir := t.TempDir()
	alice := newSigner(t)
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", alice)
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))
	g := supervise(t, "TestServeStopOnStdinEOFSecondSignal", path)
	c, err := detailsLogin(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(g.details.Port)), alice, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := g.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	waitLog(t, g.logs.String, `"msg":"stdin reached end of file; stopping as on SIGTERM"`)
	waitLog(t, g.logs.String, `"msg":"shutting down"`) // the open session holds the drain
	if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if ws := g.wait(t); !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("wait status %#x, want killed by SIGTERM:\n%s", ws, g.logs.String())
	}
	if log := audit(); !strings.Contains(log, `"event":"server.start"`) || strings.Contains(log, `"event":"server.stop"`) {
		t.Errorf("audit log:\n%s", log)
	}
	// The sandbox step leaves the interfaces to be listed.
	if strings.Contains(g.logs.String(), "cannot list the addresses") {
		t.Errorf("stderr:\n%s", g.logs.String())
	}
}

// TestServeStopOnStdinEOFSocket: stdin may be a socket, which reaches end
// of file when its peer closes.
func TestServeStopOnStdinEOFSocket(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdin, peer := os.NewFile(uintptr(fds[0]), "stdin"), os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() { stdin.Close(); peer.Close() })
	ts := startWith(t, stdin, "serve", "--allow-root", "--print-details", "--stop-on-stdin-eof", "--config", path)
	if _, err := peer.WriteString("discarded"); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	if code := ts.exited(t); code != exitOK || !strings.Contains(ts.stderr.String(), `msg="stdin reached end of file; stopping as on SIGTERM"`) {
		t.Errorf("exit %d:\n%s", code, ts.stderr.String())
	}
}

// TestServeStopOnStdinEOFDevNull: /dev/null, a character device, is
// refused like a terminal.
func TestServeStopOnStdinEOFDevNull(t *testing.T) {
	isolate(t)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	path := detailsConfig(t, t.TempDir(), `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	code, _, errOut := runWith(t, null, "serve", "--allow-root", "--stop-on-stdin-eof", "--config", path)
	if want := "Error: --stop-on-stdin-eof needs stdin to be a pipe or a socket whose other end the program that starts gosftpd holds; stdin is a terminal or another character device, such as /dev/null\n"; code != exitUsage || !strings.Contains(errOut, want) {
		t.Errorf("exit %d:\n%s", code, errOut)
	}
}
