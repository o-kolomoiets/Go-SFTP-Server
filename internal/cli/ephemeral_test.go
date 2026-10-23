// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
)

// detailsFields are the fields of the line of serve --ephemeral, in their
// order (ADR 0012).
var detailsFields = []string{"host", "port", "user", "password", "private_key_path", "dir", "host_key_fingerprint", "known_hosts", "pid", "version"}

// ephemeralTemp points the temporary directory of os.MkdirTemp at a new
// empty directory and returns it.
func ephemeralTemp(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("TMP", tmp)
		t.Setenv("TEMP", tmp)
	}
	return tmp
}

// entries lists the names in dir.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(des))
	for i, de := range des {
		names[i] = de.Name()
	}
	return names
}

// waitDetails waits for the line of serve --ephemeral on stdout and
// decodes it.
func waitDetails(t *testing.T, ts *testServer) ephemeralDetails {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(ts.stdout.String(), "\n") {
		if time.Now().After(deadline) {
			t.Fatalf("no connection details on stdout:\n%s", ts.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return decodeDetails(t, ts.stdout.String())
}

// decodeDetails checks that out is exactly one line, a JSON object with
// the fields of detailsFields in that order, port and pid numbers and the
// others strings, and decodes it.
func decodeDetails(t *testing.T, out string) ephemeralDetails {
	t.Helper()
	line, rest, _ := strings.Cut(out, "\n")
	if rest != "" {
		t.Fatalf("more than one line on stdout:\n%s", out)
	}
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not a JSON object: %q", line)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		key, _ := tok.(string)
		keys = append(keys, key)
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		_, number := v.(json.Number)
		if _, str := v.(string); number != (key == "port" || key == "pid") || !number && !str {
			t.Errorf("%s = %#v: want a number for port and pid, else a string", key, v)
		}
	}
	if !slices.Equal(keys, detailsFields) {
		t.Errorf("fields %v, want %v", keys, detailsFields)
	}
	var d ephemeralDetails
	if err := json.Unmarshal([]byte(line), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// hostKeyCallback checks the host key against the known_hosts line of d.
func hostKeyCallback(t *testing.T, d ephemeralDetails) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeFile(t, path, d.KnownHosts+"\n")
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		if fp := ssh.FingerprintSHA256(key); fp != d.HostKeyFingerprint {
			return errors.New("host key " + fp + ", the details say " + d.HostKeyFingerprint)
		}
		return cb(host, remote, key)
	}
}

// ephemeralLogin logs in to the server of d with auth, checking its host
// key against the details.
func ephemeralLogin(t *testing.T, d ephemeralDetails, user string, auth ssh.AuthMethod) (*sftpConn, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback(t, d),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sc := &sftpConn{Client: c, conn: conn}
	t.Cleanup(sc.Close)
	return sc, nil
}

// clientKey reads the private key of d.
func clientKey(t *testing.T, d ephemeralDetails) ssh.AuthMethod {
	t.Helper()
	pem, err := os.ReadFile(d.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.PublicKeys(s)
}

// TestEphemeral: serve --ephemeral serves a new directory to the user
// test with a password and a key, prints the details as one JSON line,
// the only output on stdout, ignores SIGHUP, and removes everything it
// made when it stops (without Landlock in the test process, the directory
// too).
func TestEphemeral(t *testing.T) {
	home := isolate(t)
	tmp := ephemeralTemp(t)
	ts := startServe(t, "--ephemeral")
	d := waitDetails(t, ts)

	made := entries(t, tmp)
	if len(made) != 1 || !strings.HasPrefix(made[0], "gosftpd-ephemeral-") {
		t.Fatalf("%s holds %v", tmp, made)
	}
	dir := filepath.Join(tmp, made[0])
	if got := entries(t, dir); !slices.Equal(got, []string{"data", "id_ed25519"}) {
		t.Errorf("%s holds %v", dir, got)
	}
	if d.Host != "127.0.0.1" || net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) != ts.addr || d.User != "test" ||
		d.PrivateKeyPath != filepath.Join(dir, "id_ed25519") || d.Dir != filepath.Join(dir, "data") ||
		d.PID != os.Getpid() || d.Version != version.Get().Version {
		t.Errorf("details %+v; listening on %s", d, ts.addr)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(d.Password); err != nil || len(raw) != 24 {
		t.Errorf("password %q: %d bytes, %v", d.Password, len(raw), err)
	}
	if !strings.HasPrefix(d.KnownHosts, "["+d.Host+"]:"+strconv.Itoa(d.Port)+" ssh-ed25519 ") || !strings.HasPrefix(d.HostKeyFingerprint, "SHA256:") {
		t.Errorf("known_hosts %q, fingerprint %q", d.KnownHosts, d.HostKeyFingerprint)
	}
	if fi, err := os.Stat(d.PrivateKeyPath); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("client key: %v, %v", fi, err)
	}
	if strings.Contains(ts.stderr.String(), d.Password) {
		t.Errorf("the password is on stderr:\n%s", ts.stderr.String())
	}

	key := clientKey(t, d)
	c, err := ephemeralLogin(t, d, "test", key)
	if err != nil {
		t.Fatalf("key login: %v", err)
	}
	if err := putFile(c, "/a.txt", "by key"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got, err := os.ReadFile(filepath.Join(d.Dir, "a.txt")); err != nil || string(got) != "by key" {
		t.Errorf("uploaded: %q, %v", got, err)
	}
	c, err = ephemeralLogin(t, d, "test", ssh.Password(d.Password))
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	if err := putFile(c, "/b.txt", "by password"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := ephemeralLogin(t, d, "test", ssh.Password(d.Password+"x")); err == nil {
		t.Error("a wrong password logs in")
	}
	if _, err := ephemeralLogin(t, d, "alice", key); err == nil {
		t.Error("another user name logs in")
	}

	ts.hup <- syscall.SIGHUP
	waitLog(t, ts.stderr.String, `msg="SIGHUP ignored" reason="serve --ephemeral does not reload: a new configuration would change the password, the client key and the host key"`)
	for _, auth := range []ssh.AuthMethod{key, ssh.Password(d.Password)} {
		c, err := ephemeralLogin(t, d, "test", auth)
		if err != nil {
			t.Fatalf("after SIGHUP: %v", err)
		}
		if _, err := c.Stat("/a.txt"); err != nil {
			t.Error(err)
		}
		c.Close()
	}

	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, ts.stderr.String())
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after the stop", tmp, got)
	}
	logs := ts.stderr.String()
	for _, want := range []string{
		`"event":"server.start"`, `"event":"auth.success"`, `"event":"fs.upload"`, `"event":"server.stop"`,
		"host key: in memory (generated, never written)", "connect: sftp -P " + strconv.Itoa(d.Port) + " test@127.0.0.1",
		`msg="removed the client key, the data and the directory" dir=` + dir,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("stderr lacks %s:\n%s", want, logs)
		}
	}
	if evs := events(t, logs, "server.reload"); len(evs) != 0 {
		t.Errorf("server.reload after SIGHUP: %v", evs)
	}
	if again := decodeDetails(t, ts.stdout.String()); again != d {
		t.Errorf("stdout changed: %+v", again)
	}
	// The host key was never written, also not to the state directory.
	if got := entries(t, home); len(got) != 0 {
		t.Errorf("%s holds %v", home, got)
	}
}

// TestEphemeralAuditFile: --audit-output names a file for the audit log,
// which then is neither on stdout nor on stderr.
func TestEphemeralAuditFile(t *testing.T) {
	isolate(t)
	ephemeralTemp(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts := startServe(t, "--ephemeral", "--audit-output", path)
	d := waitDetails(t, ts)
	c, err := ephemeralLogin(t, d, "test", ssh.Password(d.Password))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"server.start", "auth.success", "server.stop"} {
		if len(events(t, string(data), ev)) != 1 {
			t.Errorf("no %s in the audit file:\n%s", ev, data)
		}
	}
	if strings.Contains(ts.stderr.String(), `"event":`) {
		t.Errorf("audit events on stderr:\n%s", ts.stderr.String())
	}
	decodeDetails(t, ts.stdout.String())
}

// TestEphemeralFlags: the flags that --ephemeral replaces, a second --dir
// or --listen, the audit log on stdout and a bad value exit 2 before
// anything is created.
func TestEphemeralFlags(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	share := t.TempDir()
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", filepath.Join(share, "c.toml")}, "--ephemeral and --config cannot be used together"},
		{[]string{"--authorized-keys", filepath.Join(share, "keys")}, "--ephemeral and --authorized-keys cannot be used together"},
		{[]string{"--user", "alice"}, "--ephemeral and --user cannot be used together"},
		{[]string{"--host-key", filepath.Join(share, "key")}, "--ephemeral and --host-key cannot be used together"},
		{[]string{"--state-dir", share}, "--ephemeral and --state-dir cannot be used together"},
		{[]string{"--dir", share, "--dir", t.TempDir()}, "--ephemeral serves one directory: give --dir once"},
		{[]string{"--listen", "127.0.0.1:0", "--listen", "127.0.0.1:0"}, "--ephemeral describes one listener: give --listen once"},
		{[]string{"--audit-output", "stdout"}, "--audit-output stdout cannot be used with --ephemeral"},
		{[]string{"--on-conflict", "merge"}, "--on-conflict"},
		{[]string{"--log-level", "loud"}, "--log-level"},
		{[]string{"--dir", filepath.Join(share, "missing")}, "missing"},
	} {
		args := append([]string{"serve", "--ephemeral", "--allow-root"}, tt.args...)
		code, out, errOut := execute(t, args...)
		if code != exitUsage || !strings.Contains(errOut, tt.want) || out != "" {
			t.Errorf("%q: exit %d, stdout %q, stderr:\n%s", tt.args, code, out, errOut)
		}
		if got := entries(t, tmp); len(got) != 0 {
			t.Fatalf("%q: %s holds %v", tt.args, tmp, got)
		}
	}
	// The refusal to run as root stays, and names --allow-root.
	if os.Geteuid() == 0 {
		code, _, errOut := execute(t, "serve", "--ephemeral")
		if code != exitUsage || !strings.Contains(errOut, "--allow-root") {
			t.Errorf("as root: exit %d:\n%s", code, errOut)
		}
		if got := entries(t, tmp); len(got) != 0 {
			t.Fatalf("as root: %s holds %v", tmp, got)
		}
	}
}

// TestEphemeralEnvironment: $GOSFTPD_CONFIG and $GOSFTPD_LISTEN are
// ignored with a warning; the log variables apply as for serve.
func TestEphemeralEnvironment(t *testing.T) {
	isolate(t)
	ephemeralTemp(t)
	t.Setenv(config.EnvConfig, filepath.Join(t.TempDir(), "missing.toml"))
	t.Setenv(config.EnvListen, "192.0.2.1:22,192.0.2.2:22")
	t.Setenv(config.EnvLogFormat, "json")
	ts := startServe(t, "--ephemeral")
	d := waitDetails(t, ts)
	if d.Host != "127.0.0.1" || net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) != ts.addr {
		t.Errorf("details %+v; listening on %s", d, ts.addr)
	}
	for _, want := range []string{
		`"msg":"configuration","detail":"$GOSFTPD_CONFIG is ignored with --ephemeral, which uses no configuration file"`,
		`"msg":"configuration","detail":"$GOSFTPD_LISTEN is ignored with --ephemeral, which listens on --listen, by default 127.0.0.1:0"`,
	} {
		if !strings.Contains(ts.stderr.String(), want) {
			t.Errorf("stderr lacks %s:\n%s", want, ts.stderr.String())
		}
	}
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
}

// TestEphemeralIPv6: the details of an IPv6 listener.
func TestEphemeralIPv6(t *testing.T) {
	isolate(t)
	ephemeralTemp(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	ln.Close()
	ts := startServe(t, "--ephemeral", "--listen", "[::1]:0")
	d := waitDetails(t, ts)
	if d.Host != "::1" || !strings.HasPrefix(d.KnownHosts, "[::1]:"+strconv.Itoa(d.Port)+" ") {
		t.Errorf("details %+v", d)
	}
	if _, err := ephemeralLogin(t, d, "test", ssh.Password(d.Password)); err != nil {
		t.Errorf("login over IPv6: %v", err)
	}
}

// TestEphemeralDir: --dir names the data directory, which serve --ephemeral
// serves as / and never deletes; --read-only and --on-conflict apply to it.
func TestEphemeralDir(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	share := t.TempDir()
	writeFile(t, filepath.Join(share, "kept.txt"), "kept")
	ts := startServe(t, "--ephemeral", "--dir", share, "--on-conflict", "reject")
	d := waitDetails(t, ts)
	if d.Dir != share {
		t.Errorf("dir %q, want %q", d.Dir, share)
	}
	made := entries(t, tmp)
	if len(made) != 1 || !slices.Equal(entries(t, filepath.Join(tmp, made[0])), []string{"id_ed25519"}) {
		t.Errorf("%s holds %v", tmp, made)
	}
	c, err := ephemeralLogin(t, d, "test", clientKey(t, d))
	if err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/new.txt", "new"); err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/kept.txt", "replaced"); err == nil {
		t.Error("on_conflict = reject: kept.txt replaced")
	}
	c.Close()
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if got := entries(t, share); !slices.Equal(got, []string{"kept.txt", "new.txt"}) {
		t.Errorf("--dir holds %v after the stop", got)
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after the stop", tmp, got)
	}

	ts = startServe(t, "--ephemeral", "--read-only")
	d = waitDetails(t, ts)
	writeFile(t, filepath.Join(d.Dir, "fixture.txt"), "fixture") // as a test puts one there
	c, err = ephemeralLogin(t, d, "test", ssh.Password(d.Password))
	if err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/up.txt", "x"); err == nil {
		t.Error("--read-only: upload accepted")
	}
	f, err := c.Open("/fixture.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(f); err != nil || string(got) != "fixture" {
		t.Errorf("download: %q, %v", got, err)
	}
	f.Close()
	c.Close()
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after the stop", tmp, got)
	}
}

// TestEphemeralSandboxStep: the sandbox step gets the directory held open
// and runs before the line is printed; a start that fails before the line
// exits 1 without it and removes the directory. Not parallel: it replaces
// startSandbox.
func TestEphemeralSandboxStep(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	defer func() { startSandbox = noSandbox }()

	var stdout lockedBuffer
	var calls []sandbox.Options
	startSandbox = func(_ context.Context, o sandbox.Options) (sandbox.Result, error) {
		if stdout.String() != "" {
			t.Errorf("stdout before the sandbox step: %q", stdout.String())
		}
		calls = append(calls, o)
		return sandbox.Result{}, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "--ephemeral", "--allow-root"}, &stdout, io.Discard) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stdout.String(), "\n") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != exitOK {
		t.Fatalf("exit %d", code)
	}
	d := decodeDetails(t, stdout.String())
	if len(calls) != 1 || calls[0].Ephemeral == nil || calls[0].Config.EphemeralDir != filepath.Dir(d.PrivateKeyPath) {
		t.Fatalf("calls %+v", calls)
	}
	if runtime.GOOS == "linux" && calls[0].Ephemeral.FD < 0 {
		t.Errorf("the directory is not held open: %+v", calls[0].Ephemeral)
	}

	startSandbox = func(context.Context, sandbox.Options) (sandbox.Result, error) {
		return sandbox.Result{}, errors.New("landlock: failed: self-check: / can still be opened")
	}
	code, out, errOut := execute(t, "serve", "--ephemeral", "--allow-root")
	if code != exitFailure || out != "" || !strings.Contains(errOut, "Error: landlock: failed") {
		t.Errorf("exit %d\nstdout %q\nstderr:\n%s", code, out, errOut)
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after a failed start", tmp, got)
	}

	startSandbox = noSandbox
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	code, out, errOut = execute(t, "serve", "--ephemeral", "--allow-root", "--listen", ln.Addr().String())
	if code != exitFailure || out != "" {
		t.Errorf("a port in use: exit %d\nstdout %q\nstderr:\n%s", code, out, errOut)
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after a failed start", tmp, got)
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

// TestEphemeralStdoutFails: when the line cannot be written, serve stops
// at once with exit status 1 and removes the directory.
func TestEphemeralStdoutFails(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	var stderr lockedBuffer
	code := run(t.Context(), []string{"serve", "--ephemeral", "--allow-root"}, failingWriter{}, &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "Error: writing the connection details: broken pipe") {
		t.Errorf("exit %d:\n%s", code, stderr.String())
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v", tmp, got)
	}
}

// newTestEphemeral makes what serve --ephemeral makes at start.
func newTestEphemeral(t *testing.T) *ephemeral {
	t.Helper()
	cmd := newServeCmd()
	if err := cmd.ParseFlags([]string{"--ephemeral"}); err != nil {
		t.Fatal(err)
	}
	_, e, err := newEphemeral(cmd.Flags(), serveOptions{ephemeral: true, onConflict: "rename", logLevel: "info", logFormat: "text"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestEphemeralRemove: under Landlock the directory stays, empty; a key
// that is already gone is no error.
func TestEphemeralRemove(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	e := newTestEphemeral(t)
	writeFile(t, filepath.Join(e.data, "a.txt"), "a")
	if err := os.Mkdir(filepath.Join(e.data, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.dir, "id_ed25519")); err != nil {
		t.Fatal(err)
	}
	e.landlocked = true
	if err := e.remove(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, e.dir); len(got) != 0 {
		t.Errorf("%s holds %v", e.dir, got)
	}
	if got := entries(t, tmp); len(got) != 1 {
		t.Errorf("%s holds %v", tmp, got)
	}
}

// TestEphemeralCleanupErrors: a start that fails after the directory was
// made removes it whole; a clean-up that fails says so and keeps the
// directory.
func TestEphemeralCleanupErrors(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	e := newTestEphemeral(t)
	writeFile(t, filepath.Join(e.data, "a.txt"), "a")
	e.discard()
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("after discard: %s holds %v", tmp, got)
	}

	e = newTestEphemeral(t)
	_ = e.root.Close() // the removal through it fails
	if err := e.remove(t.Context()); err == nil || !strings.HasPrefix(err.Error(), "--ephemeral: cleaning up "+e.dir+": ") {
		t.Errorf("remove = %v", err)
	}
	if got := entries(t, e.dir); !slices.Equal(got, []string{"data", "id_ed25519"}) {
		t.Errorf("after a failed clean-up: %s holds %v", e.dir, got)
	}
}

// TestDetailsLine: the line's field names and order, and its host: the
// listener's, or 127.0.0.1 for an unspecified address.
func TestDetailsLine(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(ephemeralDetails{
		Host: "127.0.0.1", Port: 40123, User: "test", Password: "pw", PrivateKeyPath: "/tmp/x/id_ed25519", Dir: "/tmp/x/data",
		HostKeyFingerprint: "SHA256:fp", KnownHosts: "[127.0.0.1]:40123 ssh-ed25519 AAAA", PID: 4242, Version: "v0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"host":"127.0.0.1","port":40123,"user":"test","password":"pw","private_key_path":"/tmp/x/id_ed25519","dir":"/tmp/x/data",` +
		`"host_key_fingerprint":"SHA256:fp","known_hosts":"[127.0.0.1]:40123 ssh-ed25519 AAAA","pid":4242,"version":"v0.5.0"}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	for addr, want := range map[string]string{
		"127.0.0.1:2022": "127.0.0.1",
		"0.0.0.0:2022":   "127.0.0.1",
		"[::]:2022":      "127.0.0.1",
		"[::1]:2022":     "::1",
		"192.0.2.7:2022": "192.0.2.7",
	} {
		tcp, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if host, port := detailsHost(tcp); host != want || port != 2022 {
			t.Errorf("%s: %s, %d", addr, host, port)
		}
	}
}

// TestServeListenCounted: without --ephemeral the last --listen wins, as
// before; the help still shows a string flag with its default.
func TestServeListenCounted(t *testing.T) {
	t.Parallel()
	cmd := newServeCmd()
	if err := cmd.ParseFlags([]string{"--listen", "127.0.0.1:1", "--listen", "127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	if f := cmd.Flags().Lookup("listen"); f.Value.String() != "127.0.0.1:2" || f.DefValue != ":2022" || f.Value.Type() != "string" {
		t.Errorf("--listen %q, default %q, type %q", f.Value.String(), f.DefValue, f.Value.Type())
	}
	code, out, _ := execute(t, "serve", "--help")
	if code != exitOK || !strings.Contains(out, `--listen string `) || !strings.Contains(out, `(default ":2022")`) || !strings.Contains(out, "--ephemeral ") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}
