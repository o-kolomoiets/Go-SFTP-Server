// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// syncBuffer is a goroutine-safe audit sink that can be made to fail.
type syncBuffer struct {
	mu   sync.Mutex
	b    bytes.Buffer
	fail bool
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return 0, syscall.ENOSPC
	}
	return b.b.Write(p)
}

func (b *syncBuffer) setFail(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = v
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type env struct {
	addr     string
	share    string
	outside  string
	hostKey  ssh.PublicKey
	userKey  ssh.Signer
	auditLog *syncBuffer
}

func signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// start runs a server on 127.0.0.1:0 serving <tmp>/share, with a file
// <tmp>/outside/secret.txt next to it.
func start(t *testing.T, policy vfs.ConflictPolicy, readOnly bool) *env {
	t.Helper()
	return startWith(t, startOpts{policy: policy, readOnly: readOnly})
}

type startOpts struct {
	policy     vfs.ConflictPolicy
	readOnly   bool
	categories []string // audit categories; nil means the defaults
}

func startWith(t *testing.T, o startOpts) *env {
	t.Helper()
	policy, readOnly := o.policy, o.readOnly
	base := t.TempDir()
	e := &env{
		share:    filepath.Join(base, "share"),
		outside:  filepath.Join(base, "outside"),
		userKey:  signer(t),
		auditLog: &syncBuffer{},
	}
	for _, d := range []string{e.share, e.outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(e.outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.share, "a.txt"), []byte("original content"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := vfs.DefaultMountOptions()
	opts.OnConflict = policy
	mounts, err := vfs.Open([]vfs.MountSpec{{Name: "share", Path: e.share, ReadOnly: readOnly, Options: opts}},
		vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	keys, warnings := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(e.userKey.PublicKey()), "test")
	if len(warnings) > 0 {
		t.Fatal(warnings)
	}
	hk := signer(t)
	e.hostKey = hk.PublicKey()
	srv, err := New(Config{
		HostKeys: []ssh.Signer{hk},
		Auth:     auth.New("", keys),
		Mounts:   mounts,
		Audit:    mustAudit(t, e.auditLog, o.categories),
	})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve() = %v", err)
		}
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		if err := srv.Shutdown(sctx); err != nil {
			t.Errorf("Shutdown() = %v", err)
		}
		mounts.Close()
	})
	return e
}

func mustAudit(t *testing.T, w io.Writer, categories []string) *audit.Logger {
	t.Helper()
	l, err := audit.NewWithOptions(w, slog.New(slog.DiscardHandler), audit.Options{Categories: categories})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *env) dial(t *testing.T, key ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(e.hostKey),
		Timeout:         10 * time.Second,
	})
}

func (e *env) sftp(t *testing.T) *sftp.Client {
	t.Helper()
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); conn.Close() })
	return c
}

func writeRemote(t *testing.T, c *sftp.Client, path, data string) {
	t.Helper()
	f, err := c.Create(path)
	if err != nil {
		t.Fatalf("Create(%q): %v", path, err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readRemote(t *testing.T, c *sftp.Client, path string) (string, error) {
	t.Helper()
	f, err := c.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}

// statusCode returns the SFTP status code of a client error; the pkg/sftp
// client turns NO_SUCH_FILE and PERMISSION_DENIED into os errors.
func statusCode(err error) uint32 {
	var se *sftp.StatusError
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 2
	case errors.Is(err, os.ErrPermission):
		return 3
	case errors.As(err, &se):
		return se.Code
	}
	return 0
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)

	if wd, err := c.Getwd(); err != nil || wd != "/" {
		t.Errorf("Getwd() = %q, %v", wd, err)
	}
	payload := strings.Repeat("0123456789", 100_000) // 1 MB, many packets
	writeRemote(t, c, "/new.bin", payload)
	if got, err := readRemote(t, c, "/new.bin"); err != nil || got != payload {
		t.Fatalf("read back %d bytes, %v", len(got), err)
	}
	if err := c.Mkdir("/dir"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rename("/new.bin", "/dir/moved.bin"); err != nil {
		t.Fatal(err)
	}
	if err := c.PosixRename("/dir/moved.bin", "/dir/again.bin"); err != nil {
		t.Fatal(err)
	}
	entries, err := c.ReadDir("/dir")
	if err != nil || len(entries) != 1 || entries[0].Name() != "again.bin" {
		t.Errorf("ReadDir = %v, %v", entries, err)
	}
	if err := c.Remove("/dir/again.bin"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveDirectory("/dir"); err != nil {
		t.Fatal(err)
	}

	log := e.auditLog.String()
	for _, ev := range []string{"conn.accept", "auth.success", "session.start", `"event":"fs.upload"`, "fs.download", "fs.mkdir", "fs.rename", "fs.remove", "fs.rmdir"} {
		if !strings.Contains(log, ev) {
			t.Errorf("audit log has no %s event", ev)
		}
	}
}

func TestConflictRenameKeepsOriginal(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)

	f, err := c.Create("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	// FSETSTAT and FSTAT on the open handle must reach the copy, never the
	// original (pkg/sftp resolves them through the request path).
	if err := f.Truncate(2); err != nil {
		t.Fatalf("FSETSTAT size: %v", err)
	}
	if fi, err := f.Stat(); err != nil || fi.Size() != 2 {
		t.Fatalf("FSTAT = %v, %v; want size 2", fi, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := c.Chtimes("/a (1).txt", mtime, mtime); err != nil {
		t.Fatal(err)
	}

	if got, _ := os.ReadFile(filepath.Join(e.share, "a.txt")); string(got) != "original content" {
		t.Errorf("original = %q", got)
	}
	copyPath := filepath.Join(e.share, "a (1).txt")
	if got, _ := os.ReadFile(copyPath); string(got) != "ne" {
		t.Errorf("copy = %q, want %q", got, "ne")
	}
	if fi, err := os.Stat(copyPath); err != nil || !fi.ModTime().Equal(mtime) {
		t.Errorf("copy mtime = %v, %v", fi.ModTime(), err)
	}
	if err := c.Truncate("/a.txt", 0); statusCode(err) != 3 {
		t.Errorf("truncating a file without an open upload: %v, want permission denied", err)
	}
	if !strings.Contains(e.auditLog.String(), `"final_path":"/a (1).txt"`) {
		t.Error("audit log lacks the final path")
	}
}

func TestErrorsDoNotLeakHostPaths(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictReject, false)
	if err := os.Symlink(e.outside, filepath.Join(e.share, "evil")); err != nil {
		t.Skip(err)
	}
	c := e.sftp(t)

	var msgs []string
	for _, p := range []string{"/evil/secret.txt", "/../outside/secret.txt", "/missing"} {
		_, err := readRemote(t, c, p)
		if err == nil {
			t.Fatalf("read %q succeeded", p)
		}
		msgs = append(msgs, err.Error())
	}
	_, err := c.Create("/a.txt") // exists, policy reject
	if err == nil {
		t.Fatal("overwrite with on_conflict=reject succeeded")
	}
	msgs = append(msgs, err.Error())
	if err := c.Symlink("/etc", "/link"); statusCode(err) != 8 { // SSH_FX_OP_UNSUPPORTED
		t.Errorf("Symlink error = %v, want op unsupported", err)
	}
	if err := c.Link("/a.txt", "/hard"); statusCode(err) != 8 { // hardlink@openssh.com sent directly
		t.Errorf("Link error = %v, want op unsupported", err)
	}

	for _, m := range msgs {
		if strings.Contains(m, e.share) || strings.Contains(m, e.outside) || strings.Contains(m, "escapes") {
			t.Errorf("client message leaks host details: %q", m)
		}
	}
	if !strings.Contains(msgs[3], "on_conflict=reject") {
		t.Errorf("reject message = %q", msgs[3])
	}
}

func TestReadOnly(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, true)
	c := e.sftp(t)
	if _, err := c.Create("/x"); statusCode(err) != 3 { // SSH_FX_PERMISSION_DENIED
		t.Errorf("Create on a read-only mount: %v", err)
	}
	if got, err := readRemote(t, c, "/a.txt"); err != nil || got != "original content" {
		t.Errorf("read = %q, %v", got, err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	if conn, err := e.dial(t, signer(t)); err == nil {
		conn.Close()
		t.Fatal("unknown key accepted")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(e.auditLog.String(), "auth.failure") {
		if time.Now().After(deadline) {
			t.Fatal("no auth.failure event")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOnlySFTPSubsystem(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, run := range []func(*ssh.Session) error{
		func(s *ssh.Session) error { return s.Run("id") },
		func(s *ssh.Session) error { return s.Shell() },
		func(s *ssh.Session) error { return s.RequestSubsystem("netconf") },
	} {
		sess, err := conn.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := run(sess); err == nil {
			t.Error("non-SFTP session request succeeded")
		}
		sess.Close()
	}
	if _, err := conn.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Error("port forwarding succeeded")
	}
}

// OpenSSH scp treats a session without exit-status as failed.
func TestExitStatus(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		t.Fatalf("subsystem request: %v, %v", ok, err)
	}
	c, err := sftp.NewClientPipe(ch, halfCloser{ch})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Getwd(); err != nil {
		t.Fatal(err)
	}
	c.Close()

	timeout := time.After(10 * time.Second)
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				t.Fatal("channel closed without exit-status")
			}
			if req.Type != "exit-status" {
				continue
			}
			var st struct{ Status uint32 }
			if err := ssh.Unmarshal(req.Payload, &st); err != nil || st.Status != 0 {
				t.Fatalf("exit-status = %d, %v", st.Status, err)
			}
			return
		case <-timeout:
			t.Fatal("no exit-status")
		}
	}
}

// halfCloser closes only the client's write side, like OpenSSH does at the
// end of a session, so the server can still send exit-status.
type halfCloser struct{ ch ssh.Channel }

func (h halfCloser) Write(p []byte) (int, error) { return h.ch.Write(p) }
func (h halfCloser) Close() error                { return h.ch.CloseWrite() }

func TestHandleLimit(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	var files []*sftp.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for range 64 {
		f, err := c.Open("/a.txt")
		if err != nil {
			t.Fatalf("open %d: %v", len(files)+1, err)
		}
		files = append(files, f)
	}
	if f, err := c.Open("/a.txt"); err == nil {
		f.Close()
		t.Error("65th handle accepted")
	}
}

func TestSilentClientTimesOut(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	mounts, err := vfs.Open([]vfs.MountSpec{{Name: "s", Path: base, Options: vfs.DefaultMountOptions()}}, vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	defer mounts.Close()
	srv, err := New(Config{HostKeys: []ssh.Signer{signer(t)}, Auth: auth.New("", nil), Mounts: mounts, HandshakeTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { srv.ServeConn(server); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("silent client was not disconnected")
	}
}

// The audit log is fail-closed: once a write fails, modifications and new
// connections are refused.
func TestAuditFailClosed(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	e.auditLog.setFail(true)

	writeRemote(t, c, "/first.txt", "x") // its audit event is the first failed write
	if _, err := c.Create("/second.txt"); err == nil || !strings.Contains(err.Error(), "audit log unavailable") {
		t.Errorf("upload with a broken audit log: %v", err)
	}
	if conn, err := e.dial(t, e.userKey); err == nil {
		conn.Close()
		t.Error("new connection accepted with a broken audit log")
	}
	if got, err := readRemote(t, c, "/first.txt"); err != nil || got != "x" {
		t.Errorf("reads should keep working: %q, %v", got, err)
	}
}

// TestUsersAndPermissions runs the DoD M2 scenario with three users: reader
// (read), partner (upload) and alice (full, plus a personal home).
func TestUsersAndPermissions(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(share, "a.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	homeOpts := vfs.DefaultMountOptions()
	mounts, err := vfs.Open([]vfs.MountSpec{
		{Name: "share", Path: share, Options: vfs.DefaultMountOptions()},
		{Name: "home", Path: filepath.Join(base, "home", vfs.UserPlaceholder), Create: true, Options: homeOpts},
	}, vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mounts.Close() })

	keys := map[string]ssh.Signer{"reader": signer(t), "partner": signer(t), "alice": signer(t), "mallory": signer(t)}
	grants := map[string][]vfs.Grant{
		"reader":  {{Mount: "share", Perm: vfs.PermList | vfs.PermRead}},
		"partner": {{Mount: "share", Perm: vfs.PermList | vfs.PermWrite | vfs.PermMkdir}},
		"alice":   {{Mount: "share", Perm: vfs.PermAll}, {Mount: "home", Perm: vfs.PermAll}},
		"mallory": {{Mount: "home", Perm: vfs.PermAll}},
	}
	var users []auth.User
	for name, k := range keys {
		ks, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(k.PublicKey()), name)
		users = append(users, auth.User{Name: name, Keys: ks})
	}
	// Mallory's home was replaced with a symlink to Alice's.
	if err := os.MkdirAll(filepath.Join(base, "home", "alice"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("alice", filepath.Join(base, "home", "mallory")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	auditLog := &syncBuffer{}
	hk := signer(t)
	srv, err := New(Config{
		HostKeys: []ssh.Signer{hk},
		Auth:     auth.NewUsers(users),
		Mounts:   mounts,
		Grants:   func(u string) []vfs.Grant { return grants[u] },
		Audit:    audit.New(auditLog, slog.New(slog.DiscardHandler)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()
	// Cleanups run last-in first-out: clients close before the server stops.
	t.Cleanup(func() {
		cancel()
		<-served
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		if err := srv.Shutdown(sctx); err != nil {
			t.Errorf("Shutdown() = %v", err)
		}
	})

	connect := func(user string) *sftp.Client {
		t.Helper()
		conn, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(keys[user])},
			HostKeyCallback: ssh.FixedHostKey(hk.PublicKey()),
			Timeout:         10 * time.Second,
		})
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		c, err := sftp.NewClient(conn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(); conn.Close() })
		return c
	}

	// reader: one mount, flattened; can read, cannot write.
	r := connect("reader")
	if got, err := readRemote(t, r, "/a.txt"); err != nil || got != "original" {
		t.Errorf("reader read = %q, %v", got, err)
	}
	if _, err := r.Create("/new.txt"); statusCode(err) != 3 {
		t.Errorf("reader create: %v", err)
	}

	// partner: can upload, a conflict gets a new name, cannot read or delete.
	p := connect("partner")
	writeRemote(t, p, "/a.txt", "partner's")
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "original" {
		t.Errorf("original changed to %q", got)
	}
	if got := readFile(t, filepath.Join(share, "a (1).txt")); got != "partner's" {
		t.Errorf("copy = %q", got)
	}
	if _, err := readRemote(t, p, "/a.txt"); statusCode(err) != 3 {
		t.Errorf("partner read: %v", err)
	}
	if err := p.Remove("/a.txt"); statusCode(err) != 3 {
		t.Errorf("partner remove: %v", err)
	}

	// alice: two mounts under /, her own home.
	a := connect("alice")
	entries, err := a.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "home,share" {
		t.Errorf("alice sees %v", names)
	}
	writeRemote(t, a, "/home/notes.txt", "alice's notes")
	if got := readFile(t, filepath.Join(base, "home", "alice", "notes.txt")); got != "alice's notes" {
		t.Errorf("home file = %q", got)
	}

	// mallory: the replaced home is unavailable and audited.
	m := connect("mallory")
	if _, err := m.Stat("/notes.txt"); err == nil {
		t.Error("mallory reached alice's home")
	}
	if entries, err := m.ReadDir("/"); err != nil || len(entries) != 0 {
		t.Errorf("mallory root = %v, %v", entries, err)
	}
	waitFor(t, func() bool { return strings.Contains(auditLog.String(), `"reason":"home_not_dir"`) })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
