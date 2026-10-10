// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// reload switches e's server to its start configuration changed by change
// and returns how many connections the reload closed.
func (e *env) reload(t *testing.T, change func(*Config)) int {
	t.Helper()
	cfg := e.cfg
	change(&cfg)
	n, err := e.srv.Reload(cfg)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return n
}

func keysOf(t *testing.T, s ssh.Signer) []auth.Key {
	t.Helper()
	keys, warns := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(s.PublicKey()), "test")
	if len(warns) > 0 {
		t.Fatal(warns)
	}
	return keys
}

// New logins use the reloaded users; a logged-in connection keeps working
// until a reload with DisconnectRevoked closes it.
func TestReloadUsers(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	old := e.sftp(t)
	bob := signer(t)
	users := auth.NewUsers([]auth.User{{Name: "bob", Keys: keysOf(t, bob)}})
	if n := e.reload(t, func(c *Config) { c.Auth = users }); n != 0 {
		t.Errorf("a reload without DisconnectRevoked closed %d connections", n)
	}
	c, err := e.dialAs(t, "bob", bob)
	if err != nil {
		t.Fatalf("an added user cannot log in: %v", err)
	}
	c.Close()
	if c, err := e.dial(t, e.userKey); err == nil {
		c.Close()
		t.Error("a removed user logged in")
	}
	writeRemote(t, old, "after.txt", "still here")

	if n := e.reload(t, func(c *Config) { c.Auth = users; c.DisconnectRevoked = true }); n != 1 {
		t.Errorf("DisconnectRevoked closed %d connections, want 1", n)
	}
	waitFor(t, func() bool { _, err := old.Getwd(); return err != nil })
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"result":"revoked"`) },
		func() string { return "no conn.close with result revoked:\n" + e.auditLog.String() })
	checkSchema(t, auditLines(t, e.auditLog.String()))
}

// slowSigner waits before signing, like a client asking for a passphrase
// or a security key touch after its key was accepted.
type slowSigner struct {
	ssh.Signer
	once    sync.Once
	signing chan struct{} // closed when Sign is called
	release chan struct{}
}

func (s *slowSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s.once.Do(func() { close(s.signing) })
	<-s.release
	return s.Signer.Sign(rand, data)
}

// x/crypto remembers that a key was accepted when the client asked, and
// does not ask PublicKeyCallback again for the signed request: a key
// removed by a reload in between is refused by VerifiedPublicKeyCallback,
// which checks the current configuration (and, behind it, by the recheck
// after the handshake).
func TestReloadRevokesLoginInFlight(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	slow := &slowSigner{Signer: e.userKey, signing: make(chan struct{}), release: make(chan struct{})}
	type result struct {
		c   *ssh.Client
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
			User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(slow)},
			HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
		})
		done <- result{c, err}
	}()
	<-slow.signing
	e.reload(t, func(c *Config) { c.Auth = auth.New("", nil) })
	close(slow.release)
	if r := <-done; r.err == nil {
		if s, err := r.c.NewSession(); err == nil {
			s.Close()
			t.Error("a session opened with a revoked key")
		}
		r.c.Close()
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"reason":"removed"`) },
		func() string { return "the login was not refused with reason removed:\n" + e.auditLog.String() })
	if strings.Contains(e.auditLog.String(), `"event":"auth.success"`) {
		t.Errorf("a revoked login was audited as a success:\n%s", e.auditLog.String())
	}
}

// New logins get the reloaded mounts; a logged-in connection keeps the
// mounts it had, also for sessions it opens after the reload.
func TestReloadMounts(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The server pins a connection's configuration after the handshake,
	// a moment after the client returns: a session that works is proof.
	if got, err := readRemote(t, newSFTP(t, conn), "a.txt"); err != nil || got != "original content" {
		t.Fatalf("before the reload: %q, %v", got, err)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "b.txt"), []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	t2, warns, err := e.cfg.Mounts.Reload([]vfs.MountSpec{{Name: "share", Path: other, Options: vfs.DefaultMountOptions()}}, vfs.Options{Flatten: true})
	if err != nil || len(warns) > 0 {
		t.Fatal(err, warns)
	}
	t.Cleanup(func() { t2.Close() })
	e.reload(t, func(c *Config) { c.Mounts = t2 })

	if got, err := readRemote(t, e.sftp(t), "b.txt"); err != nil || got != "other" {
		t.Errorf("new login reads %q, %v", got, err)
	}
	old := newSFTP(t, conn) // a session opened after the reload
	if got, err := readRemote(t, old, "a.txt"); err != nil || got != "original content" {
		t.Errorf("old connection reads %q, %v", got, err)
	}
	if _, err := readRemote(t, old, "b.txt"); err == nil {
		t.Error("old connection sees the new mount")
	}
}

// Bans carry over a reload that keeps them on, with the new options; off
// drops them.
func TestReloadBans(t *testing.T) {
	t.Parallel()

	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 1, Duration: time.Hour})
	}})
	if c, err := e.dial(t, signer(t)); err == nil {
		c.Close()
		t.Fatal("wrong key accepted")
	}
	banned := func() bool {
		c, err := e.dial(t, e.userKey)
		if err == nil {
			c.Close()
		}
		return err != nil
	}
	waitFor(t, banned)
	e.reload(t, func(c *Config) { c.Bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 5}) })
	if !banned() {
		t.Error("a reload lifted a ban")
	}
	if got := e.srv.snap.Load().bans.Options().AfterFailures; got != 5 {
		t.Errorf("after_failures = %d after reload, want 5", got)
	}
	e.reload(t, func(c *Config) { c.Bans = nil })
	if banned() {
		t.Error("still banned with bans off")
	}
}

func newSFTP(t *testing.T, conn *ssh.Client) *sftp.Client {
	t.Helper()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
