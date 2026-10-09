// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/pkg/sftp"
)

// testServer is gosftpd serve running in the test, with reloads triggered
// through a channel instead of SIGHUP.
type testServer struct {
	addr           string
	stdout, stderr *lockedBuffer
	hup            chan os.Signal
	cancel         context.CancelFunc
	done           chan int
}

func startServe(t *testing.T, args ...string) *testServer {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	hup := make(chan os.Signal, 1)
	ctx = context.WithValue(ctx, hupKey{}, (<-chan os.Signal)(hup))
	ts := &testServer{stdout: &lockedBuffer{}, stderr: &lockedBuffer{}, hup: hup, cancel: cancel, done: make(chan int, 1)}
	go func() { ts.done <- run(ctx, append([]string{"serve", "--allow-root"}, args...), ts.stdout, ts.stderr) }()
	t.Cleanup(func() { ts.stop(t) })

	addrRE := regexp.MustCompile(`listen:\s+(127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(10 * time.Second)
	for ts.addr == "" {
		if m := addrRE.FindStringSubmatch(ts.stderr.String()); m != nil {
			ts.addr = m[1]
		}
		select {
		case code := <-ts.done:
			t.Fatalf("serve exited with %d:\n%s", code, ts.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no listen address in:\n%s", ts.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ts
}

// stop shuts the server down once and returns its exit code.
func (ts *testServer) stop(t *testing.T) int {
	t.Helper()
	if ts.cancel == nil {
		return exitOK
	}
	ts.cancel()
	ts.cancel = nil
	return <-ts.done
}

// events returns the audit events called name from the audit output out.
func events(t *testing.T, out, name string) []map[string]any {
	t.Helper()
	var evs []map[string]any
	for l := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(l, `"event":"`+name+`"`) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		evs = append(evs, m)
	}
	return evs
}

// reload triggers a reload and returns its server.reload event, read from
// the audit output that audit returns.
func (ts *testServer) reload(t *testing.T, audit func() string) map[string]any {
	t.Helper()
	n := len(events(t, audit(), "server.reload"))
	ts.hup <- syscall.SIGHUP
	deadline := time.Now().Add(10 * time.Second)
	for {
		if evs := events(t, audit(), "server.reload"); len(evs) > n {
			return evs[len(evs)-1]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no server.reload event; log:\n%s", ts.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (ts *testServer) login(user string, key ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", ts.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

// TestServeReload: reloads add and remove users, keep restart-only
// settings, refuse an invalid file, and switch the audit output.
func TestServeReload(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	alice, bob := newSigner(t), newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	base := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
`
	bobUser := `[users.bob]
authorized_keys = ["` + authorizedKey(bob) + `"]
access = { data = "read" }
`
	writeFile(t, path, base)
	ts := startServe(t, "--config", path)
	stdout := ts.stdout.String

	if c, err := ts.login("bob", bob); err == nil {
		c.Close()
		t.Fatal("bob logged in before he was added")
	}
	held, err := ts.login("alice", alice)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	// Add bob; change a restart-only key.
	writeFile(t, path, strings.Replace(base, `"127.0.0.1:0"`, `"127.0.0.1:1"`, 1)+bobUser)
	ev := ts.reload(t, stdout)
	if ev["result"] != "ok" || ev["restart_required"] != "server.listen" {
		t.Errorf("server.reload = %v", ev)
	}
	c, err := ts.login("bob", bob)
	if err != nil {
		t.Fatalf("an added user cannot log in: %v\n%s", err, ts.stderr.String())
	}
	c.Close()

	// An invalid file keeps the running configuration.
	writeFile(t, path, base+bobUser+"[server\n")
	if ev := ts.reload(t, stdout); ev["result"] != "error" || ev["reason"] != "config" {
		t.Errorf("server.reload of an invalid file = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), "configuration reload failed") {
		t.Errorf("the failed reload is not logged:\n%s", ts.stderr.String())
	}
	if c, err := ts.login("bob", bob); err != nil {
		t.Errorf("the running configuration changed after a failed reload: %v", err)
	} else {
		c.Close()
	}

	// Remove alice and close her connection; write the audit log to a file.
	auditFile := filepath.Join(dir, "audit.jsonl")
	withoutAlice := strings.Replace(base, "[users.alice]", "[users.carol]", 1) + bobUser +
		"[reload]\ndisconnect_removed_users = true\n[audit]\noutput = \"audit.jsonl\"\n"
	writeFile(t, path, withoutAlice)
	readAudit := func() string { b, _ := os.ReadFile(auditFile); return string(b) }
	ev = ts.reload(t, readAudit)
	if ev["result"] != "ok" || ev["disconnected"] != float64(1) {
		t.Errorf("server.reload = %v", ev)
	}
	if _, err := sftp.NewClient(held); err == nil {
		t.Error("the connection of a removed user stayed open")
	}
	if c, err := ts.login("alice", alice); err == nil {
		c.Close()
		t.Error("a removed user logged in")
	}
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit code %d", code)
	}
	if len(events(t, readAudit(), "server.stop")) != 1 {
		t.Errorf("server.stop is not in the new audit file:\n%s", readAudit())
	}
	if len(events(t, stdout(), "server.reload")) != 2 {
		t.Errorf("stdout should have the first two reloads:\n%s", stdout())
	}
}

// TestServeReloadZeroConfig: a reload reads --authorized-keys again, so
// removing a key from it revokes the key.
func TestServeReloadZeroConfig(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	alice, bob := newSigner(t), newSigner(t)
	keys := filepath.Join(dir, "keys")
	writeFile(t, keys, authorizedKey(alice)+"\n"+authorizedKey(bob)+"\n")
	ts := startServe(t, "--dir", share, "--authorized-keys", keys, "--state-dir", filepath.Join(dir, "state"), "--listen", "127.0.0.1:0")
	c, err := ts.login("anyone", bob)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	writeFile(t, keys, authorizedKey(alice)+"\n")
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Errorf("server.reload = %v", ev)
	}
	if c, err := ts.login("anyone", bob); err == nil {
		c.Close()
		t.Error("a removed key still logs in")
	}
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Errorf("server.reload without the key file = %v", ev)
	}
	if c, err := ts.login("anyone", alice); err == nil {
		c.Close()
		t.Error("a key of a deleted authorized_keys file still logs in")
	}
}
