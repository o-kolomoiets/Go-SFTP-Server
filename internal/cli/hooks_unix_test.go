// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// TestServeExecHookReload: an exec hook gets a client's name as data; a
// reload reaches connections that stay open; a hook whose program cannot
// be trusted is left out; a secret that cannot be read keeps the running
// one.
func TestServeExecHookReload(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox")
	if err := os.Mkdir(inbox, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "runs")
	script := filepath.Join(dir, "hooks", "record.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$GOSFTPD_HOST_PATH\" >> "+out+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	secretFile := filepath.Join(dir, "hook.secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	rcv := newReceiver(t, secret)
	alice := newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	base := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.inbox]
path = "` + filepath.ToSlash(inbox) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { inbox = "full" }
[[hooks]]
name = "notify"
on = ["fs.upload"]
webhook = { url = "` + rcv.srv.URL + `", secret_file = "hook.secret" }
`
	execHook := `[[hooks]]
name = "record"
on = ["fs.upload"]
exec = { argv = ["/bin/sh", "` + script + `"], timeout = "10s" }
`
	writeFile(t, path, base+execHook)
	ts := startServe(t, "--config", path)
	stdout := ts.stdout.String
	runs := func() []string {
		b, _ := os.ReadFile(out)
		return strings.Fields(strings.ReplaceAll(string(b), " ", "_"))
	}
	waitRuns := func(n int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for len(runs()) < n && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		if got := runs(); len(got) != n {
			t.Fatalf("%d runs, want %d: %v\n%s", len(got), n, got, ts.stderr.String())
		}
	}

	conn, err := ts.login("alice", alice)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	name := "a b $(touch pwned).pdf"
	put(t, c, "/"+name, "x")
	waitRuns(1)
	if got, want := runs()[0], strings.ReplaceAll(filepath.Join(inbox, name), " ", "_"); got != want {
		t.Errorf("GOSFTPD_HOST_PATH = %s, want %s", got, want)
	}
	for _, d := range []string{dir, inbox, "/"} {
		if _, err := os.Stat(filepath.Join(d, "pwned")); err == nil {
			t.Fatal("a client's name ran as a command")
		}
	}
	rcv.wait(1)

	// Without the exec hook: the open connection no longer runs it.
	writeFile(t, path, base)
	if ev := ts.reload(t, stdout); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v", ev)
	}
	put(t, c, "/b.pdf", "x")
	rcv.wait(2)
	waitRuns(1)

	// A program others may write is left out; the reload succeeds.
	writeFile(t, path, base+execHook)
	if err := os.Chmod(script, 0o766); err != nil {
		t.Fatal(err)
	}
	if ev := ts.reload(t, stdout); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), `hook \"record\" is left out`) {
		t.Errorf("no warning for the left-out hook:\n%s", ts.stderr.String())
	}
	put(t, c, "/c.pdf", "x")
	rcv.wait(3)
	waitRuns(1)

	// Fixed: the hook runs again. A secret that cannot be used keeps the
	// running one: the receiver still verifies every delivery.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ev := ts.reload(t, stdout); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), `hook \"notify\" keeps its running secret`) {
		t.Errorf("no warning for the kept secret:\n%s", ts.stderr.String())
	}
	put(t, c, "/d.pdf", "x")
	rcv.wait(4)
	waitRuns(2)
}
