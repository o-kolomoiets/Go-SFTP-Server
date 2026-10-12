// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// notifySocket points NOTIFY_SOCKET at a socket of the test and returns a
// function that expects the next message received there to be want.
func notifySocket(t *testing.T) (next func(want string)) {
	t.Helper()
	// A short name: macOS allows 104 bytes for a socket path, and the
	// temporary directory's name holds the test's.
	sock := filepath.Join(t.TempDir(), "n")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram sockets unavailable: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	t.Setenv("NOTIFY_SOCKET", sock)
	msgs := make(chan string, 16)
	go func() {
		defer close(msgs)
		buf := make([]byte, 4096)
		for {
			n, _, err := conn.ReadFromUnix(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return func(want string) {
		t.Helper()
		select {
		case m := <-msgs:
			if m != want && !strings.HasPrefix(m, want+"\n") {
				t.Errorf("sd_notify got %q, want %q", m, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no sd_notify message %q", want)
		}
	}
}

// TestServeNotifiesSystemd: READY=1 once serving, RELOADING=1 with a
// timestamp and then READY=1 with a status for every reload, STOPPING=1
// and then the time the stop may take when stopping (Type=notify-reload).
func TestServeNotifiesSystemd(t *testing.T) {
	isolate(t)
	next := notifySocket(t)
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n")
	ts := startServe(t, "--dir", share, "--authorized-keys", keys, "--state-dir", filepath.Join(dir, "state"), "--listen", "127.0.0.1:0")
	next("READY=1")
	ts.reload(t, ts.stdout.String)
	next("RELOADING=1")
	next("READY=1\nSTATUS=configuration reloaded")
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit code %d", code)
	}
	next("STOPPING=1")
	next("EXTEND_TIMEOUT_USEC=40000000") // the default shutdown_timeout, 30 s, + 10 s
}

// TestServeNotifiesReloadResults: the status after a reload names the
// settings that need a restart, or says that the reload failed; at stop,
// gosftpd asks for the shutdown_timeout that the last good reload set,
// plus 10 s (ADR 0011).
func TestServeNotifiesReloadResults(t *testing.T) {
	isolate(t)
	next := notifySocket(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	config := func(listen, policy, shutdown string) string {
		return `config_version = 1
[server]
listen = ["` + listen + `"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
crypto_policy = "` + policy + `"
shutdown_timeout = "` + shutdown + `"
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(newSigner(t)) + `"]
access = { data = "full" }
`
	}
	writeFile(t, path, config("127.0.0.1:0", "modern", "5s"))
	ts := startServe(t, "--config", path)
	next("READY=1")

	// shutdown_timeout is reloadable; listen and crypto_policy are not.
	writeFile(t, path, config("127.0.0.1:1", "compat", "20s"))
	if ev := ts.reload(t, ts.stdout.String); ev["restart_required"] != "server.listen,server.crypto_policy" {
		t.Errorf("server.reload: %v", ev)
	}
	next("RELOADING=1")
	next("READY=1\nSTATUS=configuration reloaded; restart needed for: server.listen, server.crypto_policy")

	// A failed reload keeps the running shutdown_timeout.
	writeFile(t, path, config("127.0.0.1:0", "modern", "50s")+"bogus = = 1\n")
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "error" {
		t.Errorf("server.reload: %v", ev)
	}
	next("RELOADING=1")
	next("READY=1\nSTATUS=configuration reload failed, see the log")

	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit code %d", code)
	}
	next("STOPPING=1")
	next("EXTEND_TIMEOUT_USEC=30000000") // 20 s + 10 s
}
