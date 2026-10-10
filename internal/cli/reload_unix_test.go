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

// TestServeNotifiesSystemd: READY=1 once serving, RELOADING=1 with a
// timestamp and then READY=1 with a status for every reload, STOPPING=1
// when stopping (Type=notify-reload).
func TestServeNotifiesSystemd(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram sockets unavailable: %v", err)
	}
	defer conn.Close()
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
	next := func(want string) {
		t.Helper()
		select {
		case m := <-msgs:
			if !strings.HasPrefix(m, want) {
				t.Errorf("sd_notify got %q, want %q...", m, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no sd_notify message %q", want)
		}
	}

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
}
