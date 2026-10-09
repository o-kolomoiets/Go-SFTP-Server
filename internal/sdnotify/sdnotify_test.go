// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sdnotify

import (
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram sockets unavailable: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func receive(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	c := listen(t, path)
	for _, state := range []string{"READY=1", "STOPPING=1"} {
		if err := send(path, state); err != nil {
			t.Fatal(err)
		}
		if got := receive(t, c); got != state {
			t.Errorf("received %q, want %q", got, state)
		}
	}
}

func TestReloading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	c := listen(t, path)
	t.Setenv("NOTIFY_SOCKET", path)
	if err := Reloading(); err != nil {
		t.Fatal(err)
	}
	got := receive(t, c)
	if !strings.HasPrefix(got, "RELOADING=1") {
		t.Fatalf("received %q", got)
	}
	if runtime.GOOS == "linux" && !strings.Contains(got, "\nMONOTONIC_USEC=") {
		t.Errorf("received %q, want MONOTONIC_USEC on Linux", got)
	}
}

func TestAbstractSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract sockets are Linux-only")
	}
	name := "@gosftpd-test-" + filepath.Base(t.TempDir())
	c := listen(t, name)
	if err := send(name, "READY=1"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, c); got != "READY=1" {
		t.Errorf("received %q", got)
	}
}

func TestWithoutSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Ready(); err != nil {
		t.Errorf("Ready without NOTIFY_SOCKET: %v", err)
	}
	if err := send("vsock:2:1234", "READY=1"); err == nil {
		t.Error("vsock address accepted")
	}
}
