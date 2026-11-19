// SPDX-License-Identifier: Apache-2.0

//go:build unix

package supervisor

import (
	"errors"
	"os"
	"testing"
)

func TestLock(t *testing.T) {
	dir := t.TempDir()
	l, err := AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(dir); !errors.Is(err, ErrRunning) {
		t.Errorf("second lock: %v, want ErrRunning", err)
	}
	layout := Layout{Dir: t.TempDir()}
	// The pid of a process that is not gosftpd serve of this layout,
	// such as this test, counts as none.
	if err := l.SetServer(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if pid, err := l.PreviousServer(layout); err != nil || pid != 0 {
		t.Errorf("PreviousServer = %d, %v", pid, err)
	}
	if err := l.SetServer(1 << 30); err != nil { // no such process
		t.Fatal(err)
	}
	if pid, _ := l.PreviousServer(layout); pid != 0 {
		t.Errorf("a pid that does not run: %d", pid)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("after Release: %v", err)
	}
	_ = l2.Release()
}

func TestIsServeOf(t *testing.T) {
	cfg := "/home/a/.config/gosftpd-gui/config.toml"
	for _, tt := range []struct {
		cmdline []string
		want    bool
	}{
		{[]string{"/usr/libexec/gosftpd-gui/gosftpd", "serve", "--config", cfg, "--print-details"}, true},
		{[]string{"gosftpd", "serve", "--config=" + cfg}, true},
		{[]string{"gosftpd", "serve", "--config", "/etc/gosftpd/config.toml"}, false},
		{[]string{"gosftpd", "user", "list", "--config", cfg}, false},
		{[]string{"/usr/bin/vim", "serve", "--config", cfg}, false},
		{[]string{"gosftpd"}, false},
	} {
		if got := isServeOf(tt.cmdline, cfg); got != tt.want {
			t.Errorf("%q: %v", tt.cmdline, got)
		}
	}
}
