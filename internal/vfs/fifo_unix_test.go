// SPDX-License-Identifier: Apache-2.0

//go:build unix

package vfs

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFIFONotOpened(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictOverwrite)
	mkfifo(t, filepath.Join(base, "share", "p"))
	done := make(chan error, 1)
	go func() {
		f, err := s.OpenRead("p")
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("OpenRead(fifo) error = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	if _, err := s.OpenWrite("p", put); !errors.Is(err, ErrNotRegular) {
		t.Errorf("OpenWrite(fifo) error = %v, want ErrNotRegular", err)
	}
}
