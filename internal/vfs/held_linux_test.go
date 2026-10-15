// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// checkHeld: the descriptor is an O_PATH descriptor of dir, with dir's
// device and inode.
func checkHeld(t *testing.T, h HeldDir, dir string) {
	t.Helper()
	var st, want syscall.Stat_t
	if err := syscall.Fstat(h.FD, &st); err != nil {
		t.Fatalf("%s: fstat: %v", h.Mount, err)
	}
	if err := syscall.Stat(dir, &want); err != nil {
		t.Fatal(err)
	}
	if st.Dev != want.Dev || st.Ino != want.Ino || h.Dev != uint64(want.Dev) || h.Ino != uint64(want.Ino) { //nolint:unconvert // uint32 on some architectures
		t.Errorf("%s: %+v is not %s", h.Mount, h, dir)
	}
	flags, err := unix.FcntlInt(uintptr(h.FD), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 {
		t.Errorf("%s: flags %#x, %v: not O_PATH", h.Mount, flags, err)
	}
}

// TestHeldDirMismatch: a descriptor that is not the directory the mount
// opened fails the open. Not parallel: it replaces openHeld.
func TestHeldDirMismatch(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{"data", "other"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	orig := openHeld
	defer func() { openHeld = orig }()
	openHeld = func(*os.Root) (*os.File, error) {
		return os.OpenFile(filepath.Join(base, "other"), unix.O_PATH|unix.O_DIRECTORY, 0)
	}
	_, err := Open([]MountSpec{spec("data", filepath.Join(base, "data"), ConflictRename)}, Options{})
	if err == nil || !strings.Contains(err.Error(), "the descriptor held for Landlock is not the directory the mount opened") {
		t.Errorf("Open = %v", err)
	}
}
