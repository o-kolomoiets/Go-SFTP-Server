// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openHeld opens the directory of root as an O_PATH descriptor, through
// root itself (a variable for tests).
var openHeld = func(root *os.Root) (*os.File, error) {
	return root.OpenFile(".", unix.O_PATH|unix.O_DIRECTORY, 0)
}

// holdDir returns an O_PATH descriptor of the directory root holds, with
// its device and inode. Landlock gets the mount's rule through it, so a
// mount directory swapped for a symlink after it was opened cannot
// redirect the rule (ADR 0011). A descriptor that is not the directory of
// root.Stat(".") is an error, which fails the start.
func holdDir(root *os.Root) (*os.File, uint64, uint64, error) {
	f, err := openHeld(root)
	if err != nil {
		return nil, 0, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, 0, err
	}
	rfi, err := root.Stat(".")
	if err != nil {
		_ = f.Close()
		return nil, 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || !os.SameFile(fi, rfi) {
		_ = f.Close()
		return nil, 0, 0, fmt.Errorf("%s: the descriptor held for Landlock is not the directory the mount opened", root.Name())
	}
	return f, uint64(st.Dev), uint64(st.Ino), nil //nolint:unconvert // uint32 on some architectures
}
