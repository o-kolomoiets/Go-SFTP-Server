// SPDX-License-Identifier: Apache-2.0

//go:build unix

package vfs

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// removeEntry removes a file (dir false) or an empty directory (dir true).
// The type is enforced by unlinkat itself: os.Root.Remove tries both, so a
// file swapped in for a directory between a check and the call would go.
func removeEntry(root *os.Root, rel string, dir bool) error {
	parent, err := root.Open(parentOf(rel))
	if err != nil {
		return err
	}
	defer parent.Close()
	flags := 0
	if dir {
		flags = unix.AT_REMOVEDIR
	}
	if err := unix.Unlinkat(int(parent.Fd()), filepath.Base(rel), flags); err != nil {
		return &os.PathError{Op: "unlinkat", Path: rel, Err: err}
	}
	return nil
}
