// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames atomically without replacing an existing target.
// Both parent directories are opened through the root, and the final
// components are single names, so the kernel never resolves a path outside it.
func renameNoReplace(root *os.Root, src, dst string) error {
	srcDir, err := root.Open(parentOf(src))
	if err != nil {
		return err
	}
	defer srcDir.Close()
	dstDir, err := root.Open(parentOf(dst))
	if err != nil {
		return err
	}
	defer dstDir.Close()

	err = unix.Renameat2(int(srcDir.Fd()), filepath.Base(src), int(dstDir.Fd()), filepath.Base(dst), unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST):
		return fs.ErrExist
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS):
		return errNoAtomicRename // filesystem or kernel without RENAME_NOREPLACE
	default:
		return &os.LinkError{Op: "renameat2", Old: src, New: dst, Err: err}
	}
}
