// SPDX-License-Identifier: Apache-2.0

//go:build darwin || freebsd || netbsd

package vfs

import (
	"io/fs"
	"syscall"
)

// ctime returns the inode change time in nanoseconds, 0 if unknown.
func ctime(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ctimespec.Nano()
	}
	return 0
}
