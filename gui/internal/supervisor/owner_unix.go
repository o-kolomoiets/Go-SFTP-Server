// SPDX-License-Identifier: Apache-2.0

//go:build unix

package supervisor

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByUs reports whether fi, from Lstat, belongs to this process's user.
func ownedByUs(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
