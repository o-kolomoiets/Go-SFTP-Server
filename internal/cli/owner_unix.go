// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// chownLike gives path the owner and group of like, as far as this user
// may: root keeps files root-owned with the group of the configuration, so
// that a gosftpd group can read them.
func chownLike(path string, like fs.FileInfo) {
	st, ok := like.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid := -1
	if os.Geteuid() == 0 {
		uid = int(st.Uid)
	}
	_ = os.Lchown(path, uid, int(st.Gid))
}
