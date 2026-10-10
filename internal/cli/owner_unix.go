// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"fmt"
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

// keyOwner returns what gives a new file next to the host key like the
// owner and group of like. It refuses a user other than like's owner and
// root: gosftpd could not read a key that user creates.
func keyOwner(like string) (func(string) error, error) {
	fi, err := os.Stat(like)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}
	euid := os.Geteuid()
	if euid != 0 && int64(euid) != int64(st.Uid) {
		return nil, fmt.Errorf("%s belongs to uid %d: run this as that user or as root, so that gosftpd can read the new key", like, st.Uid)
	}
	return func(path string) error {
		if euid == 0 {
			return os.Lchown(path, int(st.Uid), int(st.Gid))
		}
		_ = os.Lchown(path, -1, int(st.Gid)) // if this user is in that group
		return nil
	}, nil
}
