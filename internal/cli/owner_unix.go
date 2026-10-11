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

// sameOwner refuses a file f that does not belong to the owner of like (or,
// with rootOK, to root): gosftpd, which reads like, may not be able to read
// f, or may not trust it.
func sameOwner(f, like string, rootOK bool) error {
	fi, ferr := os.Stat(f)
	li, err := os.Stat(like)
	if ferr != nil || err != nil {
		return nil //nolint:nilerr // a missing file is reported by the step itself
	}
	st, ok1 := fi.Sys().(*syscall.Stat_t)
	lt, ok2 := li.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || st.Uid == lt.Uid || rootOK && st.Uid == 0 {
		return nil
	}
	return fmt.Errorf("%s belongs to uid %d, %s to uid %d: give it the owner of %s (chown --reference=%s %s)", f, st.Uid, like, lt.Uid, like, like, f)
}

// chownKeyLike gives the key file f, as root, the owner and group of like.
// It changes only a regular file with no other hard link, through the
// opened file, so that a link planted at f cannot hand over another file.
func chownKeyLike(f, like string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	li, err := os.Stat(like)
	if err != nil {
		return err
	}
	lt, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	file, err := os.OpenFile(f, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", f)
	case !ok:
		return nil
	case st.Uid == lt.Uid && st.Gid == lt.Gid:
		return nil
	case st.Nlink != 1:
		return fmt.Errorf("%s has other hard links: copy the key there instead", f)
	}
	return file.Chown(int(lt.Uid), int(lt.Gid))
}
