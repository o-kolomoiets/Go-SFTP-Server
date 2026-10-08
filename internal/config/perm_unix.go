// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkOwner applies sshd's StrictModes rule (ROADMAP §6.5): the file must
// not be writable by group or others, and must belong to root or to the
// user running gosftpd.
func checkOwner(path string, fi fs.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others (mode %04o); fix with: chmod go-w %s", path, perm, path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Getuid(); st.Uid != 0 && int(st.Uid) != uid {
		return fmt.Errorf("%s: owned by uid %d; it must belong to root or to the user running gosftpd (uid %d)", path, st.Uid, uid)
	}
	return nil
}

// worldReadable reports whether others may read the file.
func worldReadable(fi fs.FileInfo) bool { return fi.Mode().Perm()&0o004 != 0 }

// sameDevice reports whether a and b are on the same filesystem.
func sameDevice(a, b fs.FileInfo) (same, known bool) {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return false, false
	}
	return sa.Dev == sb.Dev, true
}
