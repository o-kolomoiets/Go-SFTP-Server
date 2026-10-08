// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// StatFSSupported reports whether StatFS works on this platform.
const StatFSSupported = true

func statfs(d *os.File) (*StatFS, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(d.Fd()), &st); err != nil {
		return nil, &os.PathError{Op: "fstatfs", Path: ".", Err: err}
	}
	return &StatFS{
		BlockSize:    st.Bsize,
		FragmentSize: st.Bsize,
		Blocks:       st.Blocks,
		BlocksFree:   st.Bfree,
		BlocksAvail:  nonNegative(st.Bavail), // negative when the reserve is in use
		Files:        st.Files,
		FilesFree:    nonNegative(st.Ffree),
		FilesAvail:   nonNegative(st.Ffree),
		ID:           fsid(st.Fsid.Val),
		ReadOnly:     st.Flags&unix.MNT_RDONLY != 0,
		NameMax:      uint64(st.Namemax),
	}, nil
}
