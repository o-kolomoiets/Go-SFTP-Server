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
	frsize := nonNegative(st.Frsize)
	if frsize == 0 {
		frsize = nonNegative(st.Bsize)
	}
	return &StatFS{
		BlockSize:    nonNegative(st.Bsize),
		FragmentSize: frsize,
		Blocks:       st.Blocks,
		BlocksFree:   st.Bfree,
		BlocksAvail:  st.Bavail,
		Files:        st.Files,
		FilesFree:    st.Ffree,
		FilesAvail:   st.Ffree,
		ID:           fsid(st.Fsid.Val),
		ReadOnly:     st.Flags&unix.ST_RDONLY != 0,
		NameMax:      nonNegative(st.Namelen),
	}, nil
}
