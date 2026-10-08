// SPDX-License-Identifier: Apache-2.0

package vfs

// StatFS describes the filesystem of a mount (statvfs@openssh.com, "df").
type StatFS struct {
	BlockSize    uint64
	FragmentSize uint64
	Blocks       uint64 // in fragment-size units
	BlocksFree   uint64
	BlocksAvail  uint64 // free for unprivileged users
	Files        uint64
	FilesFree    uint64
	FilesAvail   uint64
	ID           uint64
	ReadOnly     bool
	NameMax      uint64
}

// StatFS reports the filesystem holding vp's mount. The synthetic root holds
// no data and reports an empty read-only filesystem. A mount the user cannot
// change is reported read-only.
func (s *Session) StatFS(vp string) (*StatFS, error) {
	v, _, err := s.resolve(vp)
	switch {
	case err != nil:
		return nil, err
	case v == nil:
		return &StatFS{BlockSize: 4096, FragmentSize: 4096, ReadOnly: true, NameMax: maxNameLen}, nil
	case !v.perm.Has(PermList):
		return nil, ErrDenied
	}
	d, err := v.root.Open(".")
	if err != nil {
		return nil, osError(err)
	}
	defer d.Close()
	st, err := statfs(d)
	if err != nil {
		return nil, osError(err)
	}
	if v.m.readOnly || v.perm&permModify == 0 {
		st.ReadOnly = true
	}
	return st, nil
}
