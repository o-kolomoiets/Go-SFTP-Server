// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"sync"
	"time"
)

// errNoAtomicRename means the platform cannot rename without replacing.
var errNoAtomicRename = errors.New("atomic no-replace rename unavailable")

// Session is one client's view of the table. It is safe for concurrent use.
type Session struct {
	t    *Table
	user string

	mu      sync.Mutex
	writers map[string][]*WriteHandle // open uploads by final virtual path
}

// Session starts a client session.
func (t *Table) Session(user string) *Session {
	return &Session{t: t, user: user, writers: make(map[string][]*WriteHandle)}
}

// User returns the session's user name.
func (s *Session) User() string { return s.user }

// RealPath canonicalizes a client path without touching the filesystem.
func (s *Session) RealPath(vp string) string { return path.Clean("/" + vp) }

// Stat follows symlinks that stay inside the mount.
func (s *Session) Stat(vp string) (fs.FileInfo, error) { return s.stat(vp, false) }

// Lstat does not follow a final symlink.
func (s *Session) Lstat(vp string) (fs.FileInfo, error) { return s.stat(vp, true) }

func (s *Session) stat(vp string, lstat bool) (fs.FileInfo, error) {
	m, rel, err := s.t.resolve(vp)
	switch {
	case err != nil:
		return nil, err
	case m == nil:
		return s.t.rootInfo(), nil
	case rel == ".":
		return s.t.mountInfo(m)
	}
	var fi fs.FileInfo
	if lstat {
		fi, err = m.root.Lstat(rel)
	} else {
		fi, err = m.root.Stat(rel)
	}
	return fi, osError(err)
}

// ReadDir lists a directory. The caller must Close the Lister.
func (s *Session) ReadDir(vp string) (Lister, error) {
	m, rel, err := s.t.resolve(vp)
	if err != nil {
		return nil, err
	}
	if m == nil {
		infos := make([]fs.FileInfo, 0, len(s.t.mounts))
		for _, m := range s.t.mounts {
			fi, err := s.t.mountInfo(m)
			if err != nil {
				continue
			}
			infos = append(infos, fi)
		}
		return sliceLister(infos), nil
	}
	f, err := m.root.Open(rel)
	if err != nil {
		return nil, osError(err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, osError(err)
	}
	if !fi.IsDir() {
		_ = f.Close()
		return nil, ErrNotDir
	}
	return &dirLister{f: f}, nil
}

// OpenRead opens a regular file for reading.
func (s *Session) OpenRead(vp string) (*os.File, error) {
	m, rel, err := s.t.resolve(vp)
	if err != nil {
		return nil, err
	}
	if m == nil || rel == "." {
		return nil, ErrIsDir
	}
	f, err := m.root.OpenFile(rel, os.O_RDONLY|oNonblock, 0)
	if err != nil {
		return nil, osError(err)
	}
	if err := requireRegular(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func requireRegular(f *os.File) error {
	fi, err := f.Stat()
	switch {
	case err != nil:
		return osError(err)
	case fi.IsDir():
		return ErrIsDir
	case !fi.Mode().IsRegular():
		return ErrNotRegular
	}
	return nil
}

// writable resolves vp for a modification of an entry inside a mount.
func (s *Session) writable(vp string) (*Mount, string, error) {
	m, rel, err := s.t.resolve(vp)
	switch {
	case errors.Is(err, fs.ErrNotExist) && s.t.topLevel(vp):
		return nil, "", ErrDenied // creating entries in the virtual root
	case err != nil:
		return nil, "", err
	case m == nil, rel == ".", m.readOnly:
		return nil, "", ErrDenied
	}
	return m, rel, nil
}

// Mkdir creates a directory.
func (s *Session) Mkdir(vp string) error {
	m, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	return osError(m.root.Mkdir(rel, dirPerm))
}

// Remove deletes a file (not a directory).
func (s *Session) Remove(vp string) error {
	m, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	fi, err := m.root.Lstat(rel)
	if err != nil {
		return osError(err)
	}
	if fi.IsDir() {
		return ErrIsDir
	}
	return osError(m.root.Remove(rel))
}

// Rmdir deletes an empty directory.
func (s *Session) Rmdir(vp string) error {
	m, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	fi, err := m.root.Lstat(rel)
	if err != nil {
		return osError(err)
	}
	if !fi.IsDir() {
		return ErrNotDir
	}
	return osError(m.root.Remove(rel))
}

// Attrs are the attributes a client may set.
type Attrs struct {
	Size         int64
	HasSize      bool
	Atime, Mtime time.Time
	HasTimes     bool
}

// Setstat applies attributes. Permissions and ownership are not settable and
// are ignored. A size change is allowed only on a file this session has open
// for writing (OpenSSH scp truncates that way), never on arbitrary files.
func (s *Session) Setstat(vp string, a Attrs) error {
	m, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	if a.HasSize {
		h := s.openWriter(s.t.virtual(m, rel))
		if h == nil || a.Size < 0 {
			return ErrDenied
		}
		if err := h.truncate(a.Size); err != nil {
			return err
		}
	}
	if a.HasTimes {
		return osError(m.root.Chtimes(rel, a.Atime, a.Mtime))
	}
	return nil
}

// Rename moves src to dst. With posix set (posix-rename@openssh.com) an
// existing target is handled by the conflict policy; otherwise (SFTP v3
// RENAME) an existing target is an error. It returns the final client path.
func (s *Session) Rename(src, dst string, posix bool) (string, error) {
	sm, srel, err := s.writable(src)
	if err != nil {
		return "", err
	}
	dm, drel, err := s.writable(dst)
	if err != nil {
		return "", err
	}
	if sm != dm {
		return "", ErrUnsupported // across mounts
	}
	if _, err := sm.root.Lstat(srel); err != nil {
		return "", osError(err)
	}

	err = noClobberRename(sm.root, srel, drel)
	switch {
	case err == nil:
		return s.t.virtual(sm, drel), nil
	case !errors.Is(err, fs.ErrExist):
		return "", osError(err)
	case !posix:
		return "", ErrExists
	}

	switch s.t.policy {
	case ConflictOverwrite:
		if err := sm.root.Rename(srel, drel); err != nil {
			return "", osError(err)
		}
		return s.t.virtual(sm, drel), nil
	case ConflictReject:
		return "", ErrConflict
	case ConflictRename: // move the source next to the target under a free name
		final, err := freeName(drel, func(cand string) error { return noClobberRename(sm.root, srel, cand) })
		if err != nil {
			return "", err
		}
		return s.t.virtual(sm, final), nil
	}
	return "", fmt.Errorf("unknown conflict policy %q", s.t.policy)
}

// noClobberRename renames src to dst and fails with fs.ErrExist if dst exists.
func noClobberRename(root *os.Root, src, dst string) error {
	err := renameNoReplace(root, src, dst)
	if !errors.Is(err, errNoAtomicRename) {
		return err
	}
	return fallbackRename(root, src, dst)
}

// fallbackRename is noClobberRename where the platform has no atomic
// no-replace rename.
func fallbackRename(root *os.Root, src, dst string) error {
	fi, err := root.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() {
		// A hard link fails if dst exists, without a check-then-act race.
		err := root.Link(src, dst)
		if err == nil {
			return root.Remove(src)
		}
		if errors.Is(err, fs.ErrExist) {
			return fs.ErrExist
		}
		// Hard links unsupported here: fall back below.
	}
	// Last resort with a small race window between the check and the rename.
	if _, err := root.Lstat(dst); err == nil {
		return fs.ErrExist
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return root.Rename(src, dst)
}

// Symlink and Link are refused: client-created links could break confinement.
func (s *Session) Symlink(string, string) error { return ErrUnsupported }

// Link is refused, see Symlink.
func (s *Session) Link(string, string) error { return ErrUnsupported }

func (s *Session) register(h *WriteHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writers[h.virtual] = append(s.writers[h.virtual], h)
}

func (s *Session) unregister(h *WriteHandle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hs := slices.DeleteFunc(s.writers[h.virtual], func(x *WriteHandle) bool { return x == h })
	if len(hs) == 0 {
		delete(s.writers, h.virtual)
	} else {
		s.writers[h.virtual] = hs
	}
}

func (s *Session) openWriter(vp string) *WriteHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hs := s.writers[vp]; len(hs) > 0 {
		return hs[len(hs)-1]
	}
	return nil
}
