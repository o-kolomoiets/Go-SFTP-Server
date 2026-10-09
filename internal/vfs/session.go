// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// errNoAtomicRename means the platform cannot rename without replacing.
var errNoAtomicRename = errors.New("atomic no-replace rename unavailable")

// Grant gives a user permissions on a mount.
type Grant struct {
	Mount string
	Perm  Perm
}

// view is one mount as a session sees it.
type view struct {
	m    *Mount
	root *os.Root // m.root, or the user's directory for a home mount
	perm Perm
}

func (v *view) opts() *MountOptions { return &v.m.opts }

// fileID identifies a file across paths. The inode number alone is not
// enough: once a file is deleted, a new file may get the same number. The
// change time tells them apart; it moves with every change, so the session
// refreshes it after its own changes.
type fileID struct {
	fi    fs.FileInfo // for os.SameFile: device and inode, or NTFS file ID
	ctime int64
}

func identify(fi fs.FileInfo) fileID { return fileID{fi: fi, ctime: ctime(fi)} }

func (id fileID) matches(fi fs.FileInfo) bool {
	return os.SameFile(id.fi, fi) && id.ctime == ctime(fi)
}

// Session is one client's view of the table. It is safe for concurrent use.
type Session struct {
	t       *Table
	user    string
	views   []*view // sorted by mount name
	byName  map[string]*view
	flatten bool
	owned   []*os.Root // home roots, closed with the session

	mu      sync.Mutex
	writers map[string][]*WriteHandle // open uploads by final virtual path
}

// Session starts a session for user with the given grants; the caller must
// hold a reference to t (Acquire) until the session is closed. Mounts that
// cannot be opened for this user (a home directory that is missing or not a
// real directory) are left out; the returned errors say why, for the audit
// log. Grants for unknown mounts are reported the same way.
func (t *Table) Session(user string, grants []Grant) (*Session, []error) {
	s := &Session{
		t:       t,
		user:    user,
		byName:  make(map[string]*view, len(grants)),
		writers: make(map[string][]*WriteHandle),
	}
	var errs []error
	granted := map[string]bool{}
	for _, g := range grants {
		m := t.byName[g.Mount]
		if err, ok := t.missing[g.Mount]; ok {
			// Granted, so that the user's other mounts keep their paths.
			if !granted[g.Mount] {
				granted[g.Mount] = true
				errs = append(errs, &MountError{Mount: g.Mount, Err: err})
			}
			continue
		}
		if m == nil {
			errs = append(errs, &MountError{Mount: g.Mount, Err: fs.ErrNotExist})
			continue
		}
		if granted[m.name] {
			continue
		}
		granted[m.name] = true
		perm := g.Perm
		if m.readOnly {
			perm &= PermReadOnly
		}
		root := m.root
		if m.home {
			r, err := m.openHome(user)
			if err != nil {
				errs = append(errs, &MountError{Mount: m.name, Err: err})
				continue
			}
			root = r
			s.owned = append(s.owned, r)
		}
		v := &view{m: m, root: root, perm: perm}
		s.views = append(s.views, v)
		s.byName[m.name] = v
	}
	slices.SortFunc(s.views, func(a, b *view) int { return strings.Compare(a.m.name, b.m.name) })
	// Flatten by what was granted, not by what opened: if a granted home is
	// unavailable, /home/x must not resolve into the other mount.
	s.flatten = t.flatten && len(granted) == 1 && len(s.views) == 1
	return s, errs
}

// FullAccess grants every mount of t with all permissions (zero-config mode;
// read-only mounts still allow only list and read).
func (t *Table) FullAccess() []Grant {
	gs := make([]Grant, 0, len(t.mounts)+len(t.missing))
	for _, m := range t.mounts {
		gs = append(gs, Grant{Mount: m.name, Perm: PermAll})
	}
	for _, name := range slices.Sorted(maps.Keys(t.missing)) {
		gs = append(gs, Grant{Mount: name, Perm: PermAll})
	}
	return gs
}

// MountError explains why a mount is not available in a session.
type MountError struct {
	Mount string
	Err   error
}

func (e *MountError) Error() string { return fmt.Sprintf("mount %q: %v", e.Mount, e.Err) }
func (e *MountError) Unwrap() error { return e.Err }

// Close releases the session's home directories. Open handles must be
// closed first.
func (s *Session) Close() error {
	s.mu.Lock()
	owned := s.owned
	s.owned = nil
	s.mu.Unlock()
	errs := make([]error, 0, len(owned))
	for _, r := range owned {
		errs = append(errs, r.Close())
	}
	return errors.Join(errs...)
}

// User returns the session's user name.
func (s *Session) User() string { return s.user }

// Mounts returns the names of the mounts this session can see.
func (s *Session) Mounts() []string {
	names := make([]string, len(s.views))
	for i, v := range s.views {
		names[i] = v.m.name
	}
	return names
}

// RealPath canonicalizes a client path without touching the filesystem.
func (s *Session) RealPath(vp string) string { return path.Clean("/" + vp) }

// resolve maps a client path to a view and a path relative to its root.
// v == nil means the synthetic root "/" (only when not flattened); rel == "."
// means the mount root itself.
func (s *Session) resolve(vp string) (v *view, rel string, err error) {
	if len(vp) > maxPathLen || strings.IndexByte(vp, 0) >= 0 || !utf8.ValidString(vp) {
		return nil, "", ErrInvalidPath
	}
	p := path.Clean("/" + vp)

	var rest string
	switch {
	case s.flatten:
		v, rest = s.views[0], p[1:]
	case p == "/":
		return nil, "", nil
	default:
		var name string
		name, rest, _ = strings.Cut(p[1:], "/")
		if v = s.byName[name]; v == nil {
			return nil, "", fs.ErrNotExist
		}
	}
	if rest == "" {
		return v, ".", nil
	}
	if strings.Count(rest, "/") >= maxDepth || !fs.ValidPath(rest) {
		return nil, "", ErrInvalidPath
	}
	if runtime.GOOS == "windows" {
		for c := range strings.SplitSeq(rest, "/") {
			if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
				return nil, "", ErrInvalidPath
			}
		}
	}
	local, err := filepath.Localize(rest)
	if err != nil {
		return nil, "", ErrInvalidPath
	}
	if reservedPath(local) {
		return nil, "", ErrDenied // temporary upload files
	}
	if v.opts().Symlinks == SymlinksDeny {
		if err := noSymlinks(v.root, local); err != nil {
			return nil, "", err
		}
	}
	return v, local, nil
}

// noSymlinks refuses a path if any existing component is a symlink
// (symlinks = "deny"). Clients cannot create links, so only links made on
// the host are affected.
func noSymlinks(root *os.Root, rel string) error {
	p := ""
	for c := range strings.SplitSeq(rel, string(filepath.Separator)) {
		p = filepath.Join(p, c)
		fi, err := root.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil // the rest does not exist yet
		case err != nil:
			return osError(err)
		case fi.Mode()&fs.ModeSymlink != 0:
			return ErrDenied
		}
	}
	return nil
}

// topLevel reports whether vp names an entry directly in the synthetic root.
func (s *Session) topLevel(vp string) bool {
	return !s.flatten && path.Dir(path.Clean("/"+vp)) == "/"
}

// virtual returns the canonical client path of rel inside v.
func (s *Session) virtual(v *view, rel string) string {
	rel = filepath.ToSlash(rel)
	if s.flatten {
		return path.Clean("/" + rel)
	}
	return path.Clean("/" + v.m.name + "/" + rel)
}

// Stat follows symlinks that stay inside the mount. It honours stat
// redirects.
func (s *Session) Stat(vp string) (fs.FileInfo, error) { return s.stat(s.redirected(vp), false) }

// Lstat does not follow a final symlink. It honours stat redirects.
func (s *Session) Lstat(vp string) (fs.FileInfo, error) { return s.stat(s.redirected(vp), true) }

func (s *Session) stat(vp string, lstat bool) (fs.FileInfo, error) {
	v, rel, err := s.resolve(vp)
	switch {
	case err != nil:
		return nil, err
	case v == nil:
		return s.t.rootInfo(), nil
	case rel == ".":
		return s.mountInfo(v)
	case !v.perm.Has(PermList):
		return nil, ErrDenied
	}
	if h := s.openWriter(s.virtual(v, rel)); h != nil && h.target != "" {
		// This session's upload through a temporary file (FSTAT on its
		// handle arrives as a STAT of the name): report the upload.
		if fi, err := v.root.Lstat(h.rel); err == nil {
			return namedInfo{fi, filepath.Base(rel)}, nil
		}
	}
	var fi fs.FileInfo
	if lstat {
		fi, err = v.root.Lstat(rel)
	} else {
		fi, err = v.root.Stat(rel)
	}
	return fi, osError(err)
}

// ReadDir lists a directory. The caller must Close the Lister.
func (s *Session) ReadDir(vp string) (Lister, error) {
	v, rel, err := s.resolve(vp)
	if err != nil {
		return nil, err
	}
	if v == nil {
		infos := make([]fs.FileInfo, 0, len(s.views))
		for _, v := range s.views {
			fi, err := s.mountInfo(v)
			if err != nil {
				continue
			}
			infos = append(infos, fi)
		}
		return sliceLister(infos), nil
	}
	if !v.perm.Has(PermList) {
		return nil, ErrDenied
	}
	f, err := v.root.Open(rel)
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
	l := &dirLister{f: f, hideLinks: v.opts().Symlinks == SymlinksDeny} // also hides temporary upload files
	if rel == "." && v.opts().OnConflict == ConflictVersion {
		// Sync tools would try to delete what they do not have locally.
		l.hide = v.opts().Versions.Dir
	}
	return l, nil
}

// OpenRead opens a regular file for reading.
func (s *Session) OpenRead(vp string) (*os.File, error) {
	v, rel, err := s.resolve(vp)
	switch {
	case err != nil:
		return nil, err
	case v == nil, rel == ".":
		return nil, ErrIsDir
	case !v.perm.Has(PermRead):
		return nil, ErrDenied
	}
	s.clearRedirect(v, rel)
	// Check the type first, so that a FIFO or device is not even opened;
	// O_NONBLOCK and the check after opening cover a swap in between.
	if fi, err := v.root.Stat(rel); err != nil {
		return nil, osError(err)
	} else if !fi.Mode().IsRegular() {
		if fi.IsDir() {
			return nil, ErrIsDir
		}
		return nil, ErrNotRegular
	}
	f, err := v.root.OpenFile(rel, os.O_RDONLY|oNonblock, 0)
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
func (s *Session) writable(vp string) (*view, string, error) {
	v, rel, err := s.resolve(vp)
	switch {
	case errors.Is(err, fs.ErrNotExist) && s.topLevel(vp):
		return nil, "", ErrDenied // creating entries in the virtual root
	case err != nil:
		return nil, "", err
	case v == nil, rel == ".", v.m.readOnly, inVersions(v.opts(), rel):
		return nil, "", ErrDenied
	}
	return v, rel, nil
}

// Mkdir creates a directory.
func (s *Session) Mkdir(vp string) error {
	v, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	if !v.perm.Has(PermMkdir) {
		return ErrDenied
	}
	return osError(v.root.Mkdir(rel, v.opts().dirPerm()))
}

// Remove deletes a file (not a directory).
func (s *Session) Remove(vp string) error {
	v, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	if !v.perm.Has(PermDelete) {
		return ErrDenied
	}
	fi, err := v.root.Lstat(rel)
	if err != nil {
		return osError(err)
	}
	if fi.IsDir() {
		return ErrIsDir
	}
	if err := removeEntry(v.root, rel, false); err != nil {
		return osError(err)
	}
	s.forget(v, rel)
	s.clearRedirect(v, rel)
	return nil
}

// Rmdir deletes an empty directory.
func (s *Session) Rmdir(vp string) error {
	v, rel, err := s.writable(vp)
	if err != nil {
		return err
	}
	if !v.perm.Has(PermRmdir) {
		return ErrDenied
	}
	fi, err := v.root.Lstat(rel)
	if err != nil {
		return osError(err)
	}
	if !fi.IsDir() {
		return ErrNotDir
	}
	err = removeEntry(v.root, rel, true)
	if err != nil && isNotEmpty(err) && s.t.removeOrphanTemp(v.root, rel) {
		err = removeEntry(v.root, rel, true)
	}
	return osError(err)
}

// Attrs are the attributes a client may set.
type Attrs struct {
	Size         int64
	HasSize      bool
	Atime, Mtime time.Time
	HasTimes     bool
}

// Setstat applies attributes (ROADMAP §6.3). Permissions and ownership are
// not settable and are ignored. It honours stat redirects.
//
// A size change is allowed only on a file this session has open for writing
// (OpenSSH scp truncates that way; the right to change it was checked when
// the file was opened), never on arbitrary files. Times follow the mount's
// setstat_mode and need the setstat permission, except on files this
// session created: uploaders set the mtime of what they just wrote.
func (s *Session) Setstat(vp string, a Attrs) error {
	v, rel, err := s.writable(s.redirected(vp))
	if err != nil {
		return err
	}
	h := s.openWriter(s.virtual(v, rel))
	if h != nil && h.target != "" {
		rel = h.rel // an upload through a temporary file: set its attributes
	}
	if a.HasSize {
		if h == nil || a.Size < 0 {
			return ErrDenied
		}
		if err := h.truncate(a.Size); err != nil {
			return err
		}
	}
	if !a.HasTimes {
		return nil
	}
	switch v.opts().SetstatMode {
	case SetstatIgnore:
		return nil
	case SetstatDeny:
		return ErrDenied
	case SetstatTimes:
	}
	// An uploader may set the times of its own uploads, while it may
	// still upload: a reload may have taken the write permission away.
	own := v.perm.Has(PermWrite) && s.isCreated(v, rel)
	if !v.perm.Has(PermSetstat) && !own {
		return ErrDenied
	}
	if err := v.root.Chtimes(rel, a.Atime, a.Mtime); err != nil {
		return osError(err)
	}
	if own {
		s.refreshCreated(v, rel)
	}
	return nil
}

// Rename moves src to dst and returns the final client path; see Move.
func (s *Session) Rename(src, dst string, posix bool) (string, error) {
	m, err := s.Move(src, dst, posix)
	return m.Final, err
}

// Moved describes a completed rename.
type Moved struct {
	Final    string // client path the source now has
	Conflict string // ConflictNone, ConflictRenamed, ConflictOverwritten or ConflictVersioned
	Version  string // client path the replaced target was moved to (versioned)
}

// Move renames src to dst. With posix set (posix-rename@openssh.com) an
// existing target is handled by the mount's conflict policy; otherwise (SFTP
// v3 RENAME) an existing target is an error.
//
// Renaming needs the rename permission, or only write for a regular file
// this session created (temporary upload names such as WinSCP's .filepart).
// Replacing an existing target needs overwrite, except under
// on_conflict = "version", which keeps the target as a version.
func (s *Session) Move(src, dst string, posix bool) (Moved, error) {
	sv, srel, err := s.writable(src)
	if err != nil {
		return Moved{}, err
	}
	dv, drel, err := s.writable(dst)
	if err != nil {
		return Moved{}, err
	}
	if sv != dv {
		return Moved{}, ErrUnsupported // across mounts
	}
	s.clearRedirect(sv, srel)
	s.clearRedirect(dv, drel)
	fi, err := sv.root.Lstat(srel)
	if err != nil {
		return Moved{}, osError(err)
	}
	own := fi.Mode().IsRegular() && s.isCreated(sv, srel)
	if !sv.perm.Has(PermRename) && (!own || !sv.perm.Has(PermWrite)) {
		return Moved{}, ErrDenied
	}
	done := func(rel, conflict string) (Moved, error) {
		s.moveCreated(sv, srel, rel, own)
		return Moved{Final: s.virtual(sv, rel), Conflict: conflict}, nil
	}

	err = noClobberRename(sv.root, srel, drel)
	switch {
	case err == nil:
		return done(drel, ConflictNone)
	case !errors.Is(err, fs.ErrExist):
		return Moved{}, osError(err)
	case !posix:
		return Moved{}, ErrExists
	}

	switch sv.opts().OnConflict {
	case ConflictOverwrite:
		if !sv.perm.Has(PermOverwrite) {
			return Moved{}, ErrDenied
		}
		if err := sv.root.Rename(srel, drel); err != nil {
			return Moved{}, osError(err)
		}
		return done(drel, ConflictOverwritten)
	case ConflictReject:
		return Moved{}, ErrConflict
	case ConflictVersion:
		if !fi.Mode().IsRegular() {
			return Moved{}, ErrNotRegular // only files replace files
		}
		version, err := s.replaceVersioned(sv, srel, drel)
		if err != nil {
			return Moved{}, err
		}
		m, _ := done(drel, ConflictVersioned)
		m.Version = s.virtual(sv, version)
		return m, nil
	case ConflictRename: // move the source next to the target under a free name
		final, err := sv.opts().freeName(drel, func(cand string) error { return noClobberRename(sv.root, srel, cand) })
		if err != nil {
			return Moved{}, err
		}
		// rclone checks the size of the target after a move and deletes
		// "a failed copy" at the requested name: that would be the original.
		if sv.opts().StatRedirect {
			s.setRedirect(sv, drel, final)
		}
		return done(final, ConflictRenamed)
	}
	return Moved{}, fmt.Errorf("unknown conflict policy %q", sv.opts().OnConflict)
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
	s.writers[h.key] = append(s.writers[h.key], h)
	s.mu.Unlock()
	if h.reserved && h.id != nil {
		s.own(h.v, h.rel, h.id)
	}
}

func (s *Session) unregister(h *WriteHandle, removed bool) {
	s.mu.Lock()
	hs := slices.DeleteFunc(s.writers[h.key], func(x *WriteHandle) bool { return x == h })
	if len(hs) == 0 {
		delete(s.writers, h.key)
	} else {
		s.writers[h.key] = hs
	}
	s.mu.Unlock()
	if removed {
		s.forget(h.v, h.rel)
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
