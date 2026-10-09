// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Uploads that get their name only when they are closed: every upload with
// atomic_uploads, and conflicts under on_conflict = "version". They are
// written to a temporary file next to the target, which is published by a
// rename that never replaces a file by accident.

// tempPrefix starts the names of temporary upload files. Clients cannot use
// such names: they are hidden from listings and refused in paths.
const tempPrefix = ".gosftpd-"

const tempSuffix = ".part"

// TempMaxAge is the age after which the janitor removes temporary files
// left behind (by a crash of the server; aborted uploads remove their own).
const TempMaxAge = 24 * time.Hour

// isTempName reports whether a path component is reserved for temporary
// upload files. Case is ignored, as on macOS and Windows filesystems.
func isTempName(name string) bool { return hasPrefixFold(name, tempPrefix) }

// hasPrefixFold reports whether s starts with prefix under Unicode case
// folding.
func hasPrefixFold(s, prefix string) bool {
	for _, p := range prefix {
		r, n := utf8.DecodeRuneInString(s)
		if n == 0 || !strings.EqualFold(string(r), string(p)) {
			return false
		}
		s = s[n:]
	}
	return true
}

// reservedPath reports whether a client path inside a mount names a
// temporary upload file or something below one.
func reservedPath(rel string) bool {
	for c := range strings.SplitSeq(rel, string(filepath.Separator)) {
		if isTempName(c) {
			return true
		}
	}
	return false
}

// inVersions reports whether rel is the versions directory of a mount with
// on_conflict = "version", or lies inside it (ignoring case, as on macOS
// and Windows filesystems). Clients may read it, but only the server
// changes it.
func inVersions(o *MountOptions, rel string) bool {
	if o.OnConflict != ConflictVersion {
		return false
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	return strings.EqualFold(first, o.Versions.Dir)
}

// tempHandle starts an upload to target through a temporary file in the
// same directory (0600 until it is published).
func (s *Session) tempHandle(v *view, target string) (*WriteHandle, error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	tmp := filepath.Join(filepath.Dir(target), tempPrefix+hex.EncodeToString(b[:])+tempSuffix)
	f, err := v.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, osError(err)
	}
	h, err := s.reservedHandle(tmp, f, ConflictNone)
	if err != nil {
		_ = v.root.Remove(tmp)
		return nil, err
	}
	h.target = target
	return h, nil
}

// closeTemp finishes an upload written to a temporary file: it publishes
// the file under its target name, or removes it if the upload was aborted,
// is incomplete (a write was refused: ErrTooLarge) or cannot be published.
func (h *WriteHandle) closeTemp(aborted bool) error {
	s, v := h.s, h.v
	refused := !aborted && h.refused.Load()
	aborted = aborted || refused
	s.t.release(h)
	tmp := h.rel
	var err error
	if !aborted {
		err = h.f.Chmod(v.opts().filePerm())
		if err == nil && v.opts().Fsync {
			err = h.f.Sync()
		}
	}
	err = errors.Join(osError(err), osError(h.f.Close()))
	if !aborted && err == nil {
		err = s.publish(h)
	}
	if aborted || err != nil {
		_ = removeEntry(v.root, tmp, false)
		s.unregister(h, true)
		if refused && err == nil {
			err = ErrTooLarge
		}
		return err
	}
	s.moveCreated(v, tmp, h.rel, true)
	// The handle proves the upload created the file, even if its entry
	// was evicted while the upload was open.
	if st, err := v.root.Lstat(h.rel); err == nil {
		s.closedCreated(h, st)
	}
	if h.rel != h.target && v.opts().StatRedirect {
		s.setRedirect(v, h.target, h.rel)
	}
	h.virtual = s.virtual(v, h.rel)
	s.unregister(h, false)
	return nil
}

// publish gives the temporary file of h its name, by the mount's conflict
// policy if the target exists by now, and updates h.rel and h.conflict.
func (s *Session) publish(h *WriteHandle) error {
	v, opts := h.v, h.v.opts()
	tmp := h.rel
	set := func(rel, conflict string) error {
		h.rel, h.conflict = rel, conflict
		return nil
	}
	err := noClobberRename(v.root, tmp, h.target)
	switch {
	case err == nil:
		return set(h.target, ConflictNone)
	case !errors.Is(err, fs.ErrExist):
		return osError(err)
	}
	switch opts.OnConflict {
	case ConflictReject:
		return ErrConflict
	case ConflictOverwrite:
		if !v.perm.Has(PermOverwrite) {
			return ErrDenied
		}
		if err := regularTarget(v.root, h.target); err != nil {
			return err
		}
		if err := v.root.Rename(tmp, h.target); err != nil {
			return osError(err)
		}
		return set(h.target, ConflictOverwritten)
	case ConflictRename:
		final, err := opts.freeName(h.target, func(cand string) error { return noClobberRename(v.root, tmp, cand) })
		if err != nil {
			return err
		}
		return set(final, ConflictRenamed)
	case ConflictVersion:
		version, err := s.replaceVersioned(v, tmp, h.target)
		if err != nil {
			return err
		}
		h.version = version
		return set(h.target, ConflictVersioned)
	}
	return ErrUnsupported
}

// regularTarget reports why rel cannot be replaced unless it is a regular
// file.
func regularTarget(root *os.Root, rel string) error {
	fi, err := root.Lstat(rel)
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

// replaceVersioned moves the file at target into the versions directory
// and src into its place. If another file appears at target in between, it
// is versioned too. It returns the mount-relative path of the version.
func (s *Session) replaceVersioned(v *view, src, target string) (string, error) {
	var version string
	for range 3 {
		if err := regularTarget(v.root, target); err != nil {
			return "", err
		}
		ver, err := s.saveVersion(v, target)
		if err != nil {
			return "", err
		}
		version = ver
		err = noClobberRename(v.root, src, target)
		if err == nil {
			return version, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			// Put the old file back rather than leave the name empty.
			_ = noClobberRename(v.root, ver, target)
			return "", osError(err)
		}
	}
	return "", ErrBusy
}

// versionTimeLayout names versions; it sorts in time order.
const versionTimeLayout = "20060102T150405Z"

// saveVersion moves rel to <versions dir>/<rel>/<stem>.<UTC time><ext> and
// applies the retention limits to that directory. It returns the version's
// mount-relative path.
func (s *Session) saveVersion(v *view, rel string) (string, error) {
	opts := v.opts()
	dir := filepath.Join(opts.Versions.Dir, rel)
	if err := v.root.MkdirAll(dir, opts.dirPerm()); err != nil {
		return "", osError(err)
	}
	stem, ext := splitExt(filepath.Base(rel), opts.CompoundExts)
	now := s.t.now()
	ts := now.UTC().Format(versionTimeLayout)
	for n := 0; ; n++ {
		mid := ts
		if n > 0 {
			mid += "-" + strconv.Itoa(n)
		}
		cand := filepath.Join(dir, candidate("{stem}.{n}{ext}", stem, mid, ext))
		err := noClobberRename(v.root, rel, cand)
		if err == nil {
			s.forget(v, rel)
			retention := opts.Versions
			if !v.perm.Has(PermDelete) && !v.perm.Has(PermOverwrite) {
				// Otherwise a user who may only write could push the
				// original out by uploading keep times.
				retention.Keep = 0
			}
			pruneVersions(v.root, dir, ext, retention, now)
			return cand, nil
		}
		if !errors.Is(err, fs.ErrExist) || n >= 100 {
			return "", osError(err)
		}
	}
}

// pruneVersions keeps the newest Keep versions in dir that are younger
// than MaxAge. Files that do not look like versions are left alone. The
// stem is not matched: candidate may have shortened it.
func pruneVersions(root *os.Root, dir, ext string, o VersionsOptions, now time.Time) {
	f, err := root.Open(dir)
	if err != nil {
		return
	}
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	if err != nil {
		return
	}
	type version struct {
		name string
		at   time.Time
		n    int
	}
	var vs []version
	for _, name := range names {
		base, ok := strings.CutSuffix(name, ext)
		i := strings.LastIndexByte(base, '.')
		if !ok || i < 0 {
			continue
		}
		tsPart, nPart, _ := strings.Cut(base[i+1:], "-")
		at, err := time.Parse(versionTimeLayout, tsPart)
		if err != nil {
			continue
		}
		n := 0
		if nPart != "" {
			if n, err = strconv.Atoi(nPart); err != nil {
				continue
			}
		}
		vs = append(vs, version{name, at, n})
	}
	slices.SortFunc(vs, func(a, b version) int { // newest first
		return cmp.Or(b.at.Compare(a.at), cmp.Compare(b.n, a.n))
	})
	for i, ver := range vs {
		tooMany := o.Keep > 0 && i >= o.Keep
		tooOld := o.MaxAge > 0 && now.Sub(ver.at) > o.MaxAge
		if tooMany || tooOld {
			_ = removeEntry(root, filepath.Join(dir, ver.name), false)
		}
	}
}

// checkFree refuses a new write while the mount's filesystem has less free
// space than min_free_space. Platforms without statfs skip the check.
func checkFree(v *view) error {
	limit := v.opts().MinFreeSpace
	if limit <= 0 || !StatFSSupported {
		return nil
	}
	d, err := v.root.Open(".")
	if err != nil {
		return osError(err)
	}
	defer d.Close()
	// A filesystem that cannot report its free space (an error, or no
	// blocks at all, as FUSE filesystems without statfs) is not refused.
	if st, err := statfs(d); err == nil && st.Blocks > 0 && st.BlocksAvail*st.FragmentSize < uint64(limit) {
		return ErrNoSpace
	}
	return nil
}

// removeOrphanTemp removes the temporary upload files in dir that no open
// upload writes (left by a crash), if they are all dir contains. Clients do
// not see them, so to them the directory is empty.
func (t *Table) removeOrphanTemp(root *os.Root, dir string) bool {
	f, err := root.Open(dir)
	if err != nil {
		return false
	}
	names, err := f.Readdirnames(100)
	_ = f.Close()
	if err != nil || len(names) == 100 || slices.ContainsFunc(names, func(n string) bool { return !isTempName(n) }) {
		return false
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		fi, err := root.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || t.writingFile(fi) || removeEntry(root, p, false) != nil {
			return false
		}
	}
	return true
}

// writingFile reports whether an open upload writes fi.
func (t *Table) writingFile(fi os.FileInfo) bool {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return slices.ContainsFunc(t.writing, func(h *WriteHandle) bool { return os.SameFile(h.ino, fi) })
}

// CleanTemp removes temporary upload files older than TempMaxAge from every
// writable mount (for a home mount, from every user's directory). It
// returns how many it removed. Directories it cannot read are skipped.
func (t *Table) CleanTemp() int {
	removed := 0
	cutoff := time.Now().Add(-TempMaxAge)
	for _, m := range t.mounts {
		if m.readOnly {
			continue
		}
		_ = fs.WalkDir(m.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !isTempName(d.Name()) || !strings.HasSuffix(d.Name(), tempSuffix) {
				return nil //nolint:nilerr // skip what cannot be read
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() || fi.ModTime().After(cutoff) {
				return nil //nolint:nilerr // skip what cannot be read
			}
			if m.root.Remove(filepath.FromSlash(p)) == nil {
				removed++
			}
			return nil
		})
	}
	return removed
}
