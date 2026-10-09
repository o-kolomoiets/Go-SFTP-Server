// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// OpenFlags are the SFTP open flags relevant to writing.
type OpenFlags struct {
	Read, Write, Append, Creat, Trunc, Excl bool
}

// Conflict outcomes recorded for an upload.
const (
	ConflictNone        = "none"
	ConflictRenamed     = "renamed"
	ConflictOverwritten = "overwritten"
	ConflictVersioned   = "versioned"
)

// WriteHandle is an open upload.
type WriteHandle struct {
	s         *Session
	v         *view
	rel       string
	f         *os.File
	virtual   string // final client path
	conflict  string
	reserved  bool        // the file was created by this upload
	id        fs.FileInfo // identity of the created file
	ino       fs.FileInfo // the open file, for the table's writer registry
	guarded   bool        // append-only resume: bytes below minOffset are immutable
	minOffset int64
	maxSize   int64 // max_file_size; 0: no limit
	// For an upload through a temporary file (see publish.go): rel is the
	// temporary file until Close publishes it under target.
	target    string
	version   string // where publishing moved the replaced file
	key       string // the session's writers map key: the virtual path at open
	written   atomic.Int64
	refused   atomic.Bool // a write or truncation past max_file_size
	closeOnce sync.Once
	closeErr  error
}

// Path returns the client path the data is written to; with the rename
// policy it differs from the requested one.
func (h *WriteHandle) Path() string { return h.virtual }

// Conflict returns ConflictNone, ConflictRenamed, ConflictOverwritten or
// ConflictVersioned. For an upload through a temporary file it is known
// once the upload is closed.
func (h *WriteHandle) Conflict() string { return h.conflict }

// Version returns the client path the replaced file was moved to under
// on_conflict = "version", or "".
func (h *WriteHandle) Version() string {
	if h.version == "" {
		return ""
	}
	return h.s.virtual(h.v, h.version)
}

// Written returns the number of bytes written so far.
func (h *WriteHandle) Written() int64 { return h.written.Load() }

// StartOffset returns the size of the file when an append-only resume
// opened it; ok is false for other uploads.
func (h *WriteHandle) StartOffset() (offset int64, ok bool) { return h.minOffset, h.guarded }

// WriteAt writes at an absolute offset. A resumed upload may not write
// below the size the file had when it was opened, and no upload past
// max_file_size (checked on the end of the write, so a sparse file cannot
// slip past it).
func (h *WriteHandle) WriteAt(p []byte, off int64) (int, error) {
	if h.guarded && off < h.minOffset {
		return 0, ErrImmutable
	}
	if h.maxSize > 0 && (off < 0 || off > h.maxSize-int64(len(p))) {
		h.refused.Store(true)
		return 0, ErrTooLarge
	}
	n, err := h.f.WriteAt(p, off)
	h.written.Add(int64(n))
	return n, osError(err)
}

// truncate sets the file size; a resumed upload may not cut existing data
// (OpenSSH truncates to the old size after an interrupted reput, which is
// allowed).
func (h *WriteHandle) truncate(size int64) error {
	if h.guarded && size < h.minOffset {
		return ErrImmutable
	}
	if h.maxSize > 0 && size > h.maxSize {
		h.refused.Store(true)
		return ErrTooLarge
	}
	return osError(h.f.Truncate(size))
}

// removeIfUnused deletes the file this upload created, if it is still empty
// and still at its path: the session may have renamed it, and another user
// may have put a file there or written into it since.
func (h *WriteHandle) removeIfUnused() bool {
	cur, err := h.f.Stat()
	if err != nil || cur.Size() != 0 || h.id == nil || !os.SameFile(cur, h.id) {
		return false
	}
	onDisk, err := h.v.root.Lstat(h.rel)
	if err != nil || !os.SameFile(cur, onDisk) {
		return false
	}
	return removeEntry(h.v.root, h.rel, false) == nil
}

// claim registers h as the only writer of its file. A file another upload
// (of any session) has open cannot be opened in place: the new writer would
// change bytes the other one wrote, behind its back.
func (t *Table) claim(h *WriteHandle) error {
	ino, err := h.f.Stat()
	if err != nil {
		return osError(err)
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, w := range t.writing {
		if os.SameFile(w.ino, ino) {
			return ErrBusy
		}
	}
	h.ino = ino
	t.writing = append(t.writing, h)
	return nil
}

func (t *Table) release(h *WriteHandle) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.writing = slices.DeleteFunc(t.writing, func(w *WriteHandle) bool { return w == h })
}

// openedHandle claims the file of a new handle; on failure the file is
// closed.
func (s *Session) openedHandle(h *WriteHandle) (*WriteHandle, error) {
	if err := s.t.claim(h); err != nil {
		_ = h.f.Close()
		return nil, err
	}
	return h, nil
}

// reservedHandle returns a handle for a file this upload just created.
func (s *Session) reservedHandle(rel string, f *os.File, conflict string) (*WriteHandle, error) {
	h, err := s.openedHandle(&WriteHandle{rel: rel, f: f, conflict: conflict, reserved: true})
	if err != nil {
		return nil, err
	}
	h.id = h.ino
	return h, nil
}

// Close finishes the upload. When aborted (the connection broke) and no byte
// was written to a file this upload created, the empty file is removed.
func (h *WriteHandle) Close(aborted bool) error {
	h.closeOnce.Do(func() {
		if h.target != "" {
			h.closeErr = h.closeTemp(aborted)
			return
		}
		removed := aborted && h.reserved && h.written.Load() == 0 && h.removeIfUnused()
		if h.reserved && !removed {
			if st, err := h.f.Stat(); err == nil {
				h.s.closedCreated(h, st)
			}
		}
		h.s.t.release(h)
		h.closeErr = osError(h.f.Close())
		h.s.unregister(h, removed)
	})
	return h.closeErr
}

// OpenWrite opens vp for an upload, applying the mount's conflict policy:
//
//   - a new file needs the write permission;
//   - EXCL on an existing file always fails;
//   - APPEND, or WRITE without CREAT and TRUNC, is a resume: see openResume;
//   - any other write to an existing file is a conflict: rename (write to a
//     new name, needs write), reject, or overwrite (needs overwrite).
//
// Conflicts are not detected by TRUNC: OpenSSH scp opens existing files with
// WRITE|CREAT and truncates later via FSETSTAT.
func (s *Session) OpenWrite(vp string, fl OpenFlags) (*WriteHandle, error) {
	v, rel, err := s.resolve(vp)
	switch {
	case errors.Is(err, fs.ErrNotExist) && s.topLevel(vp):
		return nil, ErrDenied // creating entries in the virtual root
	case err != nil:
		return nil, err
	case v == nil:
		return nil, ErrDenied
	case rel == ".":
		return nil, ErrIsDir
	case v.m.readOnly, v.perm&(PermWrite|PermOverwrite) == 0, inVersions(v.opts(), rel):
		return nil, ErrDenied
	}
	if err := checkFree(v); err != nil {
		return nil, err
	}

	requested := rel
	if final, ok := s.redirectFor(v, rel); ok && isResume(fl) {
		// OpenSSH reput stats the name first and resumes at the size it
		// got: through the redirect, the size of the user's copy. The
		// resume must go to that copy too, never to the original.
		rel = final
	} else {
		s.clearRedirect(v, rel)
	}
	h, err := s.openWrite(v, rel, fl)
	if err != nil {
		return nil, err
	}
	h.s, h.v = s, v
	h.maxSize = v.opts().MaxFileSize
	name := h.rel
	if h.target != "" {
		name = h.target // the name is given when the upload is closed
	}
	h.virtual = s.virtual(v, name)
	h.key = h.virtual
	s.register(h)
	if name != requested && v.opts().StatRedirect {
		s.setRedirect(v, requested, name)
	}
	return h, nil
}

func (s *Session) openWrite(v *view, rel string, fl OpenFlags) (*WriteHandle, error) {
	opts := v.opts()
	fi, err := v.root.Stat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !fl.Creat {
			return nil, fs.ErrNotExist
		}
		if !v.perm.Has(PermWrite) {
			return nil, ErrDenied
		}
		if opts.AtomicUploads {
			return s.tempHandle(v, rel)
		}
		f, err := v.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, opts.filePerm())
		if err != nil {
			// Lost a race, or rel is a dangling symlink: do not follow it.
			return nil, osError(err)
		}
		return s.reservedHandle(rel, f, ConflictNone)
	case err != nil:
		return nil, osError(err)
	case fi.IsDir():
		return nil, ErrIsDir
	case !fi.Mode().IsRegular():
		return nil, ErrNotRegular
	case fl.Excl:
		return nil, ErrExists
	case isResume(fl) && opts.AtomicUploads:
		return nil, ErrResumeDisabled // an atomic upload has nothing to continue
	case isResume(fl):
		return s.openResume(v, rel, fl.Append)
	}

	switch opts.OnConflict {
	case ConflictReject:
		return nil, ErrConflict
	case ConflictVersion:
		// The old file is kept, so replacing it needs only write.
		if !v.perm.Has(PermWrite) {
			return nil, ErrDenied
		}
		return s.tempHandle(v, rel)
	case ConflictOverwrite:
		if !v.perm.Has(PermOverwrite) {
			return nil, ErrDenied
		}
		if opts.AtomicUploads {
			return s.tempHandle(v, rel)
		}
		// Not O_TRUNC: truncate only once this is the file's only writer.
		f, err := v.root.OpenFile(rel, os.O_WRONLY|oNonblock, 0)
		if err != nil {
			return nil, osError(err)
		}
		if err := requireRegular(f); err != nil {
			_ = f.Close()
			return nil, err
		}
		h, err := s.openedHandle(&WriteHandle{rel: rel, f: f, conflict: ConflictOverwritten})
		if err != nil {
			return nil, err
		}
		if fl.Trunc {
			if err := f.Truncate(0); err != nil {
				s.t.release(h)
				_ = f.Close()
				return nil, osError(err)
			}
		}
		return h, nil
	case ConflictRename:
		if !v.perm.Has(PermWrite) {
			return nil, ErrDenied
		}
		if opts.AtomicUploads {
			return s.tempHandle(v, rel) // the free name is chosen on Close
		}
		var f *os.File
		final, err := opts.freeName(rel, func(cand string) error {
			var err error
			f, err = v.root.OpenFile(cand, os.O_WRONLY|os.O_CREATE|os.O_EXCL, opts.filePerm())
			return err
		})
		if err != nil {
			return nil, err
		}
		return s.reservedHandle(final, f, ConflictRenamed)
	}
	return nil, fmt.Errorf("unknown conflict policy %q", opts.OnConflict)
}

// isResume reports whether open flags continue an existing file: APPEND, or
// WRITE without CREAT and TRUNC (ROADMAP §6.2 rows 4 and 5).
func isResume(fl OpenFlags) bool { return fl.Append || (!fl.Creat && !fl.Trunc) }

// openResume opens an existing file to continue an upload (OpenSSH reput,
// paramiko mode "a", Cyberduck). It may not go to another name: the client
// writes at the offset where it stopped. Unless resume is off, the
// append-only guard keeps the existing bytes unchanged; only WRITE without
// APPEND, with the overwrite policy and the overwrite permission, is a plain
// write.
//
// Offsets are used as sent, also with APPEND: requests are served in
// parallel, so "write at the end" would reorder pipelined writes (OpenSSH
// reput sends correct offsets). A client that sends offset 0 for APPEND
// gets "existing data is immutable" instead of overwriting the file.
func (s *Session) openResume(v *view, rel string, appendOnly bool) (*WriteHandle, error) {
	opts := v.opts()
	plain := !appendOnly && opts.OnConflict == ConflictOverwrite && v.perm.Has(PermOverwrite)
	switch {
	case plain:
	case opts.Resume == ResumeOff:
		return nil, ErrResumeDisabled
	case !v.perm.Has(PermWrite):
		return nil, ErrDenied
	}
	f, err := v.root.OpenFile(rel, os.O_WRONLY|oNonblock, 0)
	if err != nil {
		return nil, osError(err)
	}
	fi, err := f.Stat()
	switch {
	case err != nil:
		_ = f.Close()
		return nil, osError(err)
	case !fi.Mode().IsRegular():
		_ = f.Close()
		return nil, ErrNotRegular
	}
	if plain {
		return s.openedHandle(&WriteHandle{rel: rel, f: f, conflict: ConflictOverwritten})
	}
	h, err := s.openedHandle(&WriteHandle{rel: rel, f: f, conflict: ConflictNone, guarded: true})
	if err != nil {
		return nil, err
	}
	// The size once this is the only writer: nothing below it can change.
	st, err := f.Stat()
	if err != nil {
		s.t.release(h)
		_ = f.Close()
		return nil, osError(err)
	}
	h.minOffset = st.Size()
	return h, nil
}

// freeName tries the rename template with n = 1 … MaxRenameAttempts next to
// rel, then with a timestamp, calling try for each candidate until it does
// not fail with fs.ErrExist. try must create or claim the candidate
// atomically.
func (o *MountOptions) freeName(rel string, try func(cand string) error) (string, error) {
	dir, base := filepath.Split(rel)
	stem, ext := splitExt(base, o.CompoundExts)
	for n := 1; n <= o.MaxRenameAttempts; n++ {
		cand := filepath.Join(dir, candidate(o.RenameTemplate, stem, strconv.Itoa(n), ext))
		err := try(cand)
		if err == nil {
			return cand, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", osError(err)
		}
	}
	// Many copies already: avoid an O(n²) scan with a unique name.
	var b [2]byte
	_, _ = rand.Read(b[:])
	tag := time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
	cand := filepath.Join(dir, candidate(o.RenameTemplate, stem, tag, ext))
	if err := try(cand); err != nil {
		return "", osError(err)
	}
	return cand, nil
}

// splitExt splits "report.tar.gz" into "report" and ".tar.gz" when
// ".tar.gz" is one of compound. A leading dot does not start an extension:
// ".env" has none.
func splitExt(name string, compound []string) (stem, ext string) {
	lower := strings.ToLower(name)
	for _, ce := range compound {
		if strings.HasSuffix(lower, strings.ToLower(ce)) && len(name) > len(ce) {
			return name[:len(name)-len(ce)], name[len(name)-len(ce):]
		}
	}
	ext = filepath.Ext(name)
	if ext == name {
		return name, ""
	}
	return name[:len(name)-len(ext)], ext
}

// candidate expands the rename template, shortening stem so the name fits
// maxNameLen bytes without splitting a UTF-8 sequence.
func candidate(tmpl, stem, n, ext string) string {
	expand := func(stem string) string {
		return strings.NewReplacer("{stem}", stem, "{n}", n, "{ext}", ext).Replace(tmpl)
	}
	stems := max(strings.Count(tmpl, "{stem}"), 1)
	limit := max((maxNameLen-len(expand("")))/stems, 1)
	for len(stem) > limit {
		_, size := utf8.DecodeLastRuneInString(stem)
		stem = stem[:len(stem)-size]
	}
	return expand(stem)
}
