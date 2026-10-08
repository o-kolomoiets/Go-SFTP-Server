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
	written   atomic.Int64
	closeOnce sync.Once
	closeErr  error
}

// Path returns the client path the data is written to; with the rename
// policy it differs from the requested one.
func (h *WriteHandle) Path() string { return h.virtual }

// Conflict returns ConflictNone, ConflictRenamed or ConflictOverwritten.
func (h *WriteHandle) Conflict() string { return h.conflict }

// Written returns the number of bytes written so far.
func (h *WriteHandle) Written() int64 { return h.written.Load() }

// WriteAt writes at an absolute offset.
func (h *WriteHandle) WriteAt(p []byte, off int64) (int, error) {
	n, err := h.f.WriteAt(p, off)
	h.written.Add(int64(n))
	return n, osError(err)
}

func (h *WriteHandle) truncate(size int64) error { return osError(h.f.Truncate(size)) }

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

// reservedHandle returns a handle for a file this upload just created.
func reservedHandle(rel string, f *os.File, conflict string) (*WriteHandle, error) {
	id, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, osError(err)
	}
	return &WriteHandle{rel: rel, f: f, conflict: conflict, reserved: true, id: id}, nil
}

// Close finishes the upload. When aborted (the connection broke) and no byte
// was written to a file this upload created, the empty file is removed.
func (h *WriteHandle) Close(aborted bool) error {
	h.closeOnce.Do(func() {
		removed := aborted && h.reserved && h.written.Load() == 0 && h.removeIfUnused()
		if h.reserved && !removed {
			if st, err := h.f.Stat(); err == nil {
				h.s.closedCreated(h, st)
			}
		}
		h.closeErr = osError(h.f.Close())
		h.s.unregister(h, removed)
	})
	return h.closeErr
}

// OpenWrite opens vp for an upload, applying the mount's conflict policy:
//
//   - a new file needs the write permission;
//   - EXCL on an existing file always fails;
//   - APPEND, or WRITE without CREAT and TRUNC, is a resume: refused for now;
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
	case v.m.readOnly, v.perm&(PermWrite|PermOverwrite) == 0:
		return nil, ErrDenied
	}

	h, err := s.openWrite(v, rel, fl)
	if err != nil {
		return nil, err
	}
	h.s, h.v = s, v
	h.virtual = s.virtual(v, h.rel)
	s.register(h)
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
		f, err := v.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, opts.filePerm())
		if err != nil {
			// Lost a race, or rel is a dangling symlink: do not follow it.
			return nil, osError(err)
		}
		return reservedHandle(rel, f, ConflictNone)
	case err != nil:
		return nil, osError(err)
	case fi.IsDir():
		return nil, ErrIsDir
	case !fi.Mode().IsRegular():
		return nil, ErrNotRegular
	case fl.Excl:
		return nil, ErrExists
	case fl.Append || (!fl.Creat && !fl.Trunc):
		return nil, ErrResumeUnsupported
	}

	switch opts.OnConflict {
	case ConflictReject:
		return nil, ErrConflict
	case ConflictOverwrite:
		if !v.perm.Has(PermOverwrite) {
			return nil, ErrDenied
		}
		flags := os.O_WRONLY | oNonblock
		if fl.Trunc {
			flags |= os.O_TRUNC
		}
		f, err := v.root.OpenFile(rel, flags, 0)
		if err != nil {
			return nil, osError(err)
		}
		if err := requireRegular(f); err != nil {
			_ = f.Close()
			return nil, err
		}
		return &WriteHandle{rel: rel, f: f, conflict: ConflictOverwritten}, nil
	case ConflictRename:
		if !v.perm.Has(PermWrite) {
			return nil, ErrDenied
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
		return reservedHandle(final, f, ConflictRenamed)
	}
	return nil, fmt.Errorf("unknown conflict policy %q", opts.OnConflict)
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
