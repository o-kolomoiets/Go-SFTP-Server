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
	m         *Mount
	rel       string
	f         *os.File
	virtual   string // final client path
	conflict  string
	reserved  bool // the file was created by this upload
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

// Close finishes the upload. When aborted (the connection broke) and no byte
// was written to a file this upload created, the empty file is removed.
func (h *WriteHandle) Close(aborted bool) error {
	h.closeOnce.Do(func() {
		h.s.unregister(h)
		h.closeErr = osError(h.f.Close())
		if aborted && h.reserved && h.written.Load() == 0 {
			_ = h.m.root.Remove(h.rel)
		}
	})
	return h.closeErr
}

// OpenWrite opens vp for an upload, applying the conflict policy:
//
//   - EXCL on an existing file always fails;
//   - APPEND, or WRITE without CREAT and TRUNC, is a resume: refused for now;
//   - any other write to an existing file is a conflict: rename (write to
//     "name (n).ext"), reject, or overwrite, per the table's policy.
//
// Conflicts are not detected by TRUNC: OpenSSH scp opens existing files with
// WRITE|CREAT and truncates later via FSETSTAT.
func (s *Session) OpenWrite(vp string, fl OpenFlags) (*WriteHandle, error) {
	m, rel, err := s.t.resolve(vp)
	switch {
	case errors.Is(err, fs.ErrNotExist) && s.t.topLevel(vp):
		return nil, ErrDenied // creating entries in the virtual root
	case err != nil:
		return nil, err
	case m == nil:
		return nil, ErrDenied
	case rel == ".":
		return nil, ErrIsDir
	case m.readOnly:
		return nil, ErrDenied
	}

	h, err := s.openWrite(m, rel, fl)
	if err != nil {
		return nil, err
	}
	h.s, h.m = s, m
	h.virtual = s.t.virtual(m, h.rel)
	s.register(h)
	return h, nil
}

func (s *Session) openWrite(m *Mount, rel string, fl OpenFlags) (*WriteHandle, error) {
	fi, err := m.root.Stat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !fl.Creat {
			return nil, fs.ErrNotExist
		}
		f, err := m.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
		if err != nil {
			// Lost a race, or rel is a dangling symlink: do not follow it.
			return nil, osError(err)
		}
		return &WriteHandle{rel: rel, f: f, conflict: ConflictNone, reserved: true}, nil
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

	switch s.t.policy {
	case ConflictReject:
		return nil, ErrConflict
	case ConflictOverwrite:
		flags := os.O_WRONLY | oNonblock
		if fl.Trunc {
			flags |= os.O_TRUNC
		}
		f, err := m.root.OpenFile(rel, flags, 0)
		if err != nil {
			return nil, osError(err)
		}
		if err := requireRegular(f); err != nil {
			_ = f.Close()
			return nil, err
		}
		return &WriteHandle{rel: rel, f: f, conflict: ConflictOverwritten}, nil
	case ConflictRename:
		var f *os.File
		final, err := freeName(rel, func(cand string) error {
			var err error
			f, err = m.root.OpenFile(cand, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
			return err
		})
		if err != nil {
			return nil, err
		}
		return &WriteHandle{rel: final, f: f, conflict: ConflictRenamed, reserved: true}, nil
	}
	return nil, fmt.Errorf("unknown conflict policy %q", s.t.policy)
}

// freeName tries "stem (1).ext" … "stem (100).ext" next to rel, then a
// timestamped name, calling try for each candidate until it does not fail
// with fs.ErrExist. try must create or claim the candidate atomically.
func freeName(rel string, try func(cand string) error) (string, error) {
	dir, base := filepath.Split(rel)
	stem, ext := splitExt(base)
	for n := 1; n <= maxRenameNo; n++ {
		cand := filepath.Join(dir, candidate(stem, fmt.Sprintf("(%d)", n), ext))
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
	tag := fmt.Sprintf("(%s-%s)", time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(b[:]))
	cand := filepath.Join(dir, candidate(stem, tag, ext))
	if err := try(cand); err != nil {
		return "", osError(err)
	}
	return cand, nil
}

var compoundExts = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"}

// splitExt splits "report.tar.gz" into "report" and ".tar.gz". A leading dot
// does not start an extension: ".env" has none.
func splitExt(name string) (stem, ext string) {
	lower := strings.ToLower(name)
	for _, ce := range compoundExts {
		if strings.HasSuffix(lower, ce) && len(name) > len(ce) {
			return name[:len(name)-len(ce)], name[len(name)-len(ce):]
		}
	}
	ext = filepath.Ext(name)
	if ext == name {
		return name, ""
	}
	return name[:len(name)-len(ext)], ext
}

// candidate builds "stem tag ext", shortening stem so the name fits
// maxNameLen bytes without splitting a UTF-8 sequence.
func candidate(stem, tag, ext string) string {
	limit := max(maxNameLen-len(tag)-len(ext)-1, 1)
	for len(stem) > limit {
		_, size := utf8.DecodeLastRuneInString(stem)
		stem = stem[:len(stem)-size]
	}
	return stem + " " + tag + ext
}
