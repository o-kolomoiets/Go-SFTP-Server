// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"io"
	"io/fs"
	"os"
	"time"
)

// dirInfo is a synthetic directory: the virtual root or a mount root.
type dirInfo struct {
	name    string
	perm    fs.FileMode
	modTime time.Time
}

func (d dirInfo) Name() string       { return d.name }
func (d dirInfo) Size() int64        { return 0 }
func (d dirInfo) Mode() fs.FileMode  { return fs.ModeDir | d.perm }
func (d dirInfo) ModTime() time.Time { return d.modTime }
func (d dirInfo) IsDir() bool        { return true }
func (d dirInfo) Sys() any           { return nil }

func (t *Table) rootInfo() fs.FileInfo {
	return dirInfo{name: "/", perm: 0o555, modTime: t.started}
}

// mountInfo describes a mount root as the session sees it: writable if the
// user may change anything in it.
func (s *Session) mountInfo(v *view) (fs.FileInfo, error) {
	fi, err := v.root.Stat(".")
	if err != nil {
		return nil, osError(err)
	}
	name := v.m.name
	if s.flatten {
		name = "/"
	}
	perm := fs.FileMode(0o555)
	if v.perm&permModify != 0 {
		perm = 0o755
	}
	return dirInfo{name: name, perm: perm, modTime: fi.ModTime()}, nil
}

// visible reports whether a directory entry type is shown to clients:
// FIFOs, sockets and devices are hidden and never opened.
func visible(mode fs.FileMode) bool {
	return mode.IsRegular() || mode.IsDir() || mode&fs.ModeSymlink != 0
}

// Lister pages through directory entries; it matches the shape of
// github.com/pkg/sftp's ListerAt.
type Lister interface {
	ListAt(ls []os.FileInfo, offset int64) (int, error)
	Close() error
}

// sliceLister serves a fixed list.
type sliceLister []fs.FileInfo

func (l sliceLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

func (sliceLister) Close() error { return nil }

// dirLister reads a directory lazily, in batches.
type dirLister struct {
	f         *os.File
	hideLinks bool // symlinks = "deny"
	entries   []fs.FileInfo
	done      bool
	err       error
}

const readDirBatch = 256

func (l *dirLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	for !l.done && int64(len(l.entries)) < offset+int64(len(ls)) {
		des, err := l.f.ReadDir(readDirBatch)
		for _, de := range des {
			if !visible(de.Type()) || (l.hideLinks && de.Type()&fs.ModeSymlink != 0) {
				continue
			}
			fi, err := de.Info()
			if err != nil {
				continue // removed while listing
			}
			l.entries = append(l.entries, fi)
		}
		if err != nil {
			l.done = true
			if err != io.EOF {
				l.err = osError(err)
			}
		}
	}
	if offset >= int64(len(l.entries)) {
		if l.err != nil {
			return 0, l.err
		}
		return 0, io.EOF
	}
	n := copy(ls, l.entries[offset:])
	if l.done && l.err == nil && offset+int64(n) >= int64(len(l.entries)) {
		return n, io.EOF
	}
	return n, nil
}

func (l *dirLister) Close() error { return l.f.Close() }
