// SPDX-License-Identifier: Apache-2.0

// Package sftpd adapts github.com/pkg/sftp's request server to the VFS:
// it enforces the handle limit, maps errors to fixed client messages and
// writes audit events.
package sftpd

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// DefaultMaxHandles bounds open files and directories per SFTP session.
const DefaultMaxHandles = 64

var extensionsOnce sync.Once

// setExtensions advertises only the extensions that are implemented (the
// pkg/sftp default also lists hardlink). SetSFTPExtensions writes a package
// global, so it runs exactly once, before any request server.
func setExtensions() {
	extensionsOnce.Do(func() {
		exts := []string{"posix-rename@openssh.com"}
		if vfs.StatFSSupported {
			exts = append(exts, "statvfs@openssh.com")
		}
		if err := sftp.SetSFTPExtensions(exts...); err != nil {
			panic(err)
		}
	})
}

// virtualID is the uid and gid of every file as clients see it: host
// accounts are never shown. Long listings show the user's own name.
const virtualID = 1000

// ownedInfo hides the host owner of a file.
type ownedInfo struct{ os.FileInfo }

func (ownedInfo) Uid() uint32 { return virtualID } //nolint:revive // name required by sftp.FileInfoUidGid
func (ownedInfo) Gid() uint32 { return virtualID }
func (ownedInfo) Sys() any    { return nil }

// Handler serves one SFTP session.
type Handler struct {
	s          *vfs.Session
	audit      *audit.Logger
	log        *slog.Logger
	maxHandles int32
	open       atomic.Int32
}

// New returns a handler for the session. maxHandles <= 0 means DefaultMaxHandles.
func New(s *vfs.Session, al *audit.Logger, log *slog.Logger, maxHandles int) *Handler {
	setExtensions()
	if maxHandles <= 0 {
		maxHandles = DefaultMaxHandles
	}
	return &Handler{s: s, audit: al, log: log, maxHandles: int32(min(maxHandles, 1<<20))}
}

// Handlers returns the pkg/sftp handler set.
func (h *Handler) Handlers() sftp.Handlers {
	return sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}
}

func (h *Handler) acquire() bool {
	if h.open.Add(1) > h.maxHandles {
		h.open.Add(-1)
		return false
	}
	return true
}

func (h *Handler) release() { h.open.Add(-1) }

// fail maps err for the client, logs the original, and audits denials.
func (h *Handler) fail(op, path string, err error) error {
	result, st := toStatus(err)
	h.log.Debug("sftp request failed", "op", op, "path", path, "err", err)
	if result == "denied" {
		h.audit.Event("fs.denied", slog.String("op", op), slog.String("path", path), slog.String("reason", st.Error()), slog.String("result", "denied"))
	}
	return st
}

// Fileread implements sftp.FileReader.
func (h *Handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if !h.acquire() {
		return nil, h.fail("fs.download", r.Filepath, errTooManyHandles)
	}
	f, err := h.s.OpenRead(r.Filepath)
	if err != nil {
		h.release()
		return nil, h.fail("fs.download", r.Filepath, err)
	}
	return &reader{h: h, f: f, path: r.Filepath, start: time.Now()}, nil
}

// Filewrite implements sftp.FileWriter.
func (h *Handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if !h.audit.Healthy() {
		return nil, h.fail("fs.upload", r.Filepath, errAuditUnavailable)
	}
	if !h.acquire() {
		return nil, h.fail("fs.upload", r.Filepath, errTooManyHandles)
	}
	pf := r.Pflags()
	fl := vfs.OpenFlags{Read: pf.Read, Write: pf.Write, Append: pf.Append, Creat: pf.Creat, Trunc: pf.Trunc, Excl: pf.Excl}
	wh, err := h.s.OpenWrite(r.Filepath, fl)
	if err != nil {
		h.release()
		return nil, h.fail("fs.upload", r.Filepath, err)
	}
	w := &writer{h: h, wh: wh, requested: r.Filepath, flags: flagString(fl), start: time.Now()}
	// FSTAT/FSETSTAT on this handle are resolved through r.Filepath: point it
	// at the file actually written, so "put -p" updates the copy and never
	// the original.
	r.Filepath = wh.Path()
	return w, nil
}

// Filecmd implements sftp.FileCmder.
func (h *Handler) Filecmd(r *sftp.Request) error {
	op := "fs." + strings.ToLower(r.Method)
	if r.Method == "Symlink" || r.Method == "Link" {
		return h.fail(op, r.Filepath, vfs.ErrUnsupported)
	}
	if !h.audit.Healthy() {
		return h.fail(op, r.Filepath, errAuditUnavailable)
	}
	var err error
	attrs := []slog.Attr{slog.String("path", r.Filepath)}
	switch r.Method {
	case "Setstat":
		err = h.setstat(r)
	case "Rename":
		var final string
		final, err = h.s.Rename(r.Filepath, r.Target, false)
		attrs = append(attrs, slog.String("target_path", r.Target), slog.String("final_path", final))
	case "Mkdir":
		err = h.s.Mkdir(r.Filepath)
	case "Rmdir":
		err = h.s.Rmdir(r.Filepath)
	case "Remove":
		err = h.s.Remove(r.Filepath)
	default:
		err = errUnsupportedMethod
	}
	if err != nil {
		return h.fail(op, r.Filepath, err)
	}
	h.audit.Event(op, append(attrs, slog.String("result", "ok"))...)
	return nil
}

// PosixRename implements sftp.PosixRenameFileCmder.
func (h *Handler) PosixRename(r *sftp.Request) error {
	if !h.audit.Healthy() {
		return h.fail("fs.rename", r.Filepath, errAuditUnavailable)
	}
	final, err := h.s.Rename(r.Filepath, r.Target, true)
	if err != nil {
		return h.fail("fs.rename", r.Filepath, err)
	}
	conflict := vfs.ConflictNone
	if final != r.Target {
		conflict = vfs.ConflictRenamed
	}
	h.audit.Event("fs.rename", slog.String("path", r.Filepath), slog.String("target_path", r.Target),
		slog.String("final_path", final), slog.String("conflict", conflict), slog.String("result", "ok"))
	return nil
}

func (h *Handler) setstat(r *sftp.Request) error {
	af := r.AttrFlags()
	if !af.Size && !af.Acmodtime {
		return nil // permissions and ownership are not settable; ignore quietly
	}
	fa := r.Attributes()
	if fa == nil {
		return errBadAttributes
	}
	var a vfs.Attrs
	if af.Size {
		if fa.Size > 1<<62 {
			return errBadAttributes
		}
		a.Size, a.HasSize = int64(fa.Size), true
	}
	if af.Acmodtime {
		a.Atime, a.Mtime, a.HasTimes = time.Unix(int64(fa.Atime), 0), time.Unix(int64(fa.Mtime), 0), true
	}
	return h.s.Setstat(r.Filepath, a)
}

// Filelist implements sftp.FileLister.
func (h *Handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		if !h.acquire() {
			return nil, h.fail("fs.list", r.Filepath, errTooManyHandles)
		}
		l, err := h.s.ReadDir(r.Filepath)
		if err != nil {
			h.release()
			return nil, h.fail("fs.list", r.Filepath, err)
		}
		h.audit.Event("fs.list", slog.String("path", r.Filepath), slog.String("result", "ok"))
		return &lister{Lister: l, h: h}, nil
	case "Stat":
		return h.stat(r.Filepath, h.s.Stat)
	default: // Readlink: links are never exposed
		return nil, h.fail("fs.readlink", r.Filepath, vfs.ErrUnsupported)
	}
}

// Lstat implements sftp.LstatFileLister.
func (h *Handler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	return h.stat(r.Filepath, h.s.Lstat)
}

// RealPath implements sftp.RealPathFileLister: only virtual paths are returned.
func (h *Handler) RealPath(p string) (string, error) {
	return h.s.RealPath(p), nil
}

// LookupUserName implements sftp.NameLookupFileLister for long listings.
func (h *Handler) LookupUserName(uid string) string { return h.lookupName(uid) }

// LookupGroupName implements sftp.NameLookupFileLister for long listings.
func (h *Handler) LookupGroupName(gid string) string { return h.lookupName(gid) }

func (h *Handler) lookupName(id string) string {
	if id == strconv.Itoa(virtualID) {
		return h.s.User()
	}
	return id
}

// StatVFS implements sftp.StatVFSFileCmder (statvfs@openssh.com, "df").
func (h *Handler) StatVFS(r *sftp.Request) (*sftp.StatVFS, error) {
	st, err := h.s.StatFS(r.Filepath)
	if err != nil {
		return nil, h.fail("fs.statvfs", r.Filepath, err)
	}
	const stRdonly, stNosuid = 0x1, 0x2 // statvfs f_flag bits
	flag := uint64(stNosuid)
	if st.ReadOnly {
		flag |= stRdonly
	}
	return &sftp.StatVFS{
		Bsize:   st.BlockSize,
		Frsize:  st.FragmentSize,
		Blocks:  st.Blocks,
		Bfree:   st.BlocksFree,
		Bavail:  st.BlocksAvail,
		Files:   st.Files,
		Ffree:   st.FilesFree,
		Favail:  st.FilesAvail,
		Fsid:    st.ID,
		Flag:    flag,
		Namemax: st.NameMax,
	}, nil
}

func (h *Handler) stat(p string, fn func(string) (os.FileInfo, error)) (sftp.ListerAt, error) {
	fi, err := fn(p)
	if err != nil {
		return nil, h.fail("fs.stat", p, err)
	}
	h.audit.Event("fs.stat", slog.String("path", p), slog.String("result", "ok"))
	return statLister{ownedInfo{fi}}, nil
}

type statLister []os.FileInfo

func (l statLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	return copy(ls, l[offset:]), io.EOF
}

type lister struct {
	vfs.Lister
	h    *Handler
	once sync.Once
}

func (l *lister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	n, err := l.Lister.ListAt(ls, offset)
	for i := range ls[:n] {
		ls[i] = ownedInfo{ls[i]}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		_, st := toStatus(err)
		return n, st
	}
	return n, err
}

func (l *lister) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Lister.Close()
		l.h.release()
	})
	return err
}

func flagString(fl vfs.OpenFlags) string {
	var parts []string
	for _, f := range []struct {
		on   bool
		name string
	}{
		{fl.Read, "READ"},
		{fl.Write, "WRITE"},
		{fl.Append, "APPEND"},
		{fl.Creat, "CREAT"},
		{fl.Trunc, "TRUNC"},
		{fl.Excl, "EXCL"},
	} {
		if f.on {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, "+")
}
