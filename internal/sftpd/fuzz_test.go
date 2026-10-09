// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"encoding/binary"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// SFTP v3 packet types (draft-ietf-secsh-filexfer-02).
const (
	fxpInit     = 1
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpLstat    = 7
	fxpFstat    = 8
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRealpath = 16
	fxpStat     = 17
	fxpRename   = 18
	fxpReadlink = 19
	fxpSymlink  = 20
	fxpExtended = 200
)

// pkt builds one SFTP packet from uint32, uint64, string and []byte fields.
func pkt(typ byte, fields ...any) []byte {
	b := []byte{typ}
	for _, f := range fields {
		switch v := f.(type) {
		case uint32:
			b = binary.BigEndian.AppendUint32(b, v)
		case uint64:
			b = binary.BigEndian.AppendUint64(b, v)
		case string:
			b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
			b = append(b, v...)
		case []byte:
			b = append(b, v...)
		}
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func seq(ps ...[]byte) []byte {
	var out []byte
	for _, p := range ps {
		out = append(out, p...)
	}
	return out
}

// sftpPipe is the server's side of a connection: it reads what the client
// wrote and writes responses that a goroutine discards.
type sftpPipe struct {
	io.Reader
	io.WriteCloser
}

// FuzzRequestServer (ROADMAP §8.3) feeds arbitrary SFTP v3 packets to a
// request server with the real handlers on a temporary mount. Upstream
// does not fuzz the server side of pkg/sftp. Invariants: no panic, no
// hang, nothing outside the mount changes, no links appear, no handle
// stays open after the session.
func FuzzRequestServer(f *testing.F) {
	const (
		read  = 0x01
		write = 0x02
		appnd = 0x04
		creat = 0x08
		trunc = 0x10
		excl  = 0x20
	)
	noAttrs := uint32(0)
	f.Add(byte(0), seq(
		pkt(fxpOpen, uint32(1), "a.txt", uint32(write|creat|trunc), noAttrs),
		pkt(fxpWrite, uint32(2), "1", uint64(0), "data"),
		pkt(fxpFsetstat, uint32(3), "1", uint32(1), uint64(2)),
		pkt(fxpFstat, uint32(4), "1"),
		pkt(fxpClose, uint32(5), "1"),
		pkt(fxpRead, uint32(6), "1", uint64(0), uint32(10)),
	))
	f.Add(byte(1), seq(
		pkt(fxpOpen, uint32(1), "../outside/secret.txt", uint32(write|trunc), noAttrs),
		pkt(fxpOpen, uint32(2), "evil/secret.txt", uint32(read|write), noAttrs),
		pkt(fxpWrite, uint32(3), "1", uint64(0), "pwned"),
		pkt(fxpWrite, uint32(4), "2", uint64(0), "pwned"),
		pkt(fxpRename, uint32(5), "a.txt", "../outside/a.txt"),
		pkt(fxpSymlink, uint32(6), "/etc/passwd", "link"),
		pkt(fxpExtended, uint32(7), "hardlink@openssh.com", "a.txt", "hard"),
		pkt(fxpExtended, uint32(8), "posix-rename@openssh.com", "a.txt", "evil/b.txt"),
		pkt(fxpRemove, uint32(9), "evil/secret.txt"),
		pkt(fxpSetstat, uint32(10), "evil/secret.txt", uint32(1), uint64(0)),
	))
	f.Add(byte(2), seq(
		pkt(fxpMkdir, uint32(1), "d", noAttrs),
		pkt(fxpOpendir, uint32(2), "/"),
		pkt(fxpReaddir, uint32(3), "1"),
		pkt(fxpReaddir, uint32(4), "1"),
		pkt(fxpClose, uint32(5), "1"),
		pkt(fxpRmdir, uint32(6), "d"),
		pkt(fxpRealpath, uint32(7), ".."),
		pkt(fxpStat, uint32(8), "a.txt"),
		pkt(fxpLstat, uint32(9), "evil"),
		pkt(fxpReadlink, uint32(10), "evil"),
		pkt(fxpExtended, uint32(11), "statvfs@openssh.com", "/"),
	))
	f.Add(byte(3), seq(
		pkt(fxpOpen, uint32(1), "a.txt", uint32(write|appnd), noAttrs),
		pkt(fxpWrite, uint32(2), "1", uint64(0), "x"),
		pkt(fxpOpen, uint32(3), "a.txt", uint32(write|creat|excl), noAttrs),
		pkt(fxpOpen, uint32(4), ".gosftpd-0.part", uint32(write|creat), noAttrs),
		pkt(fxpWrite, uint32(5), "1", uint64(1<<40), "sparse"),
	))
	f.Add(byte(4), []byte{0xff, 0xff, 0xff, 0xff, 1})
	// Review findings: the gate must not trust request ids (an answer to
	// another request with the OPEN's id), and must keep a handle request
	// sent before an OPEN from running during it.
	f.Add(byte(1), seq(
		pkt(fxpOpen, uint32(1), "a.txt", uint32(read), noAttrs),
		pkt(fxpRead, uint32(9), "1", uint64(0), uint32(8)),
		pkt(fxpOpen, uint32(9), "a.txt", uint32(write|creat), noAttrs),
		pkt(fxpRead, uint32(10), "2", uint64(0), uint32(8)),
		pkt(fxpWrite, uint32(11), "2", uint64(0), "x"),
	))
	busy := []([]byte){pkt(fxpOpen, uint32(1), "b.txt", uint32(write|creat|trunc), noAttrs)}
	for i := range 12 {
		busy = append(busy, pkt(fxpWrite, uint32(2+i), "1", uint64(i*4096), string(make([]byte, 4096))))
	}
	busy = append(busy,
		pkt(fxpRead, uint32(20), "2", uint64(0), uint32(8)),
		pkt(fxpWrite, uint32(21), "2", uint64(0), "x"),
		pkt(fxpOpen, uint32(22), "a.txt", uint32(read|write), noAttrs),
	)
	f.Add(byte(1), seq(busy...))

	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		base := t.TempDir()
		share := filepath.Join(base, "share")
		outside := filepath.Join(base, "outside")
		for _, d := range []string{share, outside} {
			if err := os.Mkdir(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for p, s := range map[string]string{filepath.Join(share, "a.txt"): "original", filepath.Join(outside, "secret.txt"): "secret"} {
			if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		symlink := os.Symlink("../outside", filepath.Join(share, "evil")) == nil

		o := vfs.DefaultMountOptions()
		o.MinFreeSpace = 0
		o.MaxFileSize = 1 << 20
		o.OnConflict = []vfs.ConflictPolicy{vfs.ConflictRename, vfs.ConflictOverwrite, vfs.ConflictVersion, vfs.ConflictReject}[mode%4]
		o.AtomicUploads = mode&4 != 0
		tbl, err := vfs.Open([]vfs.MountSpec{{Name: "share", Path: share, Options: o}}, vfs.Options{Flatten: mode&8 == 0})
		if err != nil {
			t.Fatal(err)
		}
		defer tbl.Close()
		s, errs := tbl.Session("alice", tbl.FullAccess())
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		defer s.Close()
		h := New(s, audit.Discard(), slog.New(slog.DiscardHandler), 8)

		in, client := io.Pipe()
		resp, out := io.Pipe()
		go func() { _, _ = io.Copy(io.Discard, resp) }()
		rs := sftp.NewRequestServer(NewGate(sftpPipe{in, out}), h.Handlers(), sftp.WithStartDirectory("/"))
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = rs.Serve()
			_ = out.Close()
		}()
		go func() {
			_, _ = client.Write(pkt(fxpInit, uint32(3)))
			_, _ = client.Write(data)
			_ = client.Close()
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the request server did not finish")
		}
		_ = rs.Close()
		_ = in.CloseWithError(io.EOF)

		if got, err := os.ReadFile(filepath.Join(outside, "secret.txt")); err != nil || string(got) != "secret" {
			t.Fatalf("the file outside the mount changed: %q, %v", got, err)
		}
		for dir, n := range map[string]int{outside: 1, base: 2} {
			if des, err := os.ReadDir(dir); err != nil || len(des) != n {
				t.Fatalf("entries in %s: %v, %v", dir, des, err)
			}
		}
		links := 0
		err = filepath.WalkDir(share, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink != 0 {
				links++
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		// Clients may remove or replace the planted link, never add one.
		if limit := map[bool]int{true: 1}[symlink]; links > limit {
			t.Fatalf("%d symlinks in the mount, at most %d (clients cannot create links)", links, limit)
		}
		if n := h.open.Load(); n != 0 {
			t.Fatalf("%d handles still open after the session", n)
		}
	})
}
