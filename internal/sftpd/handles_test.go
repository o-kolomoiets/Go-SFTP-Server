// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// syncBuffer is a goroutine-safe audit sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// answer is the type of an answer and, for a STATUS, its code.
type answer struct {
	typ  byte
	code uint32
}

// ok reports whether a is a STATUS with SSH_FX_OK.
func (a answer) ok() bool { return a.typ == fxpStatus && a.code == uint32(sftp.ErrSSHFxOk) }

// session serves the client packets data on a flattened mount of share and
// returns each answer by request id. The last answers may be missing: Serve
// can return before they are written.
func session(t *testing.T, share string, o vfs.MountOptions, al *audit.Logger, data []byte) map[uint32]answer {
	t.Helper()
	tbl, err := vfs.Open([]vfs.MountSpec{{Name: "share", Path: share, Options: o}}, vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s, errs := tbl.Session("alice", tbl.FullAccess())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	defer s.Close()
	h := New(s, al, slog.New(slog.DiscardHandler), nil, 8)
	b := serve(t, h, data)
	if n := h.open.Load(); n != 0 {
		t.Fatalf("%d handles still open after the session", n)
	}

	got := map[uint32]answer{}
	for len(b) >= 9 {
		n := 4 + int(binary.BigEndian.Uint32(b))
		if n < 9 || n > len(b) {
			break // cut off
		}
		a := answer{typ: b[4]}
		if a.typ == fxpStatus && n >= 13 {
			a.code = binary.BigEndian.Uint32(b[9:])
		}
		if a.typ != fxpVersion { // the answer to INIT has no id
			got[binary.BigEndian.Uint32(b[5:])] = a
		}
		b = b[n:]
	}
	return got
}

// pkg/sftp serves a READ or WRITE sent after the CLOSE of its handle in
// parallel with the CLOSE, which publishes an atomic upload. The gate holds
// them until the CLOSE is answered: they fail, and neither the published
// file nor the upload's audit result changes (a data race before, found by
// FuzzRequestServer).
func TestRequestsAfterClose(t *testing.T) {
	t.Parallel()

	ps := [][]byte{
		pkt(fxpOpen, uint32(1), "n.txt", uint32(0x02|0x08), uint32(0)), // WRITE|CREAT
		pkt(fxpWrite, uint32(2), "1", uint64(0), "data"),
		pkt(fxpClose, uint32(3), "1"),
	}
	for i := range 16 {
		ps = append(ps,
			pkt(fxpWrite, uint32(10+2*i), "1", uint64(4+i), "x"),
			pkt(fxpRead, uint32(11+2*i), "1", uint64(0), uint32(8)), // a write too: the handle is an upload
		)
	}
	o := vfs.DefaultMountOptions()
	o.MinFreeSpace = 0
	o.AtomicUploads = true
	for range 25 {
		share := t.TempDir()
		var log syncBuffer
		got := session(t, share, o, audit.New(&log, slog.New(slog.DiscardHandler)), seq(ps...))
		for id, a := range got {
			if id >= 10 && a.ok() {
				t.Fatalf("request %d after the CLOSE succeeded", id)
			}
		}
		if b, err := os.ReadFile(filepath.Join(share, "n.txt")); err != nil || string(b) != "data" {
			t.Fatalf("published file = %q, %v; want %q", b, err, "data")
		}
		var upload string
		for line := range strings.Lines(log.String()) {
			if strings.Contains(line, `"event":"fs.upload"`) {
				upload = line
			}
		}
		if !strings.Contains(upload, `"result":"ok"`) {
			t.Fatalf("the upload is audited as %q", upload)
		}
	}
}

// pkg/sftp lists a directory in its parallel workers for a READ or WRITE
// sent with the directory's handle, also while it serves a READDIR. These
// listings ran at the same time and could crash the process (run with
// -race). A READ sent after the CLOSE does not list the directory (see
// Gate): it finds no handle and fails with SSH_FX_FAILURE. One that listed
// it would get SSH_FX_EOF, as the earlier requests use up the listing.
func TestDirectoryHandleInParallel(t *testing.T) {
	t.Parallel()

	share := t.TempDir()
	for i := range 600 { // more than two batches of the vfs lister
		if err := os.WriteFile(filepath.Join(share, fmt.Sprintf("f%03d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ps := [][]byte{pkt(fxpOpendir, uint32(1), "/")}
	for i := range 16 {
		ps = append(ps,
			pkt(fxpRead, uint32(10+3*i), "1", uint64(0), uint32(8)),
			pkt(fxpWrite, uint32(11+3*i), "1", uint64(0), "x"),
			pkt(fxpReaddir, uint32(12+3*i), "1"),
		)
	}
	ps = append(ps, pkt(fxpClose, uint32(100), "1"))
	for i := range 8 {
		ps = append(ps, pkt(fxpRead, uint32(101+i), "1", uint64(0), uint32(8)))
	}
	o := vfs.DefaultMountOptions()
	o.MinFreeSpace = 0
	for range 10 {
		got := session(t, share, o, audit.Discard(), seq(ps...))
		if a, ok := got[100]; ok && !a.ok() {
			t.Fatalf("CLOSE answered with %+v", a)
		}
		for id := uint32(101); id < 109; id++ {
			if a, ok := got[id]; ok && (a.typ != fxpStatus || a.code != uint32(sftp.ErrSSHFxFailure)) {
				t.Fatalf("READ %d after the CLOSE answered with %+v, want SSH_FX_FAILURE", id, a)
			}
		}
	}
}
