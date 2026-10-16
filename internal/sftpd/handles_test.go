// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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

// session serves the client packets data on a flattened mount of share and
// returns the type of each answer by request id; a STATUS with SSH_FX_OK is
// 0. The last answers may be missing: Serve can return before they are
// written.
func session(t *testing.T, share string, o vfs.MountOptions, al *audit.Logger, data []byte) map[uint32]byte {
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

	got := map[uint32]byte{}
	for len(b) >= 9 {
		n := 4 + int(binary.BigEndian.Uint32(b))
		if n < 9 || n > len(b) {
			break // cut off
		}
		typ := b[4]
		if typ == fxpStatus && n >= 13 && binary.BigEndian.Uint32(b[9:]) == 0 {
			typ = 0
		}
		if typ != fxpVersion { // the answer to INIT has no id
			got[binary.BigEndian.Uint32(b[5:])] = typ
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
		for id, typ := range got {
			if id >= 10 && typ == 0 {
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
