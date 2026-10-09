// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// SFTP v3 packet types the gate looks at.
const (
	typeOpen     = 3
	typeClose    = 4
	typeRead     = 5
	typeWrite    = 6
	typeFstat    = 8
	typeFsetstat = 10
	typeOpendir  = 11
	typeReaddir  = 12
)

// maxPacket is pkg/sftp's limit; longer packets are passed on unread for
// pkg/sftp to refuse.
const maxPacket = 256 * 1024

var errGateClosed = errors.New("sftp connection closed")

// Gate wraps the connection of a pkg/sftp request server. pkg/sftp v1.13
// registers the handle of an OPEN before it opens the file, in another
// goroutine than the one serving READ and WRITE. A client that sends a
// request with a guessed handle while an OPEN is in progress races with it
// (Request.Method is written and read unsynchronized), and a torn read can
// crash the process.
//
// The gate keeps OPEN and OPENDIR apart from every request that uses a
// handle: an OPEN passes once every earlier request is answered, and a
// request with a handle once the latest OPEN is answered. pkg/sftp answers
// in request order, so the gate counts requests and answers instead of
// trusting the ids clients choose. Clients learn handles from the answer
// to their OPEN, so they are not delayed.
type Gate struct {
	r io.Reader
	w io.Writer
	c io.Closer

	mu       sync.Mutex
	cond     sync.Cond
	sent     uint64 // requests passed to the server
	answered uint64 // answers written
	lastOpen uint64 // number of the latest OPEN or OPENDIR (1-based)
	closed   bool

	buf []byte // the packet being passed to the server
	in  []byte // its unread part

	hdr  [9]byte // length, type and id of the response being written
	nhdr int
	skip int // bytes of that response after hdr
}

// NewGate wraps rwc.
func NewGate(rwc io.ReadWriteCloser) *Gate {
	g := &Gate{r: rwc, w: rwc, c: rwc}
	g.cond.L = &g.mu
	return g
}

// Read passes the client's packets on one at a time.
func (g *Gate) Read(p []byte) (int, error) {
	if len(g.in) == 0 {
		if err := g.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, g.in)
	g.in = g.in[n:]
	return n, nil
}

func (g *Gate) next() error {
	if cap(g.buf) < 4 {
		g.buf = make([]byte, 4, 64*1024)
	}
	g.buf = g.buf[:4]
	if _, err := io.ReadFull(g.r, g.buf); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(g.buf)
	if n == 0 || n > maxPacket {
		g.in = g.buf // pkg/sftp refuses the length; read nothing more
		return nil
	}
	if size := 4 + int(n); cap(g.buf) < size {
		b := make([]byte, size)
		copy(b, g.buf)
		g.buf = b
	} else {
		g.buf = g.buf[:size]
	}
	if _, err := io.ReadFull(g.r, g.buf[4:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err := g.admit(g.buf[4]); err != nil {
		return err
	}
	g.in = g.buf
	return nil
}

// admit holds an OPEN or OPENDIR until every earlier request is answered,
// and a request with a handle until the latest OPEN or OPENDIR is.
func (g *Gate) admit(typ byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var wait func() bool
	switch typ {
	case typeOpen, typeOpendir:
		wait = func() bool { return g.answered < g.sent }
	case typeClose, typeRead, typeWrite, typeFstat, typeFsetstat, typeReaddir:
		wait = func() bool { return g.answered < g.lastOpen }
	default:
		wait = func() bool { return false }
	}
	for wait() && !g.closed {
		g.cond.Wait()
	}
	if g.closed {
		return errGateClosed
	}
	g.sent++
	if typ == typeOpen || typ == typeOpendir {
		g.lastOpen = g.sent
	}
	return nil
}

// Write passes the server's responses on and notes which requests they
// answer.
func (g *Gate) Write(p []byte) (int, error) {
	g.scan(p)
	n, err := g.w.Write(p)
	if err != nil {
		g.shut()
	}
	return n, err
}

func (g *Gate) scan(p []byte) {
	for len(p) > 0 {
		if g.skip > 0 {
			n := min(g.skip, len(p))
			g.skip -= n
			p = p[n:]
			continue
		}
		n := copy(g.hdr[g.nhdr:], p)
		g.nhdr += n
		p = p[n:]
		if g.nhdr < len(g.hdr) {
			return
		}
		g.nhdr = 0
		g.skip = max(int(binary.BigEndian.Uint32(g.hdr[:4]))-5, 0)
		g.mu.Lock()
		g.answered++
		g.cond.Broadcast()
		g.mu.Unlock()
	}
}

func (g *Gate) shut() {
	g.mu.Lock()
	g.closed = true
	g.cond.Broadcast()
	g.mu.Unlock()
}

// Close closes the connection and releases a held packet.
func (g *Gate) Close() error {
	g.shut()
	return g.c.Close()
}
