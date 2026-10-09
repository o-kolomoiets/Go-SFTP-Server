// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"bytes"
	"io"
	"testing"
	"time"
)

type rwc struct {
	io.Reader
	io.Writer
}

func (rwc) Close() error { return nil }

// A WRITE that a client sends before the answer to its OPEN waits for that
// answer (see Gate); other packets pass at once.
func TestGateHoldsHandlePackets(t *testing.T) {
	t.Parallel()

	in := seq(
		pkt(fxpOpen, uint32(7), "a", uint32(2), uint32(0)),
		pkt(fxpStat, uint32(8), "a"),
		pkt(fxpWrite, uint32(9), "1", uint64(0), "x"),
		[]byte{0, 0, 0, 2, 99, 1}, // a short packet passes whole
	)
	var out bytes.Buffer
	g := NewGate(rwc{bytes.NewReader(in), &out})
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(g, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	open := pkt(fxpOpen, uint32(7), "a", uint32(2), uint32(0))
	stat := pkt(fxpStat, uint32(8), "a")
	if got := read(len(open) + len(stat)); !bytes.Equal(got, seq(open, stat)) {
		t.Fatalf("read %x", got)
	}
	write := pkt(fxpWrite, uint32(9), "1", uint64(0), "x")
	got := make(chan []byte)
	go func() {
		b := make([]byte, len(write))
		_, _ = io.ReadFull(g, b)
		got <- b
	}()
	select {
	case <-got:
		t.Fatal("WRITE passed before the OPEN was answered")
	case <-time.After(50 * time.Millisecond):
	}
	// The answer to another request does not release it; the HANDLE
	// answer to id 7, written in two parts, does.
	if _, err := g.Write(pkt(101, uint32(8), uint32(0), "", "")); err != nil {
		t.Fatal(err)
	}
	answer := pkt(102, uint32(7), "1")
	_, _ = g.Write(answer[:6])
	select {
	case <-got:
		t.Fatal("WRITE passed before the OPEN was answered")
	case <-time.After(50 * time.Millisecond):
	}
	_, _ = g.Write(answer[6:])
	if b := <-got; !bytes.Equal(b, write) {
		t.Fatalf("WRITE = %x", b)
	}
	if b := read(6); !bytes.Equal(b, []byte{0, 0, 0, 2, 99, 1}) {
		t.Fatalf("short packet = %x", b)
	}
	if !bytes.HasPrefix(out.Bytes(), pkt(101, uint32(8), uint32(0), "", "")) {
		t.Fatal("responses were not passed on")
	}
}

func TestGateCloseReleases(t *testing.T) {
	t.Parallel()

	g := NewGate(rwc{bytes.NewReader(seq(pkt(fxpOpendir, uint32(1), "/"), pkt(fxpReaddir, uint32(2), "1"))), io.Discard})
	if _, err := io.ReadFull(g, make([]byte, len(pkt(fxpOpendir, uint32(1), "/")))); err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() {
		_, err := g.Read(make([]byte, 64))
		done <- err
	}()
	_ = g.Close()
	if err := <-done; err == nil {
		t.Fatal("a held READDIR passed after Close")
	}
}
