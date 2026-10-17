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

// readPackets reads the next n bytes from g in a goroutine.
func readPackets(g *Gate, n int) <-chan []byte {
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, n)
		if _, err := io.ReadFull(g, b); err != nil {
			b = nil
		}
		got <- b
	}()
	return got
}

func held(t *testing.T, got <-chan []byte, what string) {
	t.Helper()
	select {
	case <-got:
		t.Fatalf("%s passed the gate too early", what)
	case <-time.After(50 * time.Millisecond):
	}
}

func passed(t *testing.T, got <-chan []byte, want []byte, what string) {
	t.Helper()
	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Fatalf("%s = %x, want %x", what, b, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s is still held", what)
	}
}

// A request with a handle waits for the answer to the latest OPEN, and an
// OPEN for the answers to every earlier request (see Gate); other requests
// pass at once. Answers are counted, so request ids do not matter.
func TestGateOrdersOpens(t *testing.T) {
	t.Parallel()

	read := pkt(fxpRead, uint32(7), "1", uint64(0), uint32(10))
	open := pkt(fxpOpen, uint32(7), "a", uint32(2), uint32(0)) // the same id
	stat := pkt(fxpStat, uint32(8), "a")
	write := pkt(fxpWrite, uint32(9), "2", uint64(0), "x")
	short := []byte{0, 0, 0, 2, 99, 1} // a short packet passes whole
	var out bytes.Buffer
	g := NewGate(rwc{bytes.NewReader(seq(read, open, stat, write, short)), &out})
	answer := func(id uint32) {
		t.Helper()
		a := pkt(fxpStatus, id, uint32(0), "", "")
		// Answers may be written in parts.
		for _, part := range [][]byte{a[:3], a[3:7], a[7:]} {
			if _, err := g.Write(part); err != nil {
				t.Fatal(err)
			}
		}
	}

	passed(t, readPackets(g, len(read)), read, "READ")
	got := readPackets(g, len(open))
	held(t, got, "OPEN before the earlier READ is answered")
	answer(7)
	passed(t, got, open, "OPEN")

	passed(t, readPackets(g, len(stat)), stat, "STAT")
	got = readPackets(g, len(write))
	held(t, got, "WRITE before the OPEN is answered")
	answer(7)
	passed(t, got, write, "WRITE")
	passed(t, readPackets(g, len(short)), short, "short packet")
	if out.Len() != 2*len(pkt(fxpStatus, uint32(7), uint32(0), "", "")) {
		t.Fatalf("answers were not passed on: %x", out.Bytes())
	}
}

func TestGateCloseReleases(t *testing.T) {
	t.Parallel()

	opendir := pkt(fxpOpendir, uint32(1), "/")
	g := NewGate(rwc{bytes.NewReader(seq(opendir, pkt(fxpReaddir, uint32(2), "1"))), io.Discard})
	passed(t, readPackets(g, len(opendir)), opendir, "OPENDIR")
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

// A request with a handle also waits for the answer to the latest CLOSE:
// pkg/sftp would serve a READ or WRITE in parallel with the CLOSE of its
// handle. CLOSEs sent in a row pass one at a time.
func TestGateOrdersCloses(t *testing.T) {
	t.Parallel()

	close1 := pkt(fxpClose, uint32(1), "1")
	stat := pkt(fxpStat, uint32(2), "a")
	close2 := pkt(fxpClose, uint32(3), "2")
	write := pkt(fxpWrite, uint32(4), "1", uint64(0), "x")
	g := NewGate(rwc{bytes.NewReader(seq(close1, stat, close2, write)), io.Discard})
	answer := func(id uint32) {
		t.Helper()
		if _, err := g.Write(pkt(fxpStatus, id, uint32(0), "", "")); err != nil {
			t.Fatal(err)
		}
	}

	passed(t, readPackets(g, len(close1)), close1, "CLOSE")
	passed(t, readPackets(g, len(stat)), stat, "STAT")
	got := readPackets(g, len(close2))
	held(t, got, "CLOSE before the earlier CLOSE is answered")
	answer(1)
	passed(t, got, close2, "second CLOSE")

	got = readPackets(g, len(write))
	held(t, got, "WRITE before the CLOSE is answered")
	answer(2)
	held(t, got, "WRITE before the second CLOSE is answered")
	answer(3)
	passed(t, got, write, "WRITE")
}
