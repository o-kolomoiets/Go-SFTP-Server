// SPDX-License-Identifier: Apache-2.0

// Package testutil has helpers for tests only.
package testutil

import (
	"bytes"
	"net"
	"sync"
)

// AsyncConn wraps one end of a net.Pipe so that Write does not wait for the
// peer to read, like a socket with a send buffer. Without it an SSH
// handshake over net.Pipe deadlocks: both sides write their version line
// first. A goroutine forwards the writes in order; Close stops it.
type AsyncConn struct {
	net.Conn
	queue chan []byte
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

// NewAsyncConn wraps c.
func NewAsyncConn(c net.Conn) *AsyncConn {
	a := &AsyncConn{Conn: c, queue: make(chan []byte, 1024), done: make(chan struct{})}
	a.wg.Go(a.forward)
	return a
}

func (a *AsyncConn) forward() {
	for {
		select {
		case b := <-a.queue:
			if _, err := a.Conn.Write(b); err != nil {
				return
			}
		case <-a.done:
			return
		}
	}
}

// Write queues a copy of p.
func (a *AsyncConn) Write(p []byte) (int, error) {
	select {
	case <-a.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case a.queue <- bytes.Clone(p):
		return len(p), nil
	case <-a.done:
		return 0, net.ErrClosed
	}
}

// Close closes the connection and waits for the forwarding goroutine.
func (a *AsyncConn) Close() error {
	a.once.Do(func() { close(a.done) })
	err := a.Conn.Close()
	a.wg.Wait()
	return err
}
