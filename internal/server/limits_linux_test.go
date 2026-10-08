// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// TestSilentFlood is the M3 load test: 1000 TCP connections from one address
// that never speak SSH. At most max_connections_per_ip are admitted, and a
// client from another address still logs in.
func TestSilentFlood(t *testing.T) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil || lim.Cur < 4096 {
		t.Skipf("file limit %d too low", lim.Cur)
	}
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.MaxConnectionsPerIP = 16
		c.HandshakeTimeout = time.Minute
	}})

	var (
		mu       sync.Mutex
		held     []net.Conn
		admitted int
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, 64)
	for range 1000 {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			c, ok := silentDial(t, e.addr, &net.Dialer{})
			mu.Lock()
			defer mu.Unlock()
			if ok {
				admitted++
				held = append(held, c)
			}
		})
	}
	wg.Wait()
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	t.Logf("%d of 1000 silent connections admitted", admitted)
	if admitted > 16 {
		t.Errorf("%d silent connections admitted, want at most 16", admitted)
	}

	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 10 * time.Second}
	nc, err := d.DialContext(context.Background(), "tcp", e.addr)
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.2: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, e.addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(e.userKey)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey),
	})
	if err != nil {
		t.Fatalf("legitimate client refused during the flood: %v", err)
	}
	ssh.NewClient(conn, chans, reqs).Close()
}
