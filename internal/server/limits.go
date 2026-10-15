// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Reasons a connection is refused before the SSH handshake: right after
// accept, or, for a connection from a trusted proxy, once its PROXY
// protocol header is read (ADR 0011).
const (
	rejectBanned      = "banned"
	rejectMaxConns    = "max_connections"
	rejectPerIP       = "max_connections_per_ip"
	rejectPreauth     = "max_preauth_connections"
	rejectAudit       = "audit_unavailable"
	rejectProxyHeader = "proxy_header" // a trusted proxy sent no valid header
	// rejectUntrustedProxy ends a connection whose first bytes after the
	// banner are a PROXY protocol header that is not trusted; it is also
	// the connection's result in gosftpd_connections_total.
	rejectUntrustedProxy = "untrusted_proxy"
)

// limiter counts connections: in total, per source (auth.SourceKey) and
// before authentication. A reload changes its limits; connections above a
// lowered limit stay, and new ones are refused until the count is below it.
//
// Admission has two phases (ADR 0011). In the accept loop a connection
// takes its connection and pre-authentication slots and, from a peer that
// is not a trusted proxy, the slot for the peer. A connection from a
// trusted proxy takes the slot for its client once the PROXY protocol
// header names it (addSource).
type limiter struct {
	mu                                 sync.Mutex
	maxConns, maxPerSource, maxPreauth int
	total, preauth                     int
	sources                            map[netip.Prefix]int
}

func newLimiter(maxConns, maxPerSource, maxPreauth int) *limiter {
	l := &limiter{sources: make(map[netip.Prefix]int)}
	l.setLimits(maxConns, maxPerSource, maxPreauth)
	return l
}

func (l *limiter) setLimits(maxConns, maxPerSource, maxPreauth int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxConns, l.maxPerSource, l.maxPreauth = maxConns, maxPerSource, maxPreauth
}

// admission is a connection's share of the limits.
type admission struct {
	l *limiter
	// trusted is set at accept for a connection from a trusted proxy,
	// which must begin with a PROXY protocol header.
	trusted bool
	src     netip.Prefix // guarded by l.mu; invalid while no source slot is held
	preauth atomic.Bool
}

// admit takes a connection slot, a pre-authentication slot and, when src is
// valid, the slot for src; or it reports which limit is reached. src is
// invalid for non-IP connections and for trusted proxies, whose clients
// take their slot later (addSource).
func (l *limiter) admit(src netip.Prefix) (*admission, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxConns {
		return nil, rejectMaxConns
	}
	if src.IsValid() && l.sources[src] >= l.maxPerSource {
		return nil, rejectPerIP
	}
	if l.preauth >= l.maxPreauth {
		return nil, rejectPreauth
	}
	l.total++
	l.preauth++
	a := &admission{l: l}
	a.takeSource(src)
	a.preauth.Store(true)
	return a, ""
}

// addSource takes the slot for src, the client a trusted proxy names in
// its header (or the proxy itself for LOCAL and UNKNOWN), or reports that
// src has reached its limit. A connection holds at most one source slot.
func (a *admission) addSource(src netip.Prefix) string {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if !src.IsValid() || a.src.IsValid() {
		return ""
	}
	if l.sources[src] >= l.maxPerSource {
		return rejectPerIP
	}
	a.takeSource(src)
	return ""
}

// takeSource counts the connection for src, if valid; l.mu must be held.
func (a *admission) takeSource(src netip.Prefix) {
	if src.IsValid() {
		a.src = src
		a.l.sources[src]++
	}
}

// authenticated frees the pre-authentication slot.
func (a *admission) authenticated() {
	if a.preauth.CompareAndSwap(true, false) {
		a.l.mu.Lock()
		a.l.preauth--
		a.l.mu.Unlock()
	}
}

// release frees every slot the connection holds.
func (a *admission) release() {
	a.authenticated()
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if a.src.IsValid() {
		if l.sources[a.src]--; l.sources[a.src] <= 0 {
			delete(l.sources, a.src)
		}
	}
}

// rejectLog limits conn.reject events, so that a flood of refused
// connections cannot flood the audit log: at most rejectBurst events per
// second; the next event reports how many were left out.
type rejectLog struct {
	mu         sync.Mutex
	window     time.Time
	n          int
	suppressed int
}

const rejectBurst = 10

// allow reports whether an event may be written now and how many were
// suppressed before it.
func (r *rejectLog) allow(now time.Time) (bool, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.window) >= time.Second {
		r.window, r.n = now, 0
	}
	if r.n >= rejectBurst {
		r.suppressed++
		return false, 0
	}
	r.n++
	s := r.suppressed
	r.suppressed = 0
	return true, s
}

// warnLimit lets a warning through at most once a minute, so that a
// misconfigured proxy cannot flood the operational log.
type warnLimit struct {
	mu   sync.Mutex
	next time.Time
	held int
}

// allow reports whether the warning may be logged now and how many were
// held back since the last one.
func (w *warnLimit) allow(now time.Time) (bool, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Before(w.next) {
		w.held++
		return false, 0
	}
	w.next = now.Add(time.Minute)
	held := w.held
	w.held = 0
	return true, held
}

// activity records when a connection last moved SFTP data.
type activity struct{ last atomic.Int64 }

func (a *activity) touch(now time.Time) { a.last.Store(now.UnixNano()) }

func (a *activity) idleSince() time.Time { return time.Unix(0, a.last.Load()) }

// activeChannel touches the connection's activity on every read and write.
type activeChannel struct {
	ssh.Channel
	a *activity
}

func (c activeChannel) Read(p []byte) (int, error) {
	n, err := c.Channel.Read(p)
	if n > 0 {
		c.a.touch(time.Now())
	}
	return n, err
}

func (c activeChannel) Write(p []byte) (int, error) {
	n, err := c.Channel.Write(p)
	if n > 0 {
		c.a.touch(time.Now())
	}
	return n, err
}

// keepaliveMisses unanswered keepalives close a connection.
const keepaliveMisses = 3

// watch closes the connection by calling closeConn with a reason when it
// has moved no SFTP data for idle, or when keepalive requests sent every
// interval go unanswered keepaliveMisses times in a row. A zero idle or
// interval disables that check. watch returns when done is closed.
func watch(sconn ssh.Conn, act *activity, idle, interval time.Duration, done <-chan struct{}, closeConn func(reason string)) {
	var (
		idleTimer *time.Timer
		idleC     <-chan time.Time
		tickC     <-chan time.Time
	)
	if idle > 0 {
		idleTimer = time.NewTimer(idle)
		defer idleTimer.Stop()
		idleC = idleTimer.C
	}
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tickC = ticker.C
	}
	replies := make(chan error, 1) // one request is outstanding at a time
	pending, missed := false, 0
	for {
		select {
		case <-done:
			return
		case <-idleC:
			if left := idle - time.Since(act.idleSince()); left > 0 {
				idleTimer.Reset(left)
				continue
			}
			closeConn("idle_timeout")
			return
		case err := <-replies:
			if err != nil {
				return // the connection is closed
			}
			pending, missed = false, 0
		case <-tickC:
			if pending {
				if missed++; missed >= keepaliveMisses {
					closeConn("keepalive_timeout")
					return
				}
				continue
			}
			pending = true
			go func() {
				// A client that does not know the request answers with a
				// failure, which counts as an answer.
				_, _, err := sconn.SendRequest("keepalive@openssh.com", true, nil)
				replies <- err
			}()
		}
	}
}
