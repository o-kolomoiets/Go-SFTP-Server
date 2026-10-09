// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Ban defaults (ROADMAP §7.5).
const (
	DefaultBanAfterFailures = 10
	DefaultBanWithin        = 10 * time.Minute
	DefaultBanDuration      = 30 * time.Minute
	DefaultMaxBanEntries    = 65536
)

// SourceAddr returns the IP address of a connection's remote address,
// unmapped and without zone. ok is false for non-IP addresses.
func SourceAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	var ip netip.Addr
	if a, ok := addr.(*net.TCPAddr); ok {
		ip, _ = netip.AddrFromSlice(a.IP)
	} else if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		ip = ap.Addr()
	}
	if !ip.IsValid() {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

// SourceKey returns the key that connection limits and bans count by: the
// IPv4 address, or the /64 network of an IPv6 address, since one IPv6 host
// usually controls a whole /64.
func SourceKey(ip netip.Addr) netip.Prefix {
	if ip.Is4() {
		return netip.PrefixFrom(ip, 32)
	}
	p, _ := ip.Prefix(64)
	return p
}

// BanOptions configures a BanTable.
type BanOptions struct {
	AfterFailures int            // failures of a source that start a ban...
	Within        time.Duration  // ...when they happen within this window
	Duration      time.Duration  // length of a ban
	Exempt        []netip.Prefix // never banned
	MaxEntries    int            // per table (failures and bans); default DefaultMaxBanEntries
}

// BanTable bans sources that keep failing authentication. The caller
// decides what a failure is (the server counts each wrong password, and
// rejected keys once per connection, so that an agent with many keys does
// not ban its owner). Both tables are bounded LRUs: a flood of sources
// evicts the oldest entries instead of growing memory.
type BanTable struct {
	opts  BanOptions
	now   func() time.Time
	start time.Time

	mu       sync.Mutex
	failures *lru[netip.Prefix, []time.Duration] // recent failure times since start, oldest first
	bans     *lru[netip.Prefix, time.Duration]   // end of the ban since start
}

// NewBanTable returns a BanTable; zero options take the defaults.
func NewBanTable(o BanOptions) *BanTable {
	if o.AfterFailures <= 0 {
		o.AfterFailures = DefaultBanAfterFailures
	}
	if o.Within <= 0 {
		o.Within = DefaultBanWithin
	}
	if o.Duration <= 0 {
		o.Duration = DefaultBanDuration
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxBanEntries
	}
	b := &BanTable{opts: o, now: time.Now}
	b.start = b.now()
	b.failures = newLRU[netip.Prefix, []time.Duration](o.MaxEntries)
	b.bans = newLRU[netip.Prefix, time.Duration](o.MaxEntries)
	return b
}

func (b *BanTable) exempt(ip netip.Addr) bool {
	for _, p := range b.opts.Exempt {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (b *BanTable) elapsed() time.Duration { return b.now().Sub(b.start) }

// Banned reports whether ip is banned now.
func (b *BanTable) Banned(ip netip.Addr) bool {
	if b.exempt(ip) {
		return false
	}
	src := SourceKey(ip)
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.bans.get(src)
	if !ok {
		return false
	}
	if b.elapsed() >= until {
		b.bans.remove(src)
		return false
	}
	return true
}

// Fail records a failure of ip and reports whether it banned ip's source
// (SourceKey). Failures of a source that is banned already are not
// recorded, so one burst starts one ban.
func (b *BanTable) Fail(ip netip.Addr) bool {
	if b.exempt(ip) {
		return false
	}
	src := SourceKey(ip)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.elapsed()
	if until, ok := b.bans.get(src); ok && now < until {
		return false
	}
	times, _ := b.failures.get(src)
	keep := 0
	for keep < len(times) && now-times[keep] >= b.opts.Within {
		keep++
	}
	times = append(times[keep:], now)
	if len(times) < b.opts.AfterFailures {
		b.failures.put(src, times)
		return false
	}
	b.failures.remove(src)
	b.bans.put(src, now+b.opts.Duration)
	return true
}

// Duration returns the length of a ban.
func (b *BanTable) Duration() time.Duration { return b.opts.Duration }

// Len returns the number of tracked sources and of bans.
func (b *BanTable) Len() (failures, bans int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures.len(), b.bans.len()
}

// lru is a map bounded to max entries that evicts the least recently used.
type lru[K comparable, V any] struct {
	max int
	ll  *list.List
	m   map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	k K
	v V
}

func newLRU[K comparable, V any](limit int) *lru[K, V] {
	return &lru[K, V]{max: limit, ll: list.New(), m: make(map[K]*list.Element)}
}

func (l *lru[K, V]) get(k K) (V, bool) {
	if e, ok := l.m[k]; ok {
		l.ll.MoveToFront(e)
		return e.Value.(*lruEntry[K, V]).v, true
	}
	var zero V
	return zero, false
}

func (l *lru[K, V]) put(k K, v V) {
	if e, ok := l.m[k]; ok {
		e.Value.(*lruEntry[K, V]).v = v
		l.ll.MoveToFront(e)
		return
	}
	l.m[k] = l.ll.PushFront(&lruEntry[K, V]{k, v})
	if l.ll.Len() > l.max {
		oldest := l.ll.Back()
		l.ll.Remove(oldest)
		delete(l.m, oldest.Value.(*lruEntry[K, V]).k)
	}
}

func (l *lru[K, V]) remove(k K) {
	if e, ok := l.m[k]; ok {
		l.ll.Remove(e)
		delete(l.m, k)
	}
}

func (l *lru[K, V]) len() int { return l.ll.Len() }
