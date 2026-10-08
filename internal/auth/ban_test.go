// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSource(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		addr net.Addr
		ip   string
		key  string
	}{
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 1}, "192.0.2.7", "192.0.2.7/32"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 1}, "192.0.2.7", "192.0.2.7/32"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 1, Zone: "eth0"}, "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}, "10.0.0.1", "10.0.0.1/32"},
	} {
		ip, ok := SourceAddr(tt.addr)
		if !ok || ip.String() != tt.ip {
			t.Errorf("SourceAddr(%v) = %v, %v; want %s", tt.addr, ip, ok, tt.ip)
			continue
		}
		if got := SourceKey(ip).String(); got != tt.key {
			t.Errorf("SourceKey(%v) = %s, want %s", ip, got, tt.key)
		}
	}
	if _, ok := SourceAddr(&net.UnixAddr{Name: "pipe"}); ok {
		t.Error("SourceAddr accepted a Unix address")
	}
	if _, ok := SourceAddr(nil); ok {
		t.Error("SourceAddr accepted nil")
	}
}

func newTestBans(o BanOptions) (*BanTable, *time.Time) {
	b := NewBanTable(o)
	now := b.start
	b.now = func() time.Time { return now }
	return b, &now
}

func TestBanTable(t *testing.T) {
	t.Parallel()

	b, now := newTestBans(BanOptions{
		AfterFailures: 3,
		Within:        10 * time.Minute,
		Duration:      30 * time.Minute,
		Exempt:        mustPrefixes(t, "127.0.0.0/8", "::1/128"),
	})
	ip := netip.MustParseAddr("203.0.113.5")

	for range 2 {
		if b.Fail(ip) {
			t.Fatal("banned before the limit")
		}
	}
	if b.Banned(ip) {
		t.Fatal("Banned before the limit")
	}
	*now = now.Add(11 * time.Minute) // the first two failures leave the window
	for range 2 {
		if b.Fail(ip) {
			t.Fatal("old failures still counted")
		}
	}
	*now = now.Add(time.Minute)
	if !b.Fail(ip) {
		t.Fatal("third failure within the window did not ban")
	}
	if !b.Banned(ip) {
		t.Fatal("not banned after the limit")
	}
	if b.Banned(netip.MustParseAddr("203.0.113.6")) {
		t.Error("ban spread to a neighbouring IPv4 address")
	}
	*now = now.Add(30 * time.Minute)
	if b.Banned(ip) {
		t.Error("ban outlived its duration")
	}
	if f, n := b.Len(); f != 0 || n != 0 {
		t.Errorf("Len() = %d, %d after the ban expired", f, n)
	}

	// IPv6 sources are banned per /64.
	v6 := netip.MustParseAddr("2001:db8:0:1::10")
	for range 3 {
		b.Fail(v6)
	}
	if !b.Banned(netip.MustParseAddr("2001:db8:0:1::99")) {
		t.Error("IPv6 ban does not cover the /64")
	}
	if b.Banned(netip.MustParseAddr("2001:db8:0:2::10")) {
		t.Error("IPv6 ban covers another /64")
	}

	// Exempt sources are never banned.
	for _, s := range []string{"127.0.0.1", "::1"} {
		lo := netip.MustParseAddr(s)
		for range 10 {
			if b.Fail(lo) {
				t.Errorf("%s banned although exempt", s)
			}
		}
		if b.Banned(lo) {
			t.Errorf("%s banned although exempt", s)
		}
	}
	// An exempt address stays exempt when its /64 is banned.
	if b.Banned(netip.MustParseAddr("::1")) {
		t.Error("exempt ::1 banned")
	}
}

func TestBanTableBounded(t *testing.T) {
	t.Parallel()

	b, _ := newTestBans(BanOptions{AfterFailures: 2, MaxEntries: 1000})
	var buf [16]byte
	buf[0], buf[1] = 0x20, 0x01
	for i := range 1_000_000 {
		binary.BigEndian.PutUint32(buf[4:8], uint32(i))
		b.Fail(netip.AddrFrom16(buf))
	}
	for i := range 100_000 { // and bans
		binary.BigEndian.PutUint32(buf[4:8], uint32(2_000_000+i))
		b.Fail(netip.AddrFrom16(buf))
		b.Fail(netip.AddrFrom16(buf))
	}
	if f, n := b.Len(); f > 1000 || n != 1000 {
		t.Errorf("Len() = %d, %d; want at most 1000 and exactly 1000", f, n)
	}

	// Two failures in a row from the same source still ban it.
	ip := netip.MustParseAddr("198.51.100.1")
	b.Fail(ip)
	if !b.Fail(ip) || !b.Banned(ip) {
		t.Error("a full table stopped banning")
	}
}
