// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
	"github.com/o-kolomoiets/go-sftp-server/internal/testutil"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// The PROXY protocol tests (ADR 0011) run on every platform over net.Pipe
// inside a synctest bubble: addrConn gives the server's end of each pipe
// the peer address a test chooses, and time is fake.

const (
	proxyPeer  = "10.0.0.5:4000"   // a trusted proxy
	otherPeer  = "198.51.100.9:22" // a peer that is not trusted
	serverAddr = "192.0.2.10:2022" // the server's end of every connection
	client     = "203.0.113.7:51000"
	clientDst  = "192.0.2.1:22" // the address the client connected to
)

// addrConn is the server's end of a connection, with the addresses a test
// chooses; with readErr set, Read fails at once (a reset).
type addrConn struct {
	net.Conn
	remote, local net.Addr
	readErr       error
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }
func (c addrConn) LocalAddr() net.Addr  { return c.local }

func (c addrConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}

func tcpAddr(s string) *net.TCPAddr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

// v2Proxy is a v2 PROXY header for a TCP client src that connected to dst,
// in the given family.
func v2Proxy(tb testing.TB, family proxyproto.AddressFamilyAndProtocol, src, dst string) []byte {
	tb.Helper()
	h := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: family, SourceAddr: tcpAddr(src), DestinationAddr: tcpAddr(dst)}
	b, err := h.Format()
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// v2For is the v2 header of the IPv4 client src.
func v2For(tb testing.TB, src string) []byte {
	tb.Helper()
	return v2Proxy(tb, proxyproto.TCPv4, src, clientDst)
}

// rawV2 is a v2 header with any command, family and payload.
func rawV2(cmd, family byte, payload []byte) []byte {
	b := append(bytes.Clone(proxyproto.SIGV2), cmd, family, byte(len(payload)>>8), byte(len(payload)))
	return append(b, payload...)
}

var (
	localV2   = rawV2(0x20, 0x00, nil) // LOCAL, as HAProxy's health checks send it
	unknownV1 = []byte("PROXY UNKNOWN\r\n")
	// tcp4Payload is the address block of 203.0.113.7:51000 -> 192.0.2.1:22.
	tcp4Payload = []byte{203, 0, 113, 7, 192, 0, 2, 1, 0xc7, 0x38, 0, 22}
)

// proxyEnv is a server that trusts 10.0.0.5 and 2001:db8:5::/64, served
// over pipes.
type proxyEnv struct {
	srv     *Server
	audit   *syncBuffer
	log     *syncBuffer // the operational log, JSON at debug level
	m       *obs.Metrics
	hostKey ssh.PublicKey
	userKey ssh.Signer
	mounts  *vfs.Table

	mu     sync.Mutex
	conns  []net.Conn // client ends
	wg     sync.WaitGroup
	closed sync.Once
}

func newProxyEnv(t *testing.T, tweak func(*Config)) *proxyEnv {
	t.Helper()
	mounts, err := vfs.Open([]vfs.MountSpec{{Name: "share", Path: t.TempDir(), Options: vfs.DefaultMountOptions()}}, vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &proxyEnv{audit: &syncBuffer{}, log: &syncBuffer{}, m: obs.NewMetrics("test"), userKey: signer(t), mounts: mounts}
	hk := signer(t)
	e.hostKey = hk.PublicKey()
	cfg := Config{
		HostKeys: []ssh.Signer{hk},
		Auth:     auth.New("", keysOf(t, e.userKey)),
		Mounts:   mounts,
		Audit: mustAudit(t, e.audit, []string{
			audit.CategoryConn, audit.CategoryAuth, audit.CategorySession, audit.CategoryTransfer, audit.CategoryModify, audit.CategoryDenied,
		}),
		Log:            slog.New(slog.NewJSONHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Metrics:        e.m,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32"), netip.MustParsePrefix("2001:db8:5::/64")},
	}
	if tweak != nil {
		tweak(&cfg)
	}
	if e.srv, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

// close closes every client end and waits for the server's ends.
func (e *proxyEnv) close() {
	e.closed.Do(func() {
		e.mu.Lock()
		for _, c := range e.conns {
			c.Close()
		}
		e.mu.Unlock()
		e.wg.Wait()
		e.mounts.Close()
	})
}

// accept hands the server a connection from peer, as Serve does, and
// returns the client's end.
func (e *proxyEnv) accept(peer string) net.Conn {
	sc, cc := net.Pipe()
	return e.acceptConn(addrConn{Conn: sc, remote: tcpAddr(peer), local: tcpAddr(serverAddr)}, cc)
}

func (e *proxyEnv) acceptConn(sc, cc net.Conn) net.Conn {
	c := testutil.NewAsyncConn(cc)
	e.mu.Lock()
	e.conns = append(e.conns, c)
	e.mu.Unlock()
	e.wg.Go(func() { e.srv.ServeConn(sc) })
	return c
}

// login connects from peer, sends data first (a header), and logs in.
func (e *proxyEnv) login(t *testing.T, peer string, data []byte, key ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	c := e.accept(peer)
	if data != nil {
		_, _ = c.Write(data)
	}
	return e.handshake(c, key, "")
}

func (e *proxyEnv) handshake(c net.Conn, key ssh.Signer, version string) (*ssh.Client, error) {
	conn, chans, reqs, err := ssh.NewClientConn(c, "pipe", &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), ClientVersion: version,
	})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

// held is a connection that only sends data and reads what the server
// sends.
type held struct {
	got    bytes.Buffer
	mu     sync.Mutex
	closed chan struct{} // closed when the server closed the connection
}

// hold connects from peer, sends data and keeps reading.
func (e *proxyEnv) hold(peer string, data ...[]byte) *held {
	return e.holdConn(e.accept(peer), data...)
}

func (e *proxyEnv) holdConn(c net.Conn, data ...[]byte) *held {
	h := &held{closed: make(chan struct{})}
	for _, d := range data {
		_, _ = c.Write(d)
	}
	e.wg.Go(func() {
		defer close(h.closed)
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			h.mu.Lock()
			h.got.Write(buf[:n])
			h.mu.Unlock()
			if err != nil {
				return
			}
		}
	})
	return h
}

// open reports whether the server still keeps the connection; call it after
// synctest.Wait.
func (h *held) open() bool {
	select {
	case <-h.closed:
		return false
	default:
		return true
	}
}

func (h *held) received() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.got.String()
}

// lines returns the audit lines so far.
func (e *proxyEnv) lines(t *testing.T) []map[string]any {
	t.Helper()
	if strings.TrimSpace(e.audit.String()) == "" {
		return nil
	}
	lines := auditLines(t, e.audit.String())
	checkSchema(t, lines)
	return lines
}

// rejects returns the conn.reject events so far.
func (e *proxyEnv) rejects(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range e.lines(t) {
		if l["event"] == "conn.reject" {
			out = append(out, l)
		}
	}
	return out
}

// warnings returns the messages of the operational log's warnings.
func (e *proxyEnv) warnings(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(strings.TrimSpace(e.log.String()), "\n") {
		var m map[string]any
		if l == "" {
			continue
		}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m["level"] == "WARN" {
			out = append(out, m)
		}
	}
	return out
}

func (e *proxyEnv) value(series string) float64 {
	v, _ := e.m.Value(series)
	return v
}

// tally returns gosftpd_connections_active, and the sum of every series of
// gosftpd_connections_total and gosftpd_connections_refused_total.
func (e *proxyEnv) tally() (active, ended float64) {
	for _, r := range obs.ConnResults {
		ended += e.value(`gosftpd_connections_total{result="` + r + `"}`)
	}
	for _, r := range obs.RefusedReasons {
		ended += e.value(`gosftpd_connections_refused_total{reason="` + r + `"}`)
	}
	return e.value("gosftpd_connections_active"), ended
}

// endsOnce runs a connection that ends on its own and checks that it adds
// exactly one to series and to the sum of all series, and that
// gosftpd_connections_active returns to where it was.
func (e *proxyEnv) endsOnce(t *testing.T, series string, run func()) {
	t.Helper()
	synctest.Wait() // earlier connections have ended
	activeBefore, before := e.tally()
	was := e.value(series)
	run()
	synctest.Wait()
	active, after := e.tally()
	if active != activeBefore || after != before+1 || e.value(series) != was+1 {
		t.Errorf("%s: active %v -> %v, all ended %v -> %v, series %v -> %v", series, activeBefore, active, before, after, was, e.value(series))
	}
}

// connLines returns the audit lines of the connection whose remote_addr is
// remote.
func connLines(lines []map[string]any, remote string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["remote_addr"] == remote {
			out = append(out, l)
		}
	}
	return out
}

func TestTrustedProxiesChecked(t *testing.T) {
	t.Parallel()

	got, err := checkTrustedProxies([]netip.Prefix{netip.MustParsePrefix("10.0.0.5/24"), netip.MustParsePrefix("2001:db8::1/128")})
	if err != nil || len(got) != 2 || got[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("checkTrustedProxies = %v, %v", got, err)
	}
	for _, p := range []netip.Prefix{
		{},
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("::ffff:10.0.0.5/128"), netip.PrefixFrom(netip.MustParseAddr("10.0.0.5"), 33),
	} {
		if _, err := checkTrustedProxies([]netip.Prefix{p}); err == nil {
			t.Errorf("%v accepted", p)
		}
		if _, err := New(Config{HostKeys: []ssh.Signer{signer(t)}, Auth: auth.New("", nil), Mounts: &vfs.Table{}, TrustedProxies: []netip.Prefix{p}}); err == nil {
			t.Errorf("New with trusted proxy %v succeeded", p)
		}
	}
}

func TestHeaderCheck(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		in      string
		found   bool
		checked int // bytes looked at
	}{
		{"SSH-2.0-OpenSSH_10.0\r\n", false, 1},
		{"SSH-2.0-x\r\n", false, 1},
		{"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n", true, 5},
		{"PROXY", true, 5},
		{"PROX", false, 4},
		{"PROXI", false, 5},
		{string(proxyproto.SIGV2) + "\x21\x11", true, 12},
		{string(proxyproto.SIGV2[:11]) + "X", false, 12},
		{"\r\nSSH-2.0-x\r\n", false, 3},
		{"", false, 0},
	} {
		// Byte by byte, as x/crypto reads the version line, and at once.
		var one, all headerCheck
		found := false
		for i := range len(tt.in) {
			found = one.scan([]byte{tt.in[i]})
		}
		if found != tt.found || all.scan([]byte(tt.in)) != tt.found || one.n != tt.checked || all.n != tt.checked {
			t.Errorf("%q: found %v (%v at once), %d bytes checked (%d at once); want %v, %d", tt.in, found, all.found, one.n, all.n, tt.found, tt.checked)
		}
		if tt.found && !one.scan([]byte("more")) {
			t.Errorf("%q: found no more after more bytes", tt.in)
		}
	}
}

func TestWarnLimit(t *testing.T) {
	t.Parallel()

	var w warnLimit
	now := time.Now()
	if ok, held := w.allow(now); !ok || held != 0 {
		t.Fatalf("first warning: %v, %d", ok, held)
	}
	for range 3 {
		if ok, _ := w.allow(now.Add(59 * time.Second)); ok {
			t.Fatal("a second warning within the minute")
		}
	}
	if ok, held := w.allow(now.Add(time.Minute)); !ok || held != 3 {
		t.Errorf("after a minute: %v, %d held back", ok, held)
	}
}

// readerConn is a connection whose peer sent data, then closed.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chunks returns a reader that hands out each part in a Read of its own,
// as separate TCP segments do.
type chunks [][]byte

func (c *chunks) Read(p []byte) (int, error) {
	for len(*c) > 0 && len((*c)[0]) == 0 {
		*c = (*c)[1:]
	}
	if len(*c) == 0 {
		return 0, io.EOF
	}
	n := copy(p, (*c)[0])
	(*c)[0] = (*c)[0][n:]
	return n, nil
}

// fromProxy is a connection from the trusted proxy that sent parts.
func fromProxy(peer string, parts ...[]byte) net.Conn {
	c := chunks(parts)
	return addrConn{Conn: readerConn{r: &c}, remote: tcpAddr(peer), local: tcpAddr(serverAddr)}
}

// readProxyHeader on the headers HAProxy and nginx send, and on what they
// must not: the client and the address it connected to, or the proxy's own
// for LOCAL and UNKNOWN.
func TestReadProxyHeader(t *testing.T) {
	t.Parallel()

	ok := []struct {
		name          string
		peer          string
		parts         [][]byte
		remote, local string
	}{
		{"v2 TCP4", proxyPeer, [][]byte{v2For(t, client)}, client, clientDst},
		{"v1 TCP4", proxyPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 51000 22\r\n")}, client, clientDst},
		{"v2 TCP6", proxyPeer, [][]byte{v2Proxy(t, proxyproto.TCPv6, "[2001:db8::7]:51000", "[2001:db8::1]:22")}, "[2001:db8::7]:51000", "[2001:db8::1]:22"},
		{"v1 TCP6", proxyPeer, [][]byte{[]byte("PROXY TCP6 2001:db8::7 2001:db8::1 51000 22\r\n")}, "[2001:db8::7]:51000", "[2001:db8::1]:22"},
		{"v2 TCP6 mapped", proxyPeer, [][]byte{v2Proxy(t, proxyproto.TCPv6, "[::ffff:203.0.113.7]:51000", "[::ffff:192.0.2.1]:22")}, client, clientDst},
		{"v1 TCP6 mapped", proxyPeer, [][]byte{[]byte("PROXY TCP6 ::ffff:203.0.113.7 ::ffff:192.0.2.1 51000 22\r\n")}, client, clientDst},
		{"v1 TCP6 with IPv4 (nginx)", proxyPeer, [][]byte{[]byte("PROXY TCP6 203.0.113.7 2001:db8::1 51000 22\r\n")}, client, "[2001:db8::1]:22"},
		{"v2 LOCAL", proxyPeer, [][]byte{localV2}, proxyPeer, serverAddr},
		{"v2 LOCAL with addresses", proxyPeer, [][]byte{rawV2(0x20, 0x11, tcp4Payload)}, proxyPeer, serverAddr},
		{"v1 UNKNOWN", proxyPeer, [][]byte{unknownV1}, proxyPeer, serverAddr},
		{"v1 UNKNOWN with addresses", proxyPeer, [][]byte{[]byte("PROXY UNKNOWN 203.0.113.7 192.0.2.1 51000 22\r\n")}, proxyPeer, serverAddr},
		{"v2 with TLVs", proxyPeer, [][]byte{rawV2(0x21, 0x11, append(bytes.Clone(tcp4Payload), 0x05, 0, 3, 'i', 'd', '1', 0x03, 0, 4, 1, 2, 3, 4))}, client, clientDst},
		{"v2 of the largest length", proxyPeer, [][]byte{rawV2(0x21, 0x11, append(bytes.Clone(tcp4Payload), append([]byte{0xee, 0x0f, 0xf1}, make([]byte, 4096-12-3)...)...))}, client, clientDst},
		{"v2 in pieces", proxyPeer, [][]byte{v2For(t, client)[:3], v2For(t, client)[3:12], v2For(t, client)[12:14], v2For(t, client)[14:20], v2For(t, client)[20:]}, client, clientDst},
		{"v1 cut after 3 bytes", proxyPeer, [][]byte{[]byte("PRO"), []byte("XY TCP4 203.0.113.7 192.0.2.1 51000 22\r\n")}, client, clientDst},
		{"a mapped peer", "[::ffff:10.0.0.5]:4000", [][]byte{v2For(t, client)}, client, clientDst},
		// A proxy on this host relays a local client: from loopback, or
		// from the address the connection reached.
		{"loopback source from a loopback proxy", "127.0.0.1:4000", [][]byte{v2For(t, "127.0.0.1:5000")}, "127.0.0.1:5000", clientDst},
		{"loopback source from this host's address", "192.0.2.10:4000", [][]byte{v2For(t, "127.0.0.1:5000")}, "127.0.0.1:5000", clientDst},
	}
	for _, tt := range ok {
		conn, err := readProxyHeader(fromProxy(tt.peer, append(tt.parts, []byte("SSH-2.0-x\r\n"))...))
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		rest, _ := io.ReadAll(conn)
		if conn.RemoteAddr().String() != tt.remote || conn.LocalAddr().String() != tt.local || string(rest) != "SSH-2.0-x\r\n" {
			t.Errorf("%s: remote %s, local %s, then %q; want %s, %s", tt.name, conn.RemoteAddr(), conn.LocalAddr(), rest, tt.remote, tt.local)
		}
	}

	tooLong := append(bytes.Clone(tcp4Payload), append([]byte{0xee, 0x0f, 0xf2}, make([]byte, 4097-12-3)...)...)
	unix := make([]byte, 216)
	copy(unix, "/run/client.sock")
	refused := []struct {
		name  string
		peer  string
		parts [][]byte
		got   string
	}{
		{"an SSH client", proxyPeer, [][]byte{[]byte("SSH-2.0-OpenSSH_10.0\r\n")}, "no PROXY header but an SSH version line"},
		{"HTTP", proxyPeer, [][]byte{[]byte("GET / HTTP/1.0\r\n\r\n")}, "no PROXY header but other data"},
		{"the start of v1, then a close", proxyPeer, [][]byte{[]byte("PRO")}, "an incomplete PROXY header"},
		{"the start of v2, then a close", proxyPeer, [][]byte{proxyproto.SIGV2[:8]}, "an incomplete PROXY header"},
		{"v2 cut after its signature", proxyPeer, [][]byte{v2For(t, client)[:14]}, "an incomplete PROXY header"},
		{"v2 UDP4", proxyPeer, [][]byte{rawV2(0x21, 0x12, tcp4Payload)}, "a PROXY header for a UDP client"},
		{"v2 UDP6", proxyPeer, [][]byte{rawV2(0x21, 0x22, make([]byte, 36))}, "a PROXY header for a UDP client"},
		{"v2 Unix stream", proxyPeer, [][]byte{rawV2(0x21, 0x31, unix)}, "a PROXY header for a Unix socket client"},
		{"v2 Unix datagram", proxyPeer, [][]byte{rawV2(0x21, 0x32, unix)}, "a PROXY header for a Unix socket client"},
		{"v2 PROXY unspecified", proxyPeer, [][]byte{rawV2(0x21, 0x00, nil)}, "an invalid PROXY header"},
		{"v2 family 0x13", proxyPeer, [][]byte{rawV2(0x21, 0x13, tcp4Payload)}, "an invalid PROXY header"},
		{"v2 version 1", proxyPeer, [][]byte{rawV2(0x11, 0x11, tcp4Payload)}, "an invalid PROXY header"},
		{"v2 command 2", proxyPeer, [][]byte{rawV2(0x22, 0x11, tcp4Payload)}, "an invalid PROXY header"},
		{"v2 too short for its family", proxyPeer, [][]byte{rawV2(0x21, 0x11, tcp4Payload[:11])}, "an invalid PROXY header"},
		{"v2 longer than 4096", proxyPeer, [][]byte{rawV2(0x21, 0x11, tooLong)}, "an invalid PROXY header"},
		{"v1 longer than 107 bytes", proxyPeer, [][]byte{[]byte("PROXY UNKNOWN " + strings.Repeat("x", 100) + "\r\n")}, "an invalid PROXY header"},
		{"v1 without CR", proxyPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 51000 22\n")}, "an invalid PROXY header"},
		{"v1 with a zero-padded port", proxyPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 051000 22\r\n")}, "an invalid PROXY header"},
		{"v1 with a zone", proxyPeer, [][]byte{[]byte("PROXY TCP6 fe80::7%eth0 2001:db8::1 51000 22\r\n")}, "an invalid PROXY header"},
		{"v1 with junk after PROXY", proxyPeer, [][]byte{[]byte("PROXYjunk TCP4 203.0.113.7 192.0.2.1 51000 22\r\n")}, "an invalid PROXY header"},
		{"v1 TCP4 with IPv6", proxyPeer, [][]byte{[]byte("PROXY TCP4 2001:db8::7 192.0.2.1 51000 22\r\n")}, "an invalid PROXY header"},
		{"v1 split after 5 bytes", proxyPeer, [][]byte{[]byte("PROXY"), []byte(" TCP4 203.0.113.7 192.0.2.1 51000 22\r\n")}, "an invalid PROXY header"},
		{"v1 split after 10 bytes", proxyPeer, [][]byte{[]byte("PROXY TCP4"), []byte(" 203.0.113.7 192.0.2.1 51000 22\r\n")}, "an invalid PROXY header"},
		{"v1 split after 30 bytes", proxyPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2."), []byte("1 51000 22\r\n")}, "an invalid PROXY header"},
		// Loopback keeps meaning this host for allow_from, from=,
		// source-address and auth.ban.exempt.
		{"loopback source from a remote proxy", proxyPeer, [][]byte{v2For(t, "127.0.0.1:5000")}, "a PROXY header with the source address 127.0.0.1:5000"},
		{"IPv6 loopback source", proxyPeer, [][]byte{v2Proxy(t, proxyproto.TCPv6, "[::1]:5000", "[2001:db8::1]:22")}, "a PROXY header with the source address [::1]:5000"},
		{"mapped loopback source", proxyPeer, [][]byte{[]byte("PROXY TCP6 ::ffff:127.0.0.1 2001:db8::1 5000 22\r\n")}, "a PROXY header with the source address 127.0.0.1:5000"},
		{"unspecified source", proxyPeer, [][]byte{v2For(t, "0.0.0.0:5000")}, "a PROXY header with the source address 0.0.0.0:5000"},
		{"loopback source from another host's proxy", "[2001:db8:5::7]:4000", [][]byte{v2For(t, "127.0.0.2:5000")}, "a PROXY header with the source address 127.0.0.2:5000"},
	}
	for _, tt := range refused {
		conn, err := readProxyHeader(fromProxy(tt.peer, tt.parts...))
		he, isHeader := errors.AsType[*headerError](err)
		if conn != nil || !isHeader || he.got != tt.got || he.hint == "" {
			t.Errorf("%s: %v, %v; want %q", tt.name, conn, err, tt.got)
		}
	}

	// Nothing before the close, a reset or the deadline: a health check.
	for _, c := range []net.Conn{
		fromProxy(proxyPeer),
		addrConn{remote: tcpAddr(proxyPeer), local: tcpAddr(serverAddr), readErr: errors.New("connection reset by peer")},
		addrConn{remote: tcpAddr(proxyPeer), local: tcpAddr(serverAddr), readErr: timeoutError{}},
	} {
		if _, err := readProxyHeader(c); !errors.Is(err, errNothingReceived) {
			t.Errorf("nothing received: %v", err)
		}
	}
	// The start of a signature, then the deadline.
	if _, err := readProxyHeader(addrConn{Conn: readerConn{r: io.MultiReader(strings.NewReader("PRO"), errReader{timeoutError{}})}, remote: tcpAddr(proxyPeer), local: tcpAddr(serverAddr)}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("the start of a header, then the deadline: %v", err)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// The bytes a client sends along with the header are served first, also
// beyond the 256-byte buffer, and nothing is lost or reordered at its end
// (go-proxyproto's own Conn once truncated them).
func TestProxiedConnServesBufferedBytes(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	for _, split := range []int{0, 100, 228, 1000} {
		first := append(v2For(t, client), payload[:split]...)
		conn, err := readProxyHeader(fromProxy(proxyPeer, first, payload[split:]))
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		buf := make([]byte, 7) // small reads cross the buffer's end
		for {
			n, err := conn.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("split at %d: %d bytes after the header, want the %d sent", split, len(got), len(payload))
		}
	}
}

// prefixConn sends prefix together with the first write: a header and the
// client's version line in one segment.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Write(p []byte) (int, error) {
	if c.prefix == nil {
		return c.Conn.Write(p)
	}
	b := append(bytes.Clone(c.prefix), p...)
	c.prefix = nil
	if _, err := c.Conn.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Through a trusted proxy the audit log and the operational log name the
// client in remote_addr, the address it connected to in local_addr and the
// proxy in proxy_addr, on every event; for LOCAL and UNKNOWN, the proxy is
// the client.
func TestProxyAddresses(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		for _, tt := range []struct {
			name          string
			peer, proxy   string
			header        []byte
			remote, local string
		}{
			{"v2 TCP4", proxyPeer, proxyPeer, v2For(t, client), client, clientDst},
			{"v1 TCP4", proxyPeer, proxyPeer, []byte("PROXY TCP4 203.0.113.8 192.0.2.1 51000 22\r\n"), "203.0.113.8:51000", clientDst},
			{"v2 TCP6", "[2001:db8:5::1]:4000", "[2001:db8:5::1]:4000", v2Proxy(t, proxyproto.TCPv6, "[2001:db8::7]:51000", "[2001:db8::1]:22"), "[2001:db8::7]:51000", "[2001:db8::1]:22"},
			{"v1 TCP6", proxyPeer, proxyPeer, []byte("PROXY TCP6 2001:db8::8 2001:db8::1 51000 22\r\n"), "[2001:db8::8]:51000", "[2001:db8::1]:22"},
			{"v2 TCP6 mapped", proxyPeer, proxyPeer, v2Proxy(t, proxyproto.TCPv6, "[::ffff:203.0.113.9]:51000", "[::ffff:192.0.2.1]:22"), "203.0.113.9:51000", clientDst},
			{"v1 TCP6 with IPv4", proxyPeer, proxyPeer, []byte("PROXY TCP6 203.0.113.10 2001:db8::1 51000 22\r\n"), "203.0.113.10:51000", "[2001:db8::1]:22"},
			{"a mapped peer", "[::ffff:10.0.0.5]:4001", "10.0.0.5:4001", v2For(t, "203.0.113.11:51000"), "203.0.113.11:51000", clientDst},
			{"v2 LOCAL", "10.0.0.5:4002", "10.0.0.5:4002", localV2, "10.0.0.5:4002", serverAddr},
			{"v1 UNKNOWN", "10.0.0.5:4003", "10.0.0.5:4003", unknownV1, "10.0.0.5:4003", serverAddr},
		} {
			c, err := e.login(t, tt.peer, tt.header, e.userKey)
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
				continue
			}
			c.Close()
			synctest.Wait()
			lines := connLines(e.lines(t), tt.remote)
			events := map[string]bool{}
			for _, l := range lines {
				events[l["event"].(string)] = true
				if l["local_addr"] != tt.local || l["proxy_addr"] != tt.proxy {
					t.Errorf("%s: %s has local_addr %v, proxy_addr %v; want %s, %s", tt.name, l["event"], l["local_addr"], l["proxy_addr"], tt.local, tt.proxy)
				}
			}
			for _, ev := range []string{"conn.accept", "auth.success", "conn.close"} {
				if !events[ev] {
					t.Errorf("%s: no %s with remote_addr %s:\n%s", tt.name, ev, tt.remote, e.audit.String())
				}
			}
		}
		// A direct client has no proxy_addr.
		c, err := e.login(t, otherPeer, nil, e.userKey)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		synctest.Wait()
		for _, l := range connLines(e.lines(t), otherPeer) {
			if _, ok := l["proxy_addr"]; ok {
				t.Errorf("a direct client's %s has proxy_addr", l["event"])
			}
		}
		// The operational log has the same addresses.
		if c, err := e.login(t, proxyPeer, v2For(t, "203.0.113.12:51000"), signer(t)); err == nil {
			c.Close()
			t.Fatal("a wrong key logged in")
		}
		synctest.Wait()
		if !strings.Contains(e.log.String(), `"proxy_addr":"10.0.0.5:4000","remote_addr":"203.0.113.12:51000"`) {
			t.Errorf("the operational log lacks the addresses:\n%s", e.log.String())
		}
	})
}

// The bytes a client sends with the header are served first, also when
// they go beyond the 256-byte buffer the header is read through.
func TestProxyHeaderWithClientBytes(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		version := "SSH-2.0-" + strings.Repeat("x", 240)
		c := &prefixConn{Conn: e.accept(proxyPeer), prefix: v2For(t, client)}
		if len(c.prefix)+len(version)+2 <= headerBufferSize {
			t.Fatal("the test sends too little")
		}
		sc, err := e.handshake(c, e.userKey, version)
		if err != nil {
			t.Fatal(err)
		}
		sc.Close()
		synctest.Wait()
		if !strings.Contains(e.audit.String(), `"remote_addr":"`+client+`"`) || !strings.Contains(e.audit.String(), `"client_version":"SSH-2.0-xxxx`) {
			t.Errorf("audit:\n%s", e.audit.String())
		}
	})
}

// A trusted peer that sends no valid header is refused before the banner:
// conn.reject proxy_header, counted as refused, with a warning at most once
// a minute.
func TestProxyHeaderRefused(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		for i, data := range [][]byte{
			[]byte("SSH-2.0-OpenSSH_10.0\r\n"),
			rawV2(0x21, 0x12, tcp4Payload),
			v2For(t, "127.0.0.1:5000"),
			[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 051000 22\r\n"),
		} {
			var h *held
			e.endsOnce(t, `gosftpd_connections_refused_total{reason="proxy_header"}`, func() { h = e.hold(proxyPeer, data) })
			if h.open() || h.received() != "" {
				t.Errorf("case %d: open %v, the server sent %q", i, h.open(), h.received())
			}
		}
		rejects := e.rejects(t)
		if len(rejects) != 4 {
			t.Fatalf("%d conn.reject events, want 4", len(rejects))
		}
		for _, r := range rejects {
			if r["reason"] != "proxy_header" || r["remote_addr"] != proxyPeer || r["proxy_addr"] != proxyPeer || r["local_addr"] != serverAddr || r["conn_id"] == nil {
				t.Errorf("conn.reject = %v", r)
			}
		}
		warns := e.warnings(t)
		if len(warns) != 1 || warns[0]["peer"] != "10.0.0.5" || warns[0]["got"] != "no PROXY header but an SSH version line" ||
			!strings.Contains(warns[0]["msg"].(string), "server.trusted_proxies") || !strings.Contains(warns[0]["hint"].(string), "send-proxy or proxy_protocol") {
			t.Errorf("warnings = %v", warns)
		}
		// A minute later the next one is logged, with the number held back.
		time.Sleep(time.Minute)
		e.hold(proxyPeer, []byte("GET / HTTP/1.0\r\n\r\n"))
		synctest.Wait()
		warns = e.warnings(t)
		if len(warns) != 2 || warns[1]["suppressed"] != float64(3) || warns[1]["got"] != "no PROXY header but other data" {
			t.Errorf("warnings = %v", warns)
		}
	})
}

// A trusted peer that ends before its first byte is a TCP health check:
// no_version, not audited; so is one that sends LOCAL and closes.
func TestProxySilentPeers(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, func(c *Config) { c.HandshakeTimeout = 30 * time.Second })
		defer e.close()
		const noVersion = `gosftpd_connections_total{result="no_version"}`
		e.endsOnce(t, noVersion, func() { // FIN, once the server reads
			c := e.accept(proxyPeer)
			synctest.Wait()
			c.Close()
		})
		e.endsOnce(t, noVersion, func() {
			sc, cc := net.Pipe()
			e.acceptConn(addrConn{Conn: sc, remote: tcpAddr(proxyPeer), local: tcpAddr(serverAddr), readErr: errors.New("connection reset by peer")}, cc)
		})
		e.endsOnce(t, noVersion, func() {
			h := e.hold(proxyPeer, localV2)
			synctest.Wait()
			if !strings.HasPrefix(h.received(), "SSH-2.0-gosftpd\r\n") {
				t.Errorf("no banner after LOCAL: %q", h.received())
			}
			e.mu.Lock()
			e.conns[len(e.conns)-1].Close()
			e.mu.Unlock()
		})
		// Silent: closed at the header deadline, min(handshake_timeout, 10 s).
		start := time.Now()
		e.endsOnce(t, noVersion, func() {
			h := e.hold(proxyPeer)
			time.Sleep(maxHeaderWait - time.Millisecond)
			synctest.Wait()
			if !h.open() {
				t.Errorf("closed after %v, before the header deadline", time.Since(start))
			}
			time.Sleep(time.Millisecond)
		})
		if lines := e.lines(t); len(lines) != 0 {
			t.Errorf("health checks audited: %v", lines)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, func(c *Config) { c.HandshakeTimeout = 4 * time.Second })
		defer e.close()
		h := e.hold(proxyPeer)
		time.Sleep(4*time.Second - time.Millisecond)
		synctest.Wait()
		if !h.open() {
			t.Error("closed before handshake_timeout")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if h.open() {
			t.Error("open after handshake_timeout, which is below 10 s")
		}
	})
}

// After a valid header the handshake keeps its deadline from the accept:
// reading the header does not clear it.
func TestProxyHandshakeDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, func(c *Config) { c.HandshakeTimeout = 30 * time.Second })
		defer e.close()
		h := e.hold(proxyPeer, v2For(t, client))
		time.Sleep(30*time.Second - time.Millisecond)
		synctest.Wait()
		if !h.open() || h.received() != "SSH-2.0-gosftpd\r\n" {
			t.Fatalf("open %v after %q", h.open(), h.received())
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if h.open() {
			t.Error("a client that stopped after its header is still connected after handshake_timeout")
		}
		if v := e.value(`gosftpd_connections_total{result="no_version"}`); v != 1 {
			t.Errorf("no_version = %v", v)
		}
	})
}

// pipeListener hands Serve the server ends of pipes.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return tcpAddr(serverAddr) }

// dial connects to Serve through l from peer.
func (l *pipeListener) dial(e *proxyEnv, peer string) net.Conn {
	sc, cc := net.Pipe()
	c := testutil.NewAsyncConn(cc)
	e.mu.Lock()
	e.conns = append(e.conns, c)
	e.mu.Unlock()
	l.conns <- addrConn{Conn: sc, remote: tcpAddr(peer), local: tcpAddr(serverAddr)}
	return c
}

// The accept loop does no I/O: a trusted peer that stays silent does not
// delay the next connection's banner.
func TestProxySilentPeerDoesNotBlockAccept(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		ln := newPipeListener()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel() // before e.close, also when the test fails early
		served := make(chan error, 1)
		go func() { served <- e.srv.Serve(ctx, ln) }()

		ln.dial(e, proxyPeer) // silent
		start := time.Now()
		direct := bufio.NewReader(ln.dial(e, otherPeer))
		if line, err := direct.ReadString('\n'); err != nil || line != "SSH-2.0-gosftpd\r\n" {
			t.Fatalf("banner %q, %v", line, err)
		}
		proxied := ln.dial(e, proxyPeer)
		_, _ = proxied.Write(v2For(t, client))
		if line, err := bufio.NewReader(proxied).ReadString('\n'); err != nil || line != "SSH-2.0-gosftpd\r\n" {
			t.Fatalf("banner %q, %v", line, err)
		}
		if d := time.Since(start); d != 0 {
			t.Errorf("the banners came after %v", d)
		}
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
		e.close()
		if err := e.srv.Shutdown(t.Context()); err != nil {
			t.Error(err)
		}
	})
}
