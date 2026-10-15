// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
)

// PROXY protocol (ADR 0011). Trust is decided by the TCP peer: a connection
// from an address in Config.TrustedProxies must begin with a v1 or v2
// header, which names the client; a connection from any other peer must
// not. go-proxyproto is used as a parser only: the header is read in the
// connection's goroutine, never in the accept loop.

// maxHeaderWait bounds the time a trusted proxy has for its header, counted
// from the accept; handshake_timeout bounds it too.
const maxHeaderWait = 10 * time.Second

// headerBufferSize is the size of the buffer the header is read through.
// Bytes the client sent along with the header stay in it and are read
// first.
const headerBufferSize = 256

func init() {
	// nginx's stream module writes TCP6 lines with IPv4 addresses when the
	// client's and the backend's address families differ.
	proxyproto.V1AcceptIPv4InTCP6 = true
}

// checkTrustedProxies checks the prefixes of Config.TrustedProxies: each
// must be valid, unmapped and longer than /0, or any client could choose
// its address.
func checkTrustedProxies(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() || p.Bits() == 0 || p.Addr().Is4In6() {
			return nil, fmt.Errorf("trusted proxy %s: want an unmapped address or prefix longer than /0", p)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// trusts reports whether ip, a connection's peer address unmapped, is a
// trusted proxy.
func (sn *snapshot) trusts(ip netip.Addr) bool {
	for _, p := range sn.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// proxied reads the header of a connection from a trusted proxy and applies
// the second phase of admission to the client it names. It returns the
// connection to serve; or nil and why the connection is refused, "" when
// the proxy sent nothing (a TCP health check: no_version, not audited).
func (s *Server) proxied(c net.Conn, adm *admission, start time.Time, handshake time.Duration, connID string, log *slog.Logger) (net.Conn, string) {
	// The header deadline counts from the accept and is set on the socket,
	// not reset while the header is read; the handshake deadline set before
	// is restored after it. Should either call fail, the earlier deadline
	// still bounds the reads.
	_ = c.SetReadDeadline(start.Add(min(handshake, maxHeaderWait)))
	conn, err := readProxyHeader(c)
	if he, ok := errors.AsType[*headerError](err); ok {
		log.Debug("connection refused", "remote_addr", c.RemoteAddr().String(), "reason", rejectProxyHeader, "err", err)
		s.auditReject(s.audit.With(connContext(connID, c, c.RemoteAddr().String())...), rejectProxyHeader)
		s.warnHeader(c, he)
		return nil, rejectProxyHeader
	}
	if err != nil { // errNothingReceived
		return nil, ""
	}
	_ = c.SetReadDeadline(start.Add(handshake))
	if reason := s.admitClient(conn, adm); reason != "" {
		log.Debug("connection refused", "remote_addr", conn.RemoteAddr().String(), "reason", reason)
		s.auditReject(s.audit.With(connContext(connID, conn, c.RemoteAddr().String())...), reason)
		return nil, reason
	}
	return conn, ""
}

// connContext returns the context fields of a connection's audit events:
// the client's address and the one it connected to, and for a connection
// from a trusted proxy, proxyAddr, the proxy's.
func connContext(connID string, conn net.Conn, proxyAddr string) []any {
	kv := []any{"conn_id", connID, "remote_addr", conn.RemoteAddr().String(), "local_addr", conn.LocalAddr().String()}
	if proxyAddr != "" {
		kv = append(kv, "proxy_addr", proxyAddr)
	}
	return kv
}

// Hints of the warnings about headers from peers that are not trusted.
const (
	hintUntrusted    = "list the proxy in server.trusted_proxies, or turn PROXY protocol off on it; if this is a client's address, the load balancer already preserves client addresses: turn PROXY protocol off there"
	hintSecondHeader = "a client sent a header of its own, or two proxies in a row each add one: only the proxy that connects to gosftpd may send a header"
)

// warnHeader tells the operator, at most once a minute, that a trusted
// proxy sent no valid header.
func (s *Server) warnHeader(c net.Conn, he *headerError) {
	ok, held := s.headerWarn.allow(time.Now())
	if !ok {
		return
	}
	kv := []any{"peer", peerIP(c), "got", he.got}
	if he.err != nil {
		kv = append(kv, "err", he.err)
	}
	kv = append(kv, "hint", he.hint)
	if held > 0 {
		kv = append(kv, "suppressed", held)
	}
	s.log.Warn("refusing connection: a peer in server.trusted_proxies sent no valid PROXY protocol header", kv...)
}

// warnClientHeader tells the operator, at most once a minute, that a
// connection began with a header gosftpd does not trust: from a peer that
// is not a trusted proxy, or behind a trusted proxy's header (behindProxy;
// conn then has the client's address).
func (s *Server) warnClientHeader(behindProxy bool, conn net.Conn, proxyAddr string) {
	ok, held := s.untrustedWarn.allow(time.Now())
	if !ok {
		return
	}
	var kv []any
	if held > 0 {
		kv = append(kv, "suppressed", held)
	}
	if behindProxy {
		kv = append([]any{"proxy_addr", proxyAddr, "remote_addr", conn.RemoteAddr().String(), "hint", hintSecondHeader}, kv...)
		s.log.Warn("refusing connection: a second PROXY protocol header after a trusted proxy's", kv...)
		return
	}
	kv = append([]any{"peer", peerIP(conn), "hint", hintUntrusted}, kv...)
	s.log.Warn("refusing connection: PROXY protocol header from a peer not in server.trusted_proxies", kv...)
}

// peerIP returns the IP address of a connection's peer, as
// server.trusted_proxies lists it.
func peerIP(c net.Conn) string {
	if ip, ok := auth.SourceAddr(c.RemoteAddr()); ok {
		return ip.String()
	}
	return c.RemoteAddr().String()
}

// errNothingReceived means that a trusted proxy sent nothing before its
// connection ended or the header deadline passed: a TCP health check.
var errNothingReceived = errors.New("nothing received")

// headerError says what a trusted proxy sent instead of a header gosftpd
// accepts.
type headerError struct {
	got  string // what arrived, for the warning
	hint string // what to do about it
	err  error  // the parser's error, if any
}

func (e *headerError) Error() string {
	if e.err != nil {
		return e.got + ": " + e.err.Error()
	}
	return e.got
}

func (e *headerError) Unwrap() error { return e.err }

// Hints of the header warning.
const (
	hintNoHeader = "enable send-proxy or proxy_protocol for this server on the load balancer, or remove the address from server.trusted_proxies"
	hintInvalid  = "the load balancer must send a complete PROXY protocol v1 or v2 header in one piece when it connects"
	hintFamily   = "only clients over TCP (IPv4 or IPv6) can be relayed with PROXY; a proxy sends LOCAL or UNKNOWN for its own connections"
	hintLoopback = "a remote proxy may not relay a client as this host's loopback address, which allow_from, from=, source-address and auth.ban.exempt read as this host"
)

// readProxyHeader reads the header a connection from a trusted proxy begins
// with, under the read deadline set on c. It returns the connection to
// serve: with the client's addresses for PROXY, and with the proxy's own
// for LOCAL (v2) and UNKNOWN (v1), the proxy's health checks and clients of
// a Unix socket front end. The error is errNothingReceived or a
// *headerError.
func readProxyHeader(c net.Conn) (net.Conn, error) {
	counted := &countingReader{r: c}
	br := bufio.NewReaderSize(counted, headerBufferSize)
	h, err := proxyproto.Read(br)
	if err != nil {
		// proxyproto.Read gives one error for a close without bytes and
		// for bytes without a signature; only the bytes tell them apart.
		if counted.n == 0 {
			return nil, errNothingReceived
		}
		return nil, invalidHeader(counted.first, err)
	}
	pc := &proxiedConn{Conn: c, buf: br, remote: c.RemoteAddr(), local: c.LocalAddr()}
	if h.Command.IsLocal() {
		return pc, nil
	}
	switch h.TransportProtocol {
	case proxyproto.TCPv4, proxyproto.TCPv6:
	case proxyproto.UDPv4, proxyproto.UDPv6:
		return nil, &headerError{got: "a PROXY header for a UDP client", hint: hintFamily}
	case proxyproto.UnixStream, proxyproto.UnixDatagram:
		return nil, &headerError{got: "a PROXY header for a Unix socket client", hint: hintFamily}
	case proxyproto.UNSPEC: // go-proxyproto refuses it for PROXY itself
		return nil, &headerError{got: "a PROXY header without addresses", hint: hintInvalid}
	default: // the parser refuses other families
		return nil, &headerError{got: "a PROXY header of an unknown family", hint: hintInvalid}
	}
	src, srcOK := h.SourceAddr.(*net.TCPAddr)
	dst, dstOK := h.DestinationAddr.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return nil, &headerError{got: "a PROXY header without addresses", hint: hintInvalid}
	}
	if ip, ok := netip.AddrFromSlice(src.IP); !ok || thisHost(ip.Unmap()) && !fromThisHost(c) {
		return nil, &headerError{got: "a PROXY header with the source address " + src.String(), hint: hintLoopback}
	}
	pc.remote, pc.local = src, dst
	return pc, nil
}

// invalidHeader describes what a trusted proxy sent instead of a header
// gosftpd accepts: first are the first bytes, err the parser's error.
func invalidHeader(first []byte, err error) *headerError {
	noSignature := errors.Is(err, proxyproto.ErrNoProxyProtocol)
	var ne net.Error
	cut := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ne) && ne.Timeout()
	switch {
	case noSignature && bytes.HasPrefix(first, []byte("SSH-")):
		return &headerError{got: "no PROXY header but an SSH version line", hint: hintNoHeader}
	case noSignature && !prefixOf(first, proxyproto.SIGV1) && !prefixOf(first, proxyproto.SIGV2):
		return &headerError{got: "no PROXY header but other data", hint: hintNoHeader}
	case noSignature || cut:
		// The start of a header, then a close or the deadline.
		return &headerError{got: "an incomplete PROXY header", hint: hintInvalid}
	}
	return &headerError{got: "an invalid PROXY header", hint: hintInvalid, err: err}
}

// prefixOf reports whether b is a non-empty prefix of sig.
func prefixOf(b, sig []byte) bool {
	return len(b) > 0 && len(b) < len(sig) && bytes.HasPrefix(sig, b)
}

// thisHost reports whether ip, from a header, would mean this host: a
// loopback or unspecified address.
func thisHost(ip netip.Addr) bool { return ip.IsLoopback() || ip.IsUnspecified() }

// fromThisHost reports whether a proxy runs on this host: it connects from
// loopback, or from the address its connection reached.
func fromThisHost(c net.Conn) bool {
	peer, ok := auth.SourceAddr(c.RemoteAddr())
	if !ok {
		return false
	}
	if peer.IsLoopback() {
		return true
	}
	local, ok := auth.SourceAddr(c.LocalAddr())
	return ok && peer == local
}

// countingReader counts the bytes read through it and keeps the first
// ones, so that a header error can say what arrived.
type countingReader struct {
	r     io.Reader
	n     int
	first []byte
}

const firstBytes = 16

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	if keep := min(n, firstBytes-len(c.first)); keep > 0 {
		c.first = append(c.first, p[:keep]...)
	}
	return n, err
}

// proxiedConn is a connection from a trusted proxy after its header: it
// reads the bytes buffered past the header first, then the socket, and has
// the addresses the header gives. Only one goroutine reads it at a time.
type proxiedConn struct {
	net.Conn
	buf           *bufio.Reader // nil once drained
	remote, local net.Addr
}

func (c *proxiedConn) Read(p []byte) (int, error) {
	if c.buf != nil {
		if c.buf.Buffered() > 0 {
			return c.buf.Read(p) // never reads the socket while bytes are buffered
		}
		c.buf = nil
	}
	return c.Conn.Read(p)
}

func (c *proxiedConn) RemoteAddr() net.Addr { return c.remote }

func (c *proxiedConn) LocalAddr() net.Addr { return c.local }

// errClientHeader ends a connection whose first bytes are a PROXY header.
var errClientHeader = errors.New("the connection began with a PROXY protocol header that is not trusted")

// headerCheck matches the first bytes a connection sends against the PROXY
// protocol signatures. No SSH client starts with them (RFC 4253 allows
// lines before the version only from the server), so they come from a proxy
// that is not trusted, or are a second header behind a trusted one. The
// check ends at the first byte that differs from both, so it never holds
// back a client's version line.
type headerCheck struct {
	n            int  // bytes checked
	notV1, notV2 bool // the bytes so far do not begin that signature
	found        bool
}

// scan checks the next bytes the connection sent; it reports true once they
// complete a signature.
func (h *headerCheck) scan(p []byte) bool {
	for _, b := range p {
		if h.found || h.notV1 && h.notV2 {
			break
		}
		h.notV1 = h.notV1 || b != proxyproto.SIGV1[h.n]
		h.notV2 = h.notV2 || b != proxyproto.SIGV2[h.n]
		h.n++
		h.found = !h.notV1 && h.n == len(proxyproto.SIGV1) || !h.notV2 && h.n == len(proxyproto.SIGV2)
	}
	return h.found
}
