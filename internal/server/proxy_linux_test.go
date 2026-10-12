// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// The PROXY protocol over real sockets: 127.0.0.2 is the trusted proxy,
// 127.0.0.1 a peer that is not trusted. Every Linux system routes
// 127.0.0.0/8 to the loopback interface.
func TestProxyRealSockets(t *testing.T) {
	t.Parallel()

	m := obs.NewMetrics("test")
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Metrics = m
		c.HandshakeTimeout = 3 * time.Second // the header deadline too
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}
	}})
	proxy := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}, Timeout: 10 * time.Second}
	direct := &net.Dialer{Timeout: 10 * time.Second}
	dial := func(d *net.Dialer) *net.TCPConn {
		t.Helper()
		c, err := d.DialContext(t.Context(), "tcp", e.addr)
		if err != nil {
			t.Fatalf("dial from %v: %v", d.LocalAddr, err)
		}
		t.Cleanup(func() { c.Close() })
		return c.(*net.TCPConn)
	}
	// rest returns what the server sends until it closes the connection; a
	// close with bytes unread sends a reset, which ends it too.
	rest := func(c net.Conn) string {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, err := io.ReadAll(c)
		if err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("the server did not close the connection: %v", err)
		}
		return string(b)
	}

	// A silent trusted peer does not hold up another client's banner: it
	// comes while the server still waits for the silent peer's header.
	silent := dial(proxy)
	other := dial(direct)
	if line, err := bufio.NewReader(other).ReadString('\n'); err != nil || line != "SSH-2.0-gosftpd\r\n" {
		t.Fatalf("banner %q, %v", line, err)
	}
	_ = silent.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err := silent.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the banner came only after the silent peer's header deadline: %v", err)
	}
	other.Close()

	// The client a header names logs in, with the proxy as proxy_addr.
	c := dial(proxy)
	if _, err := c.Write(v2For(t, client)); err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(c, e.addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(e.userKey)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey),
	})
	if err != nil {
		t.Fatalf("login through the proxy: %v", err)
	}
	ssh.NewClient(conn, chans, reqs).Close()
	proxyAddr := c.LocalAddr().String()

	// No header from the trusted peer: closed before the banner.
	noHeader := dial(proxy)
	_, _ = noHeader.Write([]byte("SSH-2.0-OpenSSH_10.0\r\n"))
	if got := rest(noHeader); got != "" {
		t.Errorf("the server answered a trusted peer without a header: %q", got)
	}
	// A header from 127.0.0.1: refused after the banner.
	untrusted := dial(direct)
	if line, err := bufio.NewReader(untrusted).ReadString('\n'); err != nil || line != "SSH-2.0-gosftpd\r\n" {
		t.Fatalf("banner %q, %v", line, err)
	}
	_, _ = untrusted.Write(v2For(t, client))
	if got := rest(untrusted); got != "" {
		t.Errorf("a header from an untrusted peer: the server sent %q after its banner", got)
	}
	// FIN and RST before a byte, and the silent peer at the header
	// deadline: health checks, not audited.
	dial(proxy).Close()
	rst := dial(proxy)
	if err := rst.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	rst.Close()
	if got := rest(silent); got != "" {
		t.Errorf("the server sent %q to a silent trusted peer", got)
	}

	waitMetrics(t, m, map[string]float64{
		`gosftpd_connections_total{result="ok"}`:                   1,
		`gosftpd_connections_total{result="no_version"}`:           4, // the direct banner check, FIN, RST, silent
		`gosftpd_connections_total{result="untrusted_proxy"}`:      1,
		`gosftpd_connections_refused_total{reason="proxy_header"}`: 1,
		`gosftpd_connections_active`:                               0,
	})
	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	var events []string
	for _, l := range lines {
		events = append(events, l["event"].(string))
		switch l["event"] {
		case "conn.accept", "auth.success", "conn.close":
			if l["remote_addr"] != client || l["proxy_addr"] != proxyAddr || l["local_addr"] != clientDst {
				t.Errorf("%s: %v", l["event"], l)
			}
		case "conn.reject":
			_, viaProxy := l["proxy_addr"]
			if l["reason"] == "proxy_header" && (!viaProxy || !strings.HasPrefix(l["remote_addr"].(string), "127.0.0.2:")) ||
				l["reason"] == "untrusted_proxy" && (viaProxy || !strings.HasPrefix(l["remote_addr"].(string), "127.0.0.1:")) {
				t.Errorf("conn.reject: %v", l)
			}
		}
	}
	slices.Sort(events) // the login's conn.close may come after a refusal
	if want := "auth.success conn.accept conn.close conn.reject conn.reject"; strings.Join(events, " ") != want {
		t.Errorf("audit events %v, want %s", events, want)
	}
}
