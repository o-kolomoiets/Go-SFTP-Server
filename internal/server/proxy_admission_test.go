// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
)

// Per-address limits and bans apply to the clients a trusted proxy names,
// never to the proxy; its LOCAL and UNKNOWN connections are its own and
// share its ban entry.
func TestProxyAdmission(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var bans *auth.BanTable
		e := newProxyEnv(t, func(c *Config) {
			c.MaxConnectionsPerIP = 2
			bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 2})
			c.Bans = bans
		})
		defer e.close()

		// Two connections of one client, then a third one: refused.
		a1 := e.hold(proxyPeer, v2For(t, client))
		a2 := e.hold(proxyPeer, v2For(t, "203.0.113.7:51001"))
		var a3 *held
		e.endsOnce(t, `gosftpd_connections_refused_total{reason="max_connections_per_ip"}`, func() { a3 = e.hold(proxyPeer, v2For(t, "203.0.113.7:51002")) })
		if !a1.open() || !a2.open() || a3.open() || a3.received() != "" {
			t.Fatalf("open: %v %v %v, the server sent %q", a1.open(), a2.open(), a3.open(), a3.received())
		}
		// Other clients through the same proxy, more than the limit.
		for i := range 5 {
			e.hold(proxyPeer, v2For(t, "203.0.113."+strconv.Itoa(100+i)+":1"))
		}
		synctest.Wait()
		if v := e.value(`gosftpd_connections_refused_total{reason="max_connections_per_ip"}`); v != 1 {
			t.Fatalf("the clients of one proxy are limited together: %v refusals", v)
		}
		rejects := e.rejects(t)
		if len(rejects) != 1 || rejects[0]["remote_addr"] != "203.0.113.7:51002" || rejects[0]["proxy_addr"] != proxyPeer || rejects[0]["local_addr"] != clientDst {
			t.Errorf("conn.reject = %v", rejects)
		}

		// Two failed logins of one client ban the client, not the proxy.
		for range 2 {
			if c, err := e.login(t, proxyPeer, v2For(t, "203.0.113.20:1"), signer(t)); err == nil {
				c.Close()
				t.Fatal("a wrong key logged in")
			}
			synctest.Wait()
		}
		if !bans.Banned(netip.MustParseAddr("203.0.113.20")) || bans.Banned(netip.MustParseAddr("10.0.0.5")) {
			t.Fatal("the client is not banned, or the proxy is")
		}
		if !strings.Contains(e.audit.String(), `"event":"auth.ban","source":"203.0.113.20/32"`) {
			t.Errorf("auth.ban:\n%s", e.audit.String())
		}
		var banned *held
		e.endsOnce(t, `gosftpd_connections_refused_total{reason="banned"}`, func() { banned = e.hold(proxyPeer, v2For(t, "203.0.113.20:2")) })
		if banned.open() || banned.received() != "" {
			t.Error("a banned client got through the proxy")
		}
		if c, err := e.login(t, proxyPeer, v2For(t, "203.0.113.21:1"), e.userKey); err != nil {
			t.Errorf("another client of the proxy after a ban: %v", err)
		} else {
			c.Close()
		}
		// LOCAL and UNKNOWN connections are the proxy's own: their failures
		// ban the proxy, and then its LOCAL connections are refused, while
		// the clients it names still get in.
		for _, h := range [][]byte{localV2, unknownV1} {
			if c, err := e.login(t, proxyPeer, h, signer(t)); err == nil {
				c.Close()
				t.Fatal("a wrong key logged in")
			}
			synctest.Wait()
		}
		if !bans.Banned(netip.MustParseAddr("10.0.0.5")) {
			t.Fatal("failures over LOCAL and UNKNOWN did not ban the proxy")
		}
		e.endsOnce(t, `gosftpd_connections_refused_total{reason="banned"}`, func() { e.hold(proxyPeer, localV2) })
		if c, err := e.login(t, proxyPeer, v2For(t, "203.0.113.22:1"), e.userKey); err != nil {
			t.Errorf("a client of a banned proxy: %v", err)
		} else {
			c.Close()
		}
		rejects = e.rejects(t)
		if last := rejects[len(rejects)-1]; last["reason"] != "banned" || last["remote_addr"] != proxyPeer || last["proxy_addr"] != proxyPeer {
			t.Errorf("conn.reject of a LOCAL connection = %v", last)
		}
	})
}

// A trusted peer is held to max_connections and max_preauth_connections
// before its header is read; such a refusal names the proxy in proxy_addr.
func TestProxyPhaseOneRefusal(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, func(c *Config) { c.MaxPreauthConnections = 1 })
		defer e.close()
		e.hold(proxyPeer) // silent: holds the pre-authentication slot
		synctest.Wait()
		e.endsOnce(t, `gosftpd_connections_refused_total{reason="max_preauth_connections"}`, func() { e.hold("10.0.0.5:4001", v2For(t, client)) })
		r := e.rejects(t)
		if len(r) != 1 || r[0]["remote_addr"] != "10.0.0.5:4001" || r[0]["proxy_addr"] != "10.0.0.5:4001" || r[0]["reason"] != "max_preauth_connections" {
			t.Errorf("conn.reject = %v", r)
		}
		if !strings.Contains(e.log.String(), `"remote_addr":"10.0.0.5:4001","proxy_addr":"10.0.0.5:4001","reason":"max_preauth_connections"`) {
			t.Errorf("operational log:\n%s", e.log.String())
		}
	})
}

// Clients behind a proxy are counted as direct clients are: IPv6 by /64,
// a v4-mapped address as IPv4.
func TestProxyClientGrouping(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, func(c *Config) { c.MaxConnectionsPerIP = 1 })
		defer e.close()
		for _, tt := range []struct {
			header []byte
			open   bool
		}{
			{v2Proxy(t, proxyproto.TCPv6, "[2001:db8::1]:1", "[2001:db8::a]:22"), true},
			{v2Proxy(t, proxyproto.TCPv6, "[2001:db8::2]:1", "[2001:db8::a]:22"), false}, // the same /64
			{v2Proxy(t, proxyproto.TCPv6, "[2001:db8:0:1::1]:1", "[2001:db8::a]:22"), true},
			{v2Proxy(t, proxyproto.TCPv6, "[::ffff:198.51.100.1]:1", "[::ffff:192.0.2.1]:22"), true},
			{v2For(t, "198.51.100.1:2"), false}, // keyed as 198.51.100.1/32
			{[]byte("PROXY TCP6 198.51.100.1 2001:db8::a 3 22\r\n"), false},
			{v2Proxy(t, proxyproto.TCPv6, "[::ffff:198.51.100.2]:1", "[::ffff:192.0.2.1]:22"), true}, // not in ::/64
		} {
			h := e.hold(proxyPeer, tt.header)
			synctest.Wait()
			if h.open() != tt.open {
				t.Errorf("%q: open %v, want %v", tt.header, h.open(), tt.open)
			}
		}
	})
}

// allow_from, from=, a certificate's source-address and the re-check at
// reload all see the client a trusted proxy names; loopback keeps meaning
// this host.
func TestProxyClientAuth(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		alice, bob, carol, ca := signer(t), signer(t), signer(t), signer(t)
		bobKeys, warns := auth.ParseAuthorizedKeys([]byte(`from="203.0.113.0/24" `+string(ssh.MarshalAuthorizedKey(bob.PublicKey()))), "test")
		if len(warns) > 0 {
			t.Fatal(warns)
		}
		users := func(aliceFrom string) *auth.Authenticator {
			a := auth.NewUsers([]auth.User{
				{Name: "alice", Keys: keysOf(t, alice), AllowFrom: []netip.Prefix{netip.MustParsePrefix(aliceFrom)}},
				{Name: "bob", Keys: bobKeys},
				{Name: "carol"},
				{Name: "local", Keys: keysOf(t, alice), AllowFrom: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}},
			})
			a.Trust([]ssh.PublicKey{ca.PublicKey()}, nil)
			return a
		}
		var cfg Config
		e := newProxyEnv(t, func(c *Config) {
			c.Auth = users("203.0.113.0/24")
			c.DisconnectRevoked = true
			cfg = *c
		})
		defer e.close()
		cert := &ssh.Certificate{
			Key: carol.PublicKey(), CertType: ssh.UserCert, KeyId: "carol", ValidPrincipals: []string{"carol"},
			ValidBefore: ssh.CertTimeInfinity, Permissions: ssh.Permissions{CriticalOptions: map[string]string{"source-address": "203.0.113.0/24"}},
		}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		carolCert, err := ssh.NewCertSigner(cert, carol)
		if err != nil {
			t.Fatal(err)
		}
		login := func(user string, key ssh.Signer, header []byte) (*ssh.Client, error) {
			c := e.accept(proxyPeer)
			_, _ = c.Write(header)
			conn, chans, reqs, err := ssh.NewClientConn(c, "pipe", &ssh.ClientConfig{
				User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey),
			})
			if err != nil {
				return nil, err
			}
			return ssh.NewClient(conn, chans, reqs), nil
		}
		for _, tt := range []struct {
			user string
			key  ssh.Signer
			src  string
			ok   bool
		}{
			{"alice", alice, "203.0.113.7:1", true},
			{"alice", alice, "198.51.100.1:1", false},
			{"bob", bob, "203.0.113.7:1", true},
			{"bob", bob, "198.51.100.1:1", false},
			{"carol", carolCert, "203.0.113.7:1", true},
			{"carol", carolCert, "198.51.100.1:1", false},
		} {
			c, err := login(tt.user, tt.key, v2For(t, tt.src))
			if (err == nil) != tt.ok {
				t.Errorf("%s from %s: %v", tt.user, tt.src, err)
			}
			if err == nil {
				c.Close()
			}
		}
		synctest.Wait()
		// from= on a key line is enforced by x/crypto, as the certificate
		// option source-address, after gosftpd's checks: without a reason.
		if n := strings.Count(e.audit.String(), `"reason":"address"`); n != 2 {
			t.Errorf("%d auth.failure events with reason address, want 2:\n%s", n, e.audit.String())
		}
		// allow_from = ["127.0.0.1"] means this host: a remote proxy
		// cannot name it, and the proxy's own connections are not loopback.
		for _, h := range [][]byte{v2For(t, "127.0.0.1:1"), localV2} {
			if c, err := login("local", alice, h); err == nil {
				c.Close()
				t.Errorf("%q: a loopback-only user logged in through a remote proxy", h)
			}
		}
		// The reload re-check closes the connection whose client no longer
		// matches allow_from.
		kept, err := login("alice", alice, v2For(t, "203.0.113.7:2"))
		if err != nil {
			t.Fatal(err)
		}
		defer kept.Close()
		synctest.Wait() // the server has registered the login
		cfg.Auth = users("203.0.113.7/32")
		if n, err := e.srv.Reload(cfg); err != nil || n != 0 {
			t.Fatalf("Reload = %d, %v", n, err)
		}
		cfg.Auth = users("198.51.100.0/24")
		if n, err := e.srv.Reload(cfg); err != nil || n != 1 {
			t.Errorf("Reload = %d, %v; want the client's connection closed", n, err)
		}
	})
}

// A connection that begins with a PROXY header after the banner, from a
// peer that is not trusted (also when none is) or behind a trusted proxy's
// header, is refused: untrusted_proxy.
func TestProxyHeaderFromUntrustedPeer(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		none := newProxyEnv(t, func(c *Config) { c.TrustedProxies = nil })
		defer none.close()
		// A v2 header whose last byte is a line feed (port 522), which
		// x/crypto alone would skip as a line before the version.
		lf := v2Proxy(t, proxyproto.TCPv4, client, "192.0.2.1:522")
		if lf[len(lf)-1] != '\n' {
			t.Fatal("the header does not end in a line feed")
		}
		for _, tt := range []struct {
			env    *proxyEnv
			peer   string
			data   [][]byte
			remote string
			proxy  bool
		}{
			{e, otherPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 51000 22\r\nSSH-2.0-x\r\n")}, otherPeer, false},
			{e, otherPeer, [][]byte{v2For(t, client)}, otherPeer, false},
			{e, otherPeer, [][]byte{lf, []byte("SSH-2.0-x\r\n")}, otherPeer, false},
			{e, otherPeer, [][]byte{proxyproto.SIGV2[:6], proxyproto.SIGV2[6:]}, otherPeer, false},
			{none, otherPeer, [][]byte{[]byte("PROXY TCP4 203.0.113.7 192.0.2.1 51000 22\r\n")}, otherPeer, false},
			{none, proxyPeer, [][]byte{v2For(t, client)}, proxyPeer, false},
			// A second header behind the trusted proxy's.
			{e, proxyPeer, [][]byte{v2For(t, client), []byte("PROXY TCP4 198.51.100.1 192.0.2.1 1 22\r\n")}, client, true},
			{e, proxyPeer, [][]byte{append(bytes.Clone(localV2), localV2...)}, proxyPeer, true},
		} {
			var h *held
			tt.env.endsOnce(t, `gosftpd_connections_total{result="untrusted_proxy"}`, func() { h = tt.env.hold(tt.peer, tt.data...) })
			if h.open() || h.received() != "SSH-2.0-gosftpd\r\n" {
				t.Errorf("%q from %s: open %v, the server sent %q", tt.data, tt.peer, h.open(), h.received())
			}
			r := tt.env.rejects(t)
			last := r[len(r)-1]
			_, viaProxy := last["proxy_addr"]
			if last["reason"] != "untrusted_proxy" || last["remote_addr"] != tt.remote || viaProxy != tt.proxy || last["conn_id"] == nil {
				t.Errorf("%q from %s: conn.reject = %v", tt.data, tt.peer, last)
			}
		}
		warns := e.warnings(t)
		if len(warns) != 1 || warns[0]["peer"] != "198.51.100.9" || !strings.Contains(warns[0]["msg"].(string), "not in server.trusted_proxies") ||
			!strings.Contains(warns[0]["hint"].(string), "already preserves client addresses") {
			t.Errorf("warnings = %v", warns)
		}
		// A minute later: the second header, naming the client and the proxy.
		time.Sleep(time.Minute)
		e.hold(proxyPeer, v2For(t, client), localV2)
		synctest.Wait()
		warns = e.warnings(t)
		if len(warns) != 2 || warns[1]["proxy_addr"] != proxyPeer || warns[1]["remote_addr"] != client || warns[1]["suppressed"] != float64(5) ||
			!strings.Contains(warns[1]["msg"].(string), "second PROXY protocol header") {
			t.Errorf("warnings = %v", warns)
		}
	})
}

// The first-bytes check never holds back a client that sends exactly its
// version line and waits: the server answers with its key exchange.
func TestProxyVersionLineNotHeldBack(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		e := newProxyEnv(t, nil)
		defer e.close()
		const banner = "SSH-2.0-gosftpd\r\n"
		for _, tt := range []struct {
			peer string
			data [][]byte
		}{
			{otherPeer, [][]byte{[]byte("SSH-2.0-x\r\n")}},
			{otherPeer, [][]byte{[]byte("SSH-2.0-\r\n")}},
			{proxyPeer, [][]byte{v2For(t, client), []byte("SSH-2.0-x\r\n")}},
			{proxyPeer, [][]byte{localV2, []byte("SSH-2.0-x\r\n")}},
		} {
			h := e.hold(tt.peer, tt.data...)
			synctest.Wait()
			// The banner, then a binary packet: KEXINIT (message 20).
			got := h.received()
			if !h.open() || !strings.HasPrefix(got, banner) || len(got) <= len(banner)+5 || got[len(banner)+5] != 20 {
				t.Errorf("%q from %s: open %v, the server sent %q", tt.data, tt.peer, h.open(), got)
			}
		}
	})
}

// trusted_proxies is reloadable; each connection keeps the classification
// it got at its accept.
func TestProxyReload(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var cfg Config
		e := newProxyEnv(t, func(c *Config) { c.TrustedProxies = nil; cfg = *c })
		defer e.close()
		before := e.accept("10.0.0.7:1") // accepted while the peer is not trusted
		synctest.Wait()
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		if _, err := e.srv.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		if c, err := e.handshake(before, e.userKey, ""); err != nil {
			t.Errorf("a connection accepted before the reload, without a header: %v", err)
		} else {
			c.Close()
		}
		if c, err := e.login(t, "10.0.0.7:2", v2For(t, client), e.userKey); err != nil {
			t.Errorf("a newly trusted proxy: %v", err)
		} else {
			c.Close()
		}
		e.endsOnce(t, `gosftpd_connections_refused_total{reason="proxy_header"}`, func() { e.hold("10.0.0.7:3", []byte("SSH-2.0-x\r\n")) })
		synctest.Wait()
		lines := e.lines(t)
		if l := connLines(lines, "10.0.0.7:1"); len(l) == 0 || l[0]["proxy_addr"] != nil {
			t.Errorf("the connection accepted before the reload: %v", l)
		}
		if l := connLines(lines, client); len(l) == 0 || l[0]["proxy_addr"] != "10.0.0.7:2" {
			t.Errorf("the connection of the newly trusted proxy: %v", l)
		}
		cfg.TrustedProxies = nil
		if _, err := e.srv.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		e.endsOnce(t, `gosftpd_connections_total{result="untrusted_proxy"}`, func() { e.hold("10.0.0.7:4", v2For(t, client)) })
	})
}

// proxy_addr reaches hook payloads with the other context fields.
func TestProxyAddrInHookPayload(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		rt := &captureTransport{}
		d := hooks.New(hooks.Options{Transport: rt})
		d.Update([]hooks.Spec{{
			Name: "notify", On: []string{"fs.upload"}, Concurrency: 1, Queue: hooks.DefaultQueue,
			Webhook: &hooks.Webhook{URL: "https://receiver.example/hook", Secret: bytes.Repeat([]byte("k"), 32), Timeout: hooks.DefaultHookTime},
		}})
		e := newProxyEnv(t, func(c *Config) { c.Hooks = d })
		defer e.close()
		c, err := e.login(t, proxyPeer, v2For(t, client), e.userKey)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := sftp.NewClient(c)
		if err != nil {
			t.Fatal(err)
		}
		writeRemote(t, sc, "/report.pdf", "data")
		for i := 0; i < 10 && rt.body() == ""; i++ {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		d.Close(time.Now().Add(time.Second))
		e.close() // the transport first, as in pipeServer
		sc.Close()
		var line map[string]any
		if err := json.Unmarshal([]byte(rt.body()), &line); err != nil {
			t.Fatalf("hook payload %q: %v", rt.body(), err)
		}
		if line["event"] != "fs.upload" || line["remote_addr"] != client || line["local_addr"] != clientDst || line["proxy_addr"] != proxyPeer {
			t.Errorf("hook payload = %v", line)
		}
	})
}

// captureTransport answers webhooks with 204 and keeps the first body.
type captureTransport struct {
	mu    sync.Mutex
	first string
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	if c.first == "" {
		c.first = string(b)
	}
	c.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (c *captureTransport) body() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.first
}
