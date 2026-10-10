// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/testutil"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func TestLimiter(t *testing.T) {
	t.Parallel()

	l := newLimiter(3, 2, 2)
	a := netip.MustParsePrefix("192.0.2.1/32")
	b := netip.MustParsePrefix("2001:db8::/64")

	a1, r := l.admit(a)
	a2, r2 := l.admit(a)
	if a1 == nil || a2 == nil || r != "" || r2 != "" {
		t.Fatalf("admit = %v %q, %v %q", a1, r, a2, r2)
	}
	if _, r := l.admit(a); r != rejectPerIP {
		t.Errorf("third connection from one source: reason %q", r)
	}
	if _, r := l.admit(b); r != rejectPreauth {
		t.Errorf("third connection before login: reason %q", r)
	}
	a1.authenticated()
	a1.authenticated() // idempotent
	b1, r := l.admit(b)
	if b1 == nil {
		t.Fatalf("admit after a login: %q", r)
	}
	if _, r := l.admit(netip.Prefix{}); r != rejectMaxConns {
		t.Errorf("fourth connection: reason %q", r)
	}
	for _, x := range []*admission{a1, a2, b1} {
		x.release()
	}
	if l.total != 0 || len(l.sources) != 0 || l.preauth != 0 {
		t.Errorf("after release: total %d, sources %v, preauth %d", l.total, l.sources, l.preauth)
	}
}

// A reload lowers a limit: connections above it stay, new ones are
// refused until the count is below it.
func TestLimiterSetLimits(t *testing.T) {
	t.Parallel()

	l := newLimiter(10, 10, 10)
	var held []*admission
	for range 3 {
		a, r := l.admit(netip.Prefix{})
		if a == nil {
			t.Fatalf("admit: %q", r)
		}
		held = append(held, a)
	}
	l.setLimits(2, 10, 10)
	if _, r := l.admit(netip.Prefix{}); r != rejectMaxConns {
		t.Fatalf("above a lowered limit: reason %q", r)
	}
	held[0].release()
	if _, r := l.admit(netip.Prefix{}); r != rejectMaxConns {
		t.Fatalf("at a lowered limit: reason %q", r)
	}
	held[1].release()
	a, r := l.admit(netip.Prefix{})
	if a == nil {
		t.Fatalf("below a lowered limit: %q", r)
	}
	l.setLimits(10, 10, 1)
	if _, r := l.admit(netip.Prefix{}); r != rejectPreauth {
		t.Errorf("lowered pre-authentication limit: reason %q", r)
	}
	a.release()
	held[2].release()
	if l.total != 0 || l.preauth != 0 {
		t.Errorf("after release: total %d, preauth %d", l.total, l.preauth)
	}
}

func TestRejectLog(t *testing.T) {
	t.Parallel()

	var r rejectLog
	now := time.Now()
	for i := range rejectBurst {
		if ok, _ := r.allow(now); !ok {
			t.Fatalf("event %d suppressed", i)
		}
	}
	for range 5 {
		if ok, _ := r.allow(now); ok {
			t.Fatal("burst not limited")
		}
	}
	ok, suppressed := r.allow(now.Add(time.Second))
	if !ok || suppressed != 5 {
		t.Errorf("next window: ok %v, suppressed %d", ok, suppressed)
	}
}

// silentDial opens a TCP connection that never speaks SSH and reports
// whether the server sent its version line (it was admitted) or closed it.
func silentDial(t *testing.T, addr string, d *net.Dialer) (net.Conn, bool) {
	t.Helper()
	c, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return nil, false
	}
	if !strings.HasPrefix(line, "SSH-2.0-gosftpd") {
		t.Fatalf("version line %q", line)
	}
	return c, true
}

func TestConnectionLimits(t *testing.T) {
	t.Parallel()

	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.MaxConnectionsPerIP = 2
	}})
	var d net.Dialer
	c1, ok1 := silentDial(t, e.addr, &d)
	c2, ok2 := silentDial(t, e.addr, &d)
	if !ok1 || !ok2 {
		t.Fatal("connections under the limit refused")
	}
	if _, ok := silentDial(t, e.addr, &d); ok {
		t.Fatal("third connection from one address admitted")
	}
	c1.Close()
	waitForMsg(t, func() bool {
		c, ok := silentDial(t, e.addr, &d)
		if ok {
			c.Close()
		}
		return ok
	}, func() string { return "slot not freed after a connection closed" })
	c2.Close()

	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"reason":"max_connections_per_ip"`) },
		func() string { return "no conn.reject event:\n" + e.auditLog.String() })
	checkSchema(t, auditLines(t, e.auditLog.String()))
}

func TestBans(t *testing.T) {
	t.Parallel()

	var bans *auth.BanTable
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 2})
		c.Bans = bans
	}})

	// A connection that only completes the key exchange is not a failure.
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ssh.NewClientConn(conn, e.addr, &ssh.ClientConfig{
		User: "alice", HostKeyCallback: ssh.FixedHostKey(e.hostKey),
	}); err == nil {
		t.Fatal("login without credentials")
	}

	// Many wrong keys in one connection count once.
	wrong := []ssh.Signer{signer(t), signer(t), signer(t)}
	dialWrong := func() error {
		c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
			User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(wrong...)},
			HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
		})
		if err == nil {
			c.Close()
		}
		return err
	}
	if dialWrong() == nil {
		t.Fatal("wrong keys accepted")
	}
	if c, err := e.dial(t, e.userKey); err != nil {
		t.Fatalf("banned after one failed connection: %v", err)
	} else {
		c.Close()
	}
	if dialWrong() == nil {
		t.Fatal("wrong keys accepted")
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"event":"auth.ban"`) },
		func() string { return "no auth.ban event:\n" + e.auditLog.String() })

	// Now even the right key is refused before the handshake.
	if _, ok := silentDial(t, e.addr, &net.Dialer{}); ok {
		t.Fatal("banned address admitted")
	}
	if _, err := e.dial(t, e.userKey); err == nil {
		t.Fatal("banned address logged in")
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"reason":"banned"`) },
		func() string { return "no conn.reject event:\n" + e.auditLog.String() })
	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	for _, m := range lines {
		if m["event"] == "auth.ban" && (m["source"] != "127.0.0.1/32" || m["duration_ms"] != float64(auth.DefaultBanDuration.Milliseconds())) {
			t.Errorf("auth.ban = %v", m)
		}
	}
}

func TestPasswordLogin(t *testing.T) {
	t.Parallel()

	h, err := auth.HashPassword([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	ph, err := auth.ParsePasswordHash(h)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(e *env, pw string) error {
		c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
			User: "bob", Auth: []ssh.AuthMethod{ssh.Password(pw)},
			HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
		})
		if err == nil {
			c.Close()
		}
		return err
	}
	users := []auth.User{{Name: "bob", Password: ph}}

	off := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) { c.Auth = auth.NewUsers(users) }})
	if err := dial(off, "s3cret"); err == nil {
		t.Fatal("password login without auth.methods = password")
	}

	e := startWith(t, startOpts{policy: vfs.ConflictRename, categories: []string{audit.CategoryAuth}, tweak: func(c *Config) {
		c.Auth = auth.NewUsers(users)
		c.Methods = []string{auth.MethodPublicKey, auth.MethodPassword}
	}})
	if err := dial(e, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := dial(e, "s3cret"); err != nil {
		t.Fatalf("password login: %v", err)
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"auth_method":"password"`) },
		func() string { return "no auth.success:\n" + e.auditLog.String() })
	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	for _, m := range lines {
		if _, ok := m["key_fp"]; ok && m["event"] == "auth.success" {
			t.Errorf("password login with key_fp: %v", m)
		}
	}
}

func TestCryptoPolicies(t *testing.T) {
	t.Parallel()

	supported, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	never := []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "hmac-sha1", "hmac-sha1-96", "ssh-rsa", "ssh-dss"}
	for _, name := range CryptoPolicies {
		p, err := policy(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range []struct {
			kind      string
			names, ok []string
			bad       []string
		}{
			{"kex", p.kex, supported.KeyExchanges, insecure.KeyExchanges},
			{"cipher", p.ciphers, supported.Ciphers, insecure.Ciphers},
			{"mac", p.macs, supported.MACs, insecure.MACs},
		} {
			for _, a := range list.names {
				switch {
				case !slices.Contains(list.ok, a):
					t.Errorf("%s %s %q is not supported by x/crypto (it would be dropped silently)", name, list.kind, a)
				case slices.Contains(list.bad, a), slices.Contains(never, a), strings.Contains(a, "cbc"):
					t.Errorf("%s %s %q is insecure", name, list.kind, a)
				}
			}
		}
	}
	if _, err := policy("legacy"); err == nil {
		t.Error("unknown policy accepted")
	}

	// A client that offers only compat algorithms gets in with compat only.
	for _, tt := range []struct {
		policy string
		ok     bool
	}{{PolicyModern, false}, {PolicyCompat, true}} {
		e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) { c.CryptoPolicy = tt.policy }})
		for _, algos := range []ssh.Config{
			{KeyExchanges: []string{ssh.KeyExchangeECDHP256}},
			{Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.HMACSHA256}},
		} {
			c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
				Config: algos, User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(e.userKey)},
				HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
			})
			if (err == nil) != tt.ok {
				t.Errorf("%s with %+v: err = %v", tt.policy, algos, err)
			}
			if err == nil {
				c.Close()
			}
		}
	}
}

// pipeServer runs ServeConn on one end of a net.Pipe inside a synctest
// bubble and returns an SFTP client on the other end.
func pipeServer(t *testing.T, cfg Config, wrap func(net.Conn) net.Conn) (*ssh.Client, *sftp.Client, *syncBuffer, func()) {
	t.Helper()
	dir := t.TempDir()
	mounts, err := vfs.Open([]vfs.MountSpec{{Name: "share", Path: dir, Options: vfs.DefaultMountOptions()}}, vfs.Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	user := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(user.PublicKey()), "test")
	hk := signer(t)
	log := &syncBuffer{}
	cfg.HostKeys = []ssh.Signer{hk}
	cfg.Auth = auth.New("", keys)
	cfg.Mounts = mounts
	cfg.Audit = mustAudit(t, log, nil)
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sc, cc := net.Pipe()
	var wg sync.WaitGroup
	wg.Go(func() { srv.ServeConn(sc) })
	var client net.Conn = testutil.NewAsyncConn(cc)
	if wrap != nil {
		client = wrap(client)
	}
	conn, chans, reqs, err := ssh.NewClientConn(client, "pipe", &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(user)}, HostKeyCallback: ssh.FixedHostKey(hk.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	sshc := ssh.NewClient(conn, chans, reqs)
	c, err := sftp.NewClient(sshc)
	if err != nil {
		t.Fatal(err)
	}
	return sshc, c, log, func() {
		// The transport first: a frozen client never sees the server's
		// close otherwise, and the SFTP client would wait for it.
		client.Close()
		c.Close()
		sshc.Close()
		wg.Wait()
		mounts.Close()
	}
}

func closedWith(t *testing.T, log *syncBuffer) string {
	t.Helper()
	for _, m := range auditLines(t, log.String()) {
		if m["event"] == "conn.close" {
			return m["result"].(string)
		}
	}
	return ""
}

func TestIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sshc, c, log, cleanup := pipeServer(t, Config{IdleTimeout: 10 * time.Minute, KeepaliveInterval: -1}, nil)
		defer cleanup()

		for range 3 {
			time.Sleep(9 * time.Minute)
			if _, err := c.Getwd(); err != nil {
				t.Fatalf("connection closed while active: %v", err)
			}
		}
		time.Sleep(10*time.Minute + time.Second)
		synctest.Wait()
		if _, err := c.Getwd(); err == nil {
			t.Error("connection still open after the idle timeout")
		}
		_ = sshc
		if got := closedWith(t, log); got != "idle_timeout" {
			t.Errorf("conn.close result = %q, want idle_timeout\n%s", got, log.String())
		}
	})
}

// freezeConn stops delivering data once frozen, like a peer that vanished:
// a goroutine reads ahead from the connection, and Read stops handing on
// what it got.
type freezeConn struct {
	net.Conn
	data   chan []byte
	frozen chan struct{}
	closed chan struct{}
	buf    []byte
	once   sync.Once
	wg     sync.WaitGroup
}

func newFreezeConn(c net.Conn) *freezeConn {
	f := &freezeConn{Conn: c, data: make(chan []byte), frozen: make(chan struct{}), closed: make(chan struct{})}
	f.wg.Go(func() {
		defer close(f.data)
		for {
			b := make([]byte, 32*1024)
			n, err := c.Read(b)
			if n > 0 {
				select {
				case f.data <- b[:n]:
				case <-f.closed:
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	return f
}

func (f *freezeConn) freeze() { close(f.frozen) }

func (f *freezeConn) Read(p []byte) (int, error) {
	if len(f.buf) == 0 {
		select {
		case <-f.frozen:
			<-f.closed
			return 0, io.EOF
		default:
		}
		select {
		case b, ok := <-f.data:
			if !ok {
				return 0, io.EOF
			}
			f.buf = b
		case <-f.frozen:
			<-f.closed
			return 0, io.EOF
		}
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *freezeConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	err := f.Conn.Close()
	f.wg.Wait()
	return err
}

func TestKeepalive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fc *freezeConn
		wrap := func(c net.Conn) net.Conn {
			fc = newFreezeConn(c)
			return fc
		}
		_, c, log, cleanup := pipeServer(t, Config{IdleTimeout: -1, KeepaliveInterval: 30 * time.Second}, wrap)
		defer cleanup()

		// An idle client that answers keepalives stays connected.
		time.Sleep(time.Hour)
		if _, err := c.Getwd(); err != nil {
			t.Fatalf("idle connection closed although keepalives were answered: %v", err)
		}

		// From now on nothing is answered. Keepalives go out every 30s,
		// the first one 29s after the freeze; the third one left
		// unanswered after it closes the connection, 119s after the freeze.
		time.Sleep(time.Second)
		fc.freeze()
		time.Sleep(110 * time.Second)
		synctest.Wait()
		if got := closedWith(t, log); got != "" {
			t.Fatalf("closed after %d unanswered keepalives, want %d", 2, keepaliveMisses)
		}
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if got := closedWith(t, log); got != "keepalive_timeout" {
			t.Errorf("conn.close result = %q, want keepalive_timeout\n%s", got, log.String())
		}
	})
}

// TestQuickDisconnectAudited: a client that leaves right after logging in is
// still audited (the SSH mux closes the connection when it reads EOF, which
// used to end serveConn before auth.success).
func TestQuickDisconnectAudited(t *testing.T) {
	t.Parallel()

	const n = 50
	e := startWith(t, startOpts{
		policy:     vfs.ConflictRename,
		categories: []string{audit.CategoryConn, audit.CategoryAuth},
		tweak:      func(c *Config) { c.MaxConnectionsPerIP, c.MaxPreauthConnections = n, n },
	})
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			c, err := e.dial(t, e.userKey)
			if err != nil {
				t.Error(err)
				return
			}
			c.Close()
		})
	}
	wg.Wait()
	count := func(ev string) int { return strings.Count(e.auditLog.String(), `"event":"`+ev+`"`) }
	waitForMsg(t, func() bool { return count("auth.success") == n && count("conn.close") == n },
		func() string {
			return fmt.Sprintf("%d auth.success and %d conn.close events for %d logins", count("auth.success"), count("conn.close"), n)
		})
}

func TestPinnedUser(t *testing.T) {
	t.Parallel()

	var p pinnedUser
	for i, tt := range []struct {
		name string
		want bool
	}{{"alice", true}, {"alice", true}, {"bob", false}, {"", false}, {"alice", true}} {
		if got := p.same(tt.name); got != tt.want {
			t.Errorf("call %d: same(%q) = %v, want %v", i, tt.name, got, tt.want)
		}
	}
}

// TestPasswordFailuresBan: every wrong password counts toward a ban at
// once, also in a connection that then logs in, and a connection opened
// before the ban gets no further guesses; rejected keys before a login do
// not count.
func TestPasswordFailuresBan(t *testing.T) {
	t.Parallel()

	h, err := auth.HashPassword([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := auth.ParsePasswordHash(h)
	key := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(key.PublicKey()), "test")
	var bans *auth.BanTable
	e := startWith(t, startOpts{policy: vfs.ConflictRename, categories: []string{audit.CategoryAuth}, tweak: func(c *Config) {
		c.Auth = auth.NewUsers([]auth.User{{Name: "bob", Password: ph, Keys: keys}})
		c.Methods = []string{auth.MethodPublicKey, auth.MethodPassword}
		bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 3})
		c.Bans = bans
	}})
	login := func(methods ...ssh.AuthMethod) error {
		c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
			User: "bob", Auth: methods, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
		})
		if err == nil {
			c.Close()
		}
		return err
	}
	passwords := func(pws ...string) ssh.AuthMethod {
		return ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			pw := pws[0]
			pws = pws[1:]
			return pw, nil
		}), len(pws))
	}
	lo := netip.MustParseAddr("127.0.0.1")

	// An agent with many keys: rejected keys before the right one are free.
	for range 3 {
		if err := login(ssh.PublicKeys(signer(t), signer(t), signer(t), key)); err != nil {
			t.Fatal(err)
		}
	}
	if f, _ := bans.Len(); f != 0 {
		t.Fatalf("%d sources with failures after logins with an agent", f)
	}

	// Two wrong passwords, then the right key: both passwords count.
	if err := login(passwords("guess1", "guess2"), ssh.PublicKeys(key)); err != nil {
		t.Fatal(err)
	}
	if bans.Banned(lo) {
		t.Fatal("banned after two failures")
	}

	// The third wrong password bans at once; the right password on the
	// same connection is then refused unchecked.
	if err := login(passwords("guess3", "s3cret", "s3cret")); err == nil {
		t.Fatal("logged in after the ban")
	}
	if !bans.Banned(lo) {
		t.Fatal("not banned after three wrong passwords")
	}
	if n := strings.Count(e.auditLog.String(), `"event":"auth.ban"`); n != 1 {
		t.Errorf("%d auth.ban events, want 1", n)
	}
}

// fakeMeta is the ssh.ConnMetadata of a connection attempt.
type fakeMeta struct {
	ssh.ConnMetadata
	user string
}

func (m fakeMeta) User() string         { return m.user }
func (m fakeMeta) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1} }

// TestUserNameChange: after an attempt as one user, a connection cannot
// log in as another (x/crypto allows it; sshd does not).
func TestUserNameChange(t *testing.T) {
	t.Parallel()

	h, err := auth.HashPassword([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := auth.ParsePasswordHash(h)
	alice := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(alice.PublicKey()), "test")
	authn := auth.NewUsers([]auth.User{{Name: "alice", Keys: keys}, {Name: "bob", Password: ph}})
	srv, err := New(Config{
		HostKeys: []ssh.Signer{signer(t)}, Auth: authn, Mounts: &vfs.Table{},
		Methods: []string{auth.MethodPublicKey, auth.MethodPassword},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, first := range []string{"none", auth.MethodPassword} {
		sc, cc := net.Pipe()
		ca := srv.newConnAuth(sc, audit.Discard())
		cfg := ca.config(srv.snap.Load())
		bob := fakeMeta{user: "bob"}
		if first == "none" {
			cfg.AuthLogCallback(bob, "none", errors.New("none"))
		} else {
			_, err := cfg.PasswordCallback(bob, []byte("wrong"))
			cfg.AuthLogCallback(bob, auth.MethodPassword, err)
		}
		if _, err := cfg.PublicKeyCallback(fakeMeta{user: "alice"}, alice.PublicKey()); !errors.Is(err, errUserChanged) {
			t.Errorf("after %s as bob, alice's key: err = %v, want errUserChanged", first, err)
		}
		if _, err := cfg.PasswordCallback(fakeMeta{user: "alice"}, []byte("s3cret")); !errors.Is(err, errUserChanged) {
			t.Errorf("after %s as bob, a password as alice: err = %v", first, err)
		}
		if _, err := cfg.PasswordCallback(bob, []byte("s3cret")); err != nil {
			t.Errorf("after %s as bob, bob's password: %v", first, err)
		}
		sc.Close()
		cc.Close()
	}
}

// TestMethods: auth.methods turns each method on or off.
func TestMethods(t *testing.T) {
	t.Parallel()

	h, err := auth.HashPassword([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := auth.ParsePasswordHash(h)
	key := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(key.PublicKey()), "test")
	for _, tt := range []struct {
		methods       []string
		keyOK, passOK bool
	}{
		{nil, true, false},
		{[]string{auth.MethodPublicKey}, true, false},
		{[]string{auth.MethodPassword}, false, true},
		{[]string{auth.MethodPassword, auth.MethodPublicKey}, true, true},
	} {
		e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
			c.Auth = auth.NewUsers([]auth.User{{Name: "bob", Password: ph, Keys: keys}})
			c.Methods = tt.methods
		}})
		for _, m := range []struct {
			name   string
			method ssh.AuthMethod
			want   bool
		}{{"publickey", ssh.PublicKeys(key), tt.keyOK}, {"password", ssh.Password("s3cret"), tt.passOK}} {
			c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
				User: "bob", Auth: []ssh.AuthMethod{m.method}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
			})
			if (err == nil) != m.want {
				t.Errorf("methods %v, %s login: err = %v", tt.methods, m.name, err)
			}
			if err == nil {
				c.Close()
			}
		}
	}
	if _, err := New(Config{HostKeys: []ssh.Signer{signer(t)}, Auth: auth.New("", nil), Mounts: &vfs.Table{}, Methods: []string{"hostbased"}}); err == nil {
		t.Error("unknown method accepted")
	}
}

// TestNegativeLimits: negative values in Config mean the default, except
// for the two timeouts where they mean off.
func TestNegativeLimits(t *testing.T) {
	t.Parallel()

	srv, err := New(Config{
		HostKeys: []ssh.Signer{signer(t)}, Auth: auth.New("", nil), Mounts: &vfs.Table{},
		HandshakeTimeout: -1, MaxConnections: -1, MaxConnectionsPerIP: -1, MaxPreauthConnections: -1,
		MaxSessionsPerConn: -1, MaxAuthTries: -1, IdleTimeout: -1, KeepaliveInterval: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sn := srv.snap.Load()
	c := sn.cfg
	if c.HandshakeTimeout != DefaultHandshakeTimeout || c.MaxConnections != DefaultMaxConnections ||
		c.MaxConnectionsPerIP != DefaultMaxPerSource || c.MaxPreauthConnections != DefaultMaxPreauth ||
		c.MaxSessionsPerConn != DefaultMaxSessions || c.MaxAuthTries != DefaultMaxAuthTries || sn.ssh.MaxAuthTries != DefaultMaxAuthTries {
		t.Errorf("negative limits did not become the defaults: %+v", c)
	}
	if c.IdleTimeout != 0 || c.KeepaliveInterval != 0 {
		t.Errorf("negative timeouts: idle %v, keepalive %v, want 0 (off)", c.IdleTimeout, c.KeepaliveInterval)
	}
	zero, err := New(Config{HostKeys: []ssh.Signer{signer(t)}, Auth: auth.New("", nil), Mounts: &vfs.Table{}})
	if err != nil {
		t.Fatal(err)
	}
	if zc := zero.snap.Load().cfg; zc.IdleTimeout != DefaultIdleTimeout || zc.KeepaliveInterval != DefaultKeepaliveInterval {
		t.Errorf("zero timeouts: idle %v, keepalive %v, want the defaults", zc.IdleTimeout, zc.KeepaliveInterval)
	}
}

// A login with the right key of an expired account is refused like any
// other failure, and the audit log says why.
func TestRefusalReasonAudited(t *testing.T) {
	t.Parallel()

	key := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(key.PublicKey()), "test")
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Auth = auth.NewUsers([]auth.User{{Name: "bob", Keys: keys, Expires: time.Now().Add(-time.Hour)}})
	}})
	if c, err := e.dialAs(t, "bob", key); err == nil {
		c.Close()
		t.Fatal("an expired account logged in")
	}
	if c, err := e.dialAs(t, "bob", signer(t)); err == nil {
		c.Close()
		t.Fatal("a wrong key logged in")
	}
	waitForMsg(t, func() bool { return strings.Count(e.auditLog.String(), `"event":"auth.failure"`) == 2 },
		func() string { return "auth.failure events:\n" + e.auditLog.String() })
	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	var reasons []any
	for _, l := range lines {
		if l["event"] == "auth.failure" {
			reasons = append(reasons, l["reason"])
		}
	}
	if len(reasons) != 2 || reasons[0] != "expired" || reasons[1] != nil {
		t.Errorf("auth.failure reasons = %v, want [expired <nil>]", reasons)
	}
}

// probeSigner holds only a public key; a client calls Sign only after the
// server accepted the key in a query (PK_OK).
type probeSigner struct {
	pub    ssh.PublicKey
	signed atomic.Bool
}

func (p *probeSigner) PublicKey() ssh.PublicKey { return p.pub }

func (p *probeSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	p.signed.Store(true)
	return nil, errors.New("no private key")
}

// Offering the public key of an account that may not log in fails like an
// unknown key: no PK_OK reveals the account, and the attempt counts toward
// a ban. The audit log has the reason.
func TestNoKeyOracle(t *testing.T) {
	t.Parallel()

	key := signer(t)
	keys, _ := auth.ParseAuthorizedKeys(ssh.MarshalAuthorizedKey(key.PublicKey()), "test")
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Auth = auth.NewUsers([]auth.User{{Name: "bob", Keys: keys, Disabled: true}})
		c.Bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 1})
	}})
	probe := &probeSigner{pub: key.PublicKey()}
	if c, err := e.dialAs(t, "bob", probe); err == nil {
		c.Close()
		t.Fatal("logged in without a private key")
	}
	if probe.signed.Load() {
		t.Error("the server accepted the key of a disabled account in a query (PK_OK)")
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"reason":"disabled"`) },
		func() string { return "no auth.failure with reason disabled:\n" + e.auditLog.String() })
	waitForMsg(t, func() bool {
		c, err := e.dialAs(t, "bob", key)
		if err == nil {
			c.Close()
		}
		return strings.Contains(e.auditLog.String(), `"reason":"banned"`)
	}, func() string { return "the probe did not count toward a ban:\n" + e.auditLog.String() })
}
