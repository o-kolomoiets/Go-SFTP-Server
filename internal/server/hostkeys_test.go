// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

const openSSHVersion = "SSH-2.0-OpenSSH_9.6"

// rsaSigner returns an RSA key that signs with SHA-2 only, as host keys do.
func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// hostKeyConn is a logged-in client connection with its global requests.
type hostKeyConn struct {
	conn ssh.Conn
	reqs <-chan *ssh.Request
	kex  *keyLog
}

// keyLog records the host key of every key exchange.
type keyLog struct {
	mu   sync.Mutex
	keys []ssh.PublicKey
}

func (l *keyLog) callback(_ string, _ net.Addr, key ssh.PublicKey) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key)
	return nil
}

func (l *keyLog) all() []ssh.PublicKey {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ssh.PublicKey(nil), l.keys...)
}

// dialHostKeys logs in as an OpenSSH client (unless version says
// otherwise) and returns the connection with its global requests.
func (e *env) dialHostKeys(t *testing.T, version string, tweak func(*ssh.ClientConfig)) *hostKeyConn {
	t.Helper()
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	kl := &keyLog{}
	cfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(e.userKey)},
		HostKeyCallback: kl.callback,
		ClientVersion:   version,
	}
	if tweak != nil {
		tweak(cfg)
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, e.addr, cfg)
	if err != nil {
		nc.Close()
		t.Fatal(err)
	}
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "")
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return &hostKeyConn{conn: conn, reqs: reqs, kex: kl}
}

// announced returns the keys of the hostkeys-00 request, which the server
// sends before it serves channels: so after a channel was opened, it was
// received if it was sent.
func (c *hostKeyConn) announced(t *testing.T) [][]byte {
	t.Helper()
	ch, creqs, err := c.conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(creqs)
	ch.Close()
	var keys [][]byte
	for {
		select {
		case req := <-c.reqs:
			if req.Type != hostkeysRequest || req.WantReply || keys != nil {
				t.Fatalf("global request %q (want reply %v); announced before: %d keys", req.Type, req.WantReply, len(keys))
			}
			payload := req.Payload
			keys = [][]byte{}
			for len(payload) > 0 {
				k, rest, ok := parseString(payload)
				if !ok {
					t.Fatalf("malformed hostkeys-00 payload %x", req.Payload)
				}
				keys, payload = append(keys, k), rest
			}
		default:
			return keys
		}
	}
}

// prove sends a proof request for keys.
func (c *hostKeyConn) prove(t *testing.T, keys ...[]byte) (bool, []byte) {
	t.Helper()
	var payload []byte
	for _, k := range keys {
		payload = appendString(payload, k)
	}
	ok, resp, err := c.conn.SendRequest(proveRequest, true, payload)
	if err != nil {
		t.Fatal(err)
	}
	return ok, resp
}

// verifyProof checks the signatures of a proof of keys.
func (c *hostKeyConn) verifyProof(t *testing.T, resp []byte, keys ...ssh.PublicKey) []string {
	t.Helper()
	var formats []string
	for _, k := range keys {
		blob, rest, ok := parseString(resp)
		if !ok {
			t.Fatalf("proof too short for %s", ssh.FingerprintSHA256(k))
		}
		resp = rest
		var sig ssh.Signature
		if err := ssh.Unmarshal(blob, &sig); err != nil {
			t.Fatal(err)
		}
		data := ssh.Marshal(struct {
			Type      string
			SessionID []byte
			Key       []byte
		}{proveRequest, c.conn.SessionID(), k.Marshal()})
		if err := k.Verify(data, &sig); err != nil {
			t.Errorf("proof of %s: %v", ssh.FingerprintSHA256(k), err)
		}
		formats = append(formats, sig.Format)
	}
	if len(resp) > 0 {
		t.Errorf("%d bytes after the signatures", len(resp))
	}
	return formats
}

func blobs(keys ...ssh.Signer) [][]byte {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = k.PublicKey().Marshal()
	}
	return out
}

// An OpenSSH client learns the host keys and the next key after login, and
// the server proves that it holds them, once per connection.
func TestHostKeyAnnouncement(t *testing.T) {
	t.Parallel()

	next, old := signer(t), rsaSigner(t)
	var hk ssh.Signer
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		hk = c.HostKeys[0]
		c.AnnouncedKeys = []ssh.Signer{next, old}
		c.AnnounceHostKeys = true
	}})
	c := e.dialHostKeys(t, openSSHVersion, nil)
	got := c.announced(t)
	want := blobs(hk, next, old)
	if len(got) != len(want) {
		t.Fatalf("announced %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("announced key %d differs", i)
		}
	}

	ok, resp := c.prove(t, want[1], want[2])
	if !ok {
		t.Fatal("proof refused")
	}
	formats := c.verifyProof(t, resp, next.PublicKey(), old.PublicKey())
	// The connection's key exchange used ed25519: RSA proofs use SHA-512.
	if formats[1] != ssh.KeyAlgoRSASHA512 {
		t.Errorf("RSA proof format = %s, want %s", formats[1], ssh.KeyAlgoRSASHA512)
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"event":"conn.hostkeys_proved"`) },
		func() string { return "no conn.hostkeys_proved event: " + e.auditLog.String() })
	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	for _, l := range lines {
		if l["event"] == "conn.hostkeys_proved" {
			if fps := ssh.FingerprintSHA256(next.PublicKey()) + "," + ssh.FingerprintSHA256(old.PublicKey()); l["key_fps"] != fps || l["user"] != "alice" {
				t.Errorf("conn.hostkeys_proved = %v, want key_fps %s", l, fps)
			}
		}
	}

	// One proof per connection; other requests are refused as before.
	if ok, _ := c.prove(t, want[1]); ok {
		t.Error("a second proof was answered")
	}
	if ok, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil); err != nil || ok {
		t.Errorf("keepalive = %v, %v; want refused", ok, err)
	}
}

// Only OpenSSH clients get the announcement, and only when it is on.
func TestHostKeyAnnouncementSkipped(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, version string
		on            bool
	}{
		{"not OpenSSH", "SSH-2.0-Go", true},
		{"Cisco", "SSH-2.0-Cisco-1.25", true},
		{"turned off", openSSHVersion, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
				c.AnnouncedKeys = []ssh.Signer{signer(t)}
				c.AnnounceHostKeys = tc.on
			}})
			c := e.dialHostKeys(t, tc.version, nil)
			if keys := c.announced(t); keys != nil {
				t.Errorf("announced %d keys", len(keys))
			}
			if ok, _ := c.prove(t, e.hostKey.Marshal()); ok {
				t.Error("proof answered without an announcement")
			}
		})
	}
}

// A proof request must name announced keys, each once, in a well-formed
// payload; anything else is refused, and uses up the connection's proof.
func TestHostKeyProofRefused(t *testing.T) {
	t.Parallel()

	next := signer(t)
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.AnnouncedKeys = []ssh.Signer{next}
		c.AnnounceHostKeys = true
	}})
	nb := next.PublicKey().Marshal()
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"unknown key", appendString(nil, signer(t).PublicKey().Marshal())},
		{"twice", appendString(appendString(nil, nb), nb)},
		{"truncated", appendString(nil, nb)[:10]},
		{"trailing bytes", append(appendString(nil, nb), 0)},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := e.dialHostKeys(t, openSSHVersion, nil)
			c.announced(t)
			ok, _, err := c.conn.SendRequest(proveRequest, true, tc.payload)
			if err != nil || ok {
				t.Fatalf("proof = %v, %v; want refused", ok, err)
			}
			if ok, _ := c.prove(t, nb); ok {
				t.Error("a proof after a refused one was answered")
			}
		})
	}
}

// RSA proofs use the RSA algorithm of the connection's key exchange: the
// OpenSSH client verifies them with it.
func TestHostKeyProofRSAAlgorithm(t *testing.T) {
	t.Parallel()

	hk, next := rsaSigner(t), rsaSigner(t)
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.HostKeys = []ssh.Signer{hk}
		c.AnnouncedKeys = []ssh.Signer{next}
		c.AnnounceHostKeys = true
	}})
	for _, algo := range []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		t.Run(algo, func(t *testing.T) {
			t.Parallel()
			c := e.dialHostKeys(t, openSSHVersion, func(cfg *ssh.ClientConfig) { cfg.HostKeyAlgorithms = []string{algo} })
			c.announced(t)
			ok, resp := c.prove(t, blobs(hk, next)...)
			if !ok {
				t.Fatal("proof refused")
			}
			for _, f := range c.verifyProof(t, resp, hk.PublicKey(), next.PublicKey()) {
				if f != algo {
					t.Errorf("proof format = %s, want %s", f, algo)
				}
			}
		})
	}
}

// hostCert certifies key as a host certificate valid from after to before.
func hostCert(t *testing.T, ca, key ssh.Signer, after, before time.Time) ssh.Signer {
	t.Helper()
	c := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "host",
		ValidPrincipals: []string{"127.0.0.1"},
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(c, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A host certificate is offered while it is valid; clients that trust its
// CA accept the host without knowing its key. Connections accepted at the
// same time each get their own configuration (run with -race).
func TestHostCertificate(t *testing.T) {
	t.Parallel()

	ca := signer(t)
	var (
		mu  sync.Mutex
		now time.Time
	)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	e := startWith(t, startOpts{policy: vfs.ConflictRename, server: func(s *Server) { s.now = clock }, tweak: func(c *Config) {
		// Three host keys (an array with room for a fourth) and two
		// certificates: connections that shared the array of a common
		// configuration would write the same element.
		ec := ecdsaSigner(t)
		c.HostKeys = append(c.HostKeys, ec, rsaSigner(t))
		c.HostCertificates = []ssh.Signer{
			hostCert(t, ca, c.HostKeys[0], time.Now().Add(-time.Hour), time.Now().Add(time.Hour)),
			hostCert(t, ca, ec, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)),
		}
	}})
	setNow := func(t time.Time) { mu.Lock(); now = t; mu.Unlock() }

	checker := &ssh.CertChecker{IsHostAuthority: func(auth ssh.PublicKey, _ string) bool { return bytes.Equal(auth.Marshal(), ca.PublicKey().Marshal()) }}
	certOnly := func(cfg *ssh.ClientConfig) {
		cfg.HostKeyCallback = checker.CheckHostKey
		cfg.HostKeyAlgorithms = []string{ssh.CertAlgoED25519v01}
	}
	dial := func() error {
		d := net.Dialer{Timeout: 10 * time.Second}
		nc, err := d.DialContext(t.Context(), "tcp", e.addr)
		if err != nil {
			return err
		}
		cfg := &ssh.ClientConfig{User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(e.userKey)}}
		certOnly(cfg)
		conn, chans, reqs, err := ssh.NewClientConn(nc, e.addr, cfg)
		if err != nil {
			nc.Close()
			return err
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
		return conn.Close()
	}

	setNow(time.Now())
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- dial() })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("certificate host key: %v", err)
		}
	}

	// Expired, or not valid yet: not offered, so a client that accepts only
	// certificates finds no common algorithm.
	for _, at := range []time.Time{time.Now().Add(2 * time.Hour), time.Now().Add(-2 * time.Hour)} {
		setNow(at)
		if err := dial(); err == nil {
			t.Errorf("at %v: an invalid certificate was offered", at)
		}
	}
	// A client that knows the plain key still connects.
	e.dialHostKeys(t, "SSH-2.0-Go", func(cfg *ssh.ClientConfig) {
		cfg.HostKeyCallback = ssh.FixedHostKey(e.hostKey)
		cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
	})
}

// Host key changes apply to new connections; an open connection keeps its
// host key when it re-keys.
func TestHostKeyReload(t *testing.T) {
	t.Parallel()

	e := start(t, vfs.ConflictRename, false)
	c := e.dialHostKeys(t, "SSH-2.0-Go", func(cfg *ssh.ClientConfig) { cfg.RekeyThreshold = 1024 })

	newKey := signer(t)
	cfg := e.cfg
	cfg.HostKeys = []ssh.Signer{newKey}
	if _, err := e.srv.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	// Traffic re-keys the open connection a few times.
	for range 20 {
		if _, _, err := c.conn.SendRequest("ping@example.org", true, bytes.Repeat([]byte{1}, 512)); err != nil {
			t.Fatal(err)
		}
	}
	keys := c.kex.all()
	if len(keys) < 2 {
		t.Fatalf("%d key exchanges, want re-keying", len(keys))
	}
	for _, k := range keys {
		if !bytes.Equal(k.Marshal(), e.hostKey.Marshal()) {
			t.Fatalf("the open connection re-keyed with %s", ssh.FingerprintSHA256(k))
		}
	}
	c2 := e.dialHostKeys(t, "SSH-2.0-Go", nil)
	if k := c2.kex.all()[0]; !bytes.Equal(k.Marshal(), newKey.PublicKey().Marshal()) {
		t.Errorf("a new connection got %s, want the reloaded key", ssh.FingerprintSHA256(k))
	}
}

// The host keys are checked: one per type, none twice, certificates of
// host keys only.
func TestHostKeyConfig(t *testing.T) {
	t.Parallel()

	hk, other := signer(t), signer(t)
	ca := signer(t)
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"none", Config{}, "no host keys"},
		{"two of a type", Config{HostKeys: []ssh.Signer{hk, other}}, "two host keys of type"},
		{"next is a host key", Config{HostKeys: []ssh.Signer{hk}, AnnouncedKeys: []ssh.Signer{hk}}, "given twice"},
		{"certificate of another key", Config{HostKeys: []ssh.Signer{hk}, HostCertificates: []ssh.Signer{hostCert(t, ca, other, time.Now(), time.Now().Add(time.Hour))}}, "not one of the host keys"},
		{"not a certificate", Config{HostKeys: []ssh.Signer{hk}, HostCertificates: []ssh.Signer{other}}, "without a host certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := hostKeySet(&tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("hostKeySet() = %v, want %q", err, tc.want)
			}
		})
	}
}
