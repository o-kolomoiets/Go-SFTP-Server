// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var certNow = time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// issue signs a user certificate for key, valid an hour around certNow for
// the principal alice, changed by edit.
func issue(t *testing.T, ca ssh.Signer, key ssh.PublicKey, edit func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key:             key,
		CertType:        ssh.UserCert,
		KeyId:           "alice-laptop",
		Serial:          7,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(certNow.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(certNow.Add(time.Hour).Unix()),
	}
	if edit != nil {
		edit(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func caLineFor(t *testing.T, options string, ca ssh.Signer) Key {
	t.Helper()
	keys, warns := ParseAuthorizedKeys([]byte(authorizedLine(t, options, ca.PublicKey())), "ca")
	if len(warns) > 0 || len(keys) != 1 {
		t.Fatalf("%q: %v", options, warns)
	}
	return keys[0]
}

func trusting(users []User, cas []ssh.PublicKey, revoked *RevokedKeys) *Authenticator {
	a := NewUsers(users)
	a.Trust(cas, revoked)
	a.now = func() time.Time { return certNow }
	return a
}

func revokedOf(t *testing.T, keys ...ssh.PublicKey) *RevokedKeys {
	t.Helper()
	var data []byte
	for _, k := range keys {
		data = append(data, ssh.MarshalAuthorizedKey(k)...)
	}
	r := &RevokedKeys{}
	if err := r.Add(data, "revoked"); err != nil {
		t.Fatal(err)
	}
	return r
}

// outcome runs KnownKey and names the result: "ok", "denied" (like a wrong
// key) or the reason.
func outcome(t *testing.T, a *Authenticator, conn ssh.ConnMetadata, key ssh.PublicKey) string {
	t.Helper()
	perms, err := a.KnownKey(conn, key)
	if err == nil {
		if u, _ := UserFrom(perms); u != conn.User() {
			t.Errorf("user = %q, want %q", u, conn.User())
		}
		return "ok"
	}
	if perms != nil {
		t.Error("permissions with an error")
	}
	if re, ok := errors.AsType[*RefusedError](err); ok {
		return re.Reason
	}
	if !errors.Is(err, errDenied) {
		t.Errorf("error %v is neither a refusal nor errDenied", err)
	}
	return "denied"
}

func TestCertificateChecks(t *testing.T) {
	t.Parallel()

	ca, other := newSigner(t), newSigner(t)
	key := newKey(t)
	rsaCA := rsaSHA1Signer(t)
	alice := User{Name: "alice"}
	cas := []ssh.PublicKey{ca.PublicKey(), rsaCA.PublicKey()}
	in, out := tcp("10.1.2.3"), tcp("192.0.2.9")

	tests := []struct {
		name  string
		users []User
		cas   []ssh.PublicKey
		rev   []ssh.PublicKey
		cert  *ssh.Certificate
		conn  fakeConn
		want  string
	}{
		{"trusted CA, principal is the name", nil, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice"}, "ok"},
		{"other principal", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"bob"} }), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"no principals", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = nil }), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"empty principal", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"", "alice"} }), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"untrusted CA", nil, nil, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, "denied"},
		{"host certificate", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.CertType = ssh.HostCert }), fakeConn{user: "alice"}, "denied"},
		{"forged signature", nil, nil, nil, forge(issue(t, ca, key, nil)), fakeConn{user: "alice"}, "denied"},
		{"forged and expired", nil, nil, nil, forge(issue(t, ca, key, func(c *ssh.Certificate) { c.ValidBefore = uint64(certNow.Add(-time.Minute).Unix()) })), fakeConn{user: "alice"}, "denied"},
		{"unknown user", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"mallory"} }), fakeConn{user: "mallory"}, "denied"},
		{"expired", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidBefore = uint64(certNow.Unix()) }), fakeConn{user: "alice"}, ReasonCertExpired},
		{"not yet valid", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidAfter = uint64(certNow.Add(time.Minute).Unix()) }), fakeConn{user: "alice"}, ReasonCertNotYetValid},
		{"valid forever", nil, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 0, ssh.CertTimeInfinity }), fakeConn{user: "alice"}, "ok"},
		{"force-command internal-sftp", nil, nil, nil, issue(t, ca, key, critical(forceCommand, "internal-sftp")), fakeConn{user: "alice"}, "ok"},
		{"force-command sftp-server", nil, nil, nil, issue(t, ca, key, critical(forceCommand, "/usr/lib/openssh/sftp-server")), fakeConn{user: "alice"}, "ok"},
		{"force-command with arguments", nil, nil, nil, issue(t, ca, key, critical(forceCommand, "internal-sftp -R")), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"force-command shell", nil, nil, nil, issue(t, ca, key, critical(forceCommand, "/bin/sh")), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"verify-required", nil, nil, nil, issue(t, ca, key, critical("verify-required", "")), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"unknown critical option", nil, nil, nil, issue(t, ca, key, critical("x@example.com", "y")), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"source-address matches", nil, nil, nil, issue(t, ca, key, critical(sourceAddress, "10.0.0.0/8")), fakeConn{user: "alice", addr: in}, "ok"},
		{"source-address does not match", nil, nil, nil, issue(t, ca, key, critical(sourceAddress, "10.0.0.0/8")), fakeConn{user: "alice", addr: out}, ReasonAddress},
		{"invalid source-address", nil, nil, nil, issue(t, ca, key, critical(sourceAddress, "*.example.org")), fakeConn{user: "alice", addr: in}, ReasonCertInvalid},
		{"SHA-1 CA signature", nil, nil, nil, issue(t, rsaCA, key, nil), fakeConn{user: "alice"}, ReasonCertInvalid},
		{"certified key revoked", nil, nil, []ssh.PublicKey{key}, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonKeyRevoked},
		{"CA revoked", nil, nil, []ssh.PublicKey{ca.PublicKey()}, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonKeyRevoked},
		{"revoked before disabled", []User{{Name: "alice", Disabled: true}}, nil, []ssh.PublicKey{key}, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonKeyRevoked},
		{"disabled before expired certificate", []User{{Name: "alice", Disabled: true}}, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 0, 1 }), fakeConn{user: "alice"}, ReasonDisabled},
		{"account expired", []User{{Name: "alice", Expires: certNow.Add(-time.Second)}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonExpired},
		{"allow_from", []User{{Name: "alice", AllowFrom: mustPrefixes(t, "10.0.0.0/8")}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice", addr: out}, ReasonAddress},
		{"mapped principal", []User{{Name: "alice", Principals: []string{"alice@corp"}}}, nil, nil, issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"alice@corp"} }), fakeConn{user: "alice"}, "ok"},
		{"name no longer a principal when mapped", []User{{Name: "alice", Principals: []string{"alice@corp"}}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"principals = [] keeps trusted CAs out", []User{{Name: "alice", Principals: []string{}}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"CA line without principals=", []User{{Name: "alice", Keys: []Key{caLineFor(t, "cert-authority", other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, "ok"},
		{"CA line, other name", []User{{Name: "alice", Keys: []Key{caLineFor(t, "cert-authority", other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"bob"} }), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"CA line principals=", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,principals="alice@corp,ops"`, other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"ops"} }), fakeConn{user: "alice"}, "ok"},
		{"CA line principals= replaces the name", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,principals="ops"`, other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, ReasonCertPrincipal},
		{"CA line from=", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,from="10.0.0.0/8"`, other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice", addr: out}, ReasonAddress},
		{"CA line from= and source-address both apply", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,from="192.0.2.0/24"`, other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, critical(sourceAddress, "10.0.0.0/8")), fakeConn{user: "alice", addr: out}, ReasonAddress},
		{"CA line expiry-time", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,expiry-time="20261231"`, other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, ReasonKeyExpired},
		{"another user's CA line", []User{alice, {Name: "bob", Keys: []Key{caLineFor(t, "cert-authority", other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, "denied"},
		{"second CA line accepts", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,principals="x"`, other), caLineFor(t, "cert-authority", other)}}}, []ssh.PublicKey{}, nil, issue(t, other, key, nil), fakeConn{user: "alice"}, "ok"},
		{"reason of the source that got furthest", []User{{Name: "alice", Principals: []string{"x"}, Keys: []Key{caLineFor(t, `cert-authority,expiry-time="20261231"`, ca)}}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice"}, ReasonKeyExpired},
		{"either source accepts", []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,from="10.0.0.0/8"`, ca)}}}, nil, nil, issue(t, ca, key, nil), fakeConn{user: "alice", addr: out}, "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := tt.users
			if users == nil {
				users = []User{alice}
			}
			trusted := tt.cas
			if trusted == nil {
				trusted = cas
			}
			var rev *RevokedKeys
			if tt.rev != nil {
				rev = revokedOf(t, tt.rev...)
			}
			a := trusting(users, trusted, rev)
			if got := outcome(t, a, tt.conn, tt.cert); got != tt.want {
				t.Errorf("KnownKey = %s, want %s", got, tt.want)
			}
		})
	}
}

func tcp(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 22} }

func critical(name, value string) func(*ssh.Certificate) {
	return func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{name: value} }
}

// forge changes cert after it was signed, so that the signature no longer
// verifies.
func forge(cert *ssh.Certificate) *ssh.Certificate {
	c := *cert
	c.KeyId += "-forged"
	return &c
}

// rsaSHA1Signer returns an RSA CA that signs with ssh-rsa (SHA-1).
func rsaSHA1Signer(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	as, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	return as
}

func TestCertificatePermissions(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newKey(t)
	a := trusting([]User{{Name: "alice"}}, []ssh.PublicKey{ca.PublicKey()}, nil)
	cert := issue(t, ca, key, func(c *ssh.Certificate) {
		c.Serial = math.MaxUint64
		c.KeyId = strings.Repeat("é", 200) // 400 bytes
		c.CriticalOptions = map[string]string{sourceAddress: "192.0.2.0/24"}
		c.Extensions = map[string]string{ExtUser: "root", noTouchRequired: "", "permit-pty": ""}
	})
	perms, err := a.KnownKey(fakeConn{user: "alice"}, cert)
	if err != nil {
		t.Fatal(err)
	}
	ext := perms.Extensions
	if ext[ExtUser] != "alice" || ext[ExtMethod] != MethodPublicKey {
		t.Errorf("identity %q/%q: the certificate's extensions leaked in", ext[ExtUser], ext[ExtMethod])
	}
	if _, ok := ext[noTouchRequired]; ok {
		t.Error("no-touch-required in Permissions: x/crypto would waive touch for lines that do not allow it")
	}
	if _, ok := ext["permit-pty"]; ok {
		t.Error("certificate extensions copied")
	}
	if ext[ExtFingerprint] != ssh.FingerprintSHA256(key) {
		t.Errorf("pubkey-fp = %q, want the certified key's", ext[ExtFingerprint])
	}
	if ext[ExtCertSerial] != "18446744073709551615" || ext[ExtCertCA] != ssh.FingerprintSHA256(ca.PublicKey()) {
		t.Errorf("serial %q, CA %q", ext[ExtCertSerial], ext[ExtCertCA])
	}
	if id := ext[ExtCertKeyID]; len(id) > maxKeyIDLen || !strings.HasPrefix(cert.KeyId, id) || len(id) < maxKeyIDLen-1 {
		t.Errorf("key id %d bytes", len(id))
	}
	if perms.CriticalOptions[sourceAddress] != "192.0.2.0/24" || len(perms.CriticalOptions) != 1 {
		t.Errorf("critical options %v, want only the source-address for x/crypto to enforce", perms.CriticalOptions)
	}
}

func TestCertificateNoTouch(t *testing.T) {
	t.Parallel()

	ca := newSigner(t)
	sk := skKey(t)
	withExt := func(c *ssh.Certificate) { c.Extensions = map[string]string{noTouchRequired: ""} }
	tests := []struct {
		name   string
		global bool
		line   string // options of a cert-authority line; "" for none
		cert   func(*ssh.Certificate)
		key    ssh.PublicKey
		want   string
	}{
		{"trusted CA: the certificate decides", true, "", withExt, sk, "ok"},
		{"line without no-touch-required", false, "cert-authority", withExt, sk, ReasonCertInvalid},
		{"line with no-touch-required", false, "cert-authority,no-touch-required", withExt, sk, "ok"},
		{"line allows, certificate does not ask", false, "cert-authority,no-touch-required", nil, sk, "ok"},
		{"not a security key", false, "cert-authority", withExt, newKey(t), "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u := User{Name: "alice"}
			var cas []ssh.PublicKey
			if tt.global {
				cas = []ssh.PublicKey{ca.PublicKey()}
			} else {
				u.Keys = []Key{caLineFor(t, tt.line, ca)}
			}
			a := trusting([]User{u}, cas, nil)
			cert := issue(t, ca, tt.key, tt.cert)
			if got := outcome(t, a, fakeConn{user: "alice"}, cert); got != tt.want {
				t.Fatalf("KnownKey = %s, want %s", got, tt.want)
			}
			if tt.want == "ok" {
				perms, _ := a.KnownKey(fakeConn{user: "alice"}, cert)
				if _, ok := perms.Extensions[noTouchRequired]; ok {
					t.Error("no-touch-required put into Permissions")
				}
			}
		})
	}
}

// skKey returns a security-key (sk-ssh-ed25519) public key.
func skKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name        string
		Key         []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, "ssh:"})
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCertificateZeroConfig(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newKey(t)
	cert := func(principals ...string) *ssh.Certificate {
		return issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = principals })
	}
	tests := []struct {
		name string
		user string // --user
		line string
		cert *ssh.Certificate
		as   string
		want string
	}{
		{"any name, line without principals= is skipped", "", "cert-authority", cert("bob"), "bob", "denied"},
		{"any name, principals=", "", `cert-authority,principals="alice,bob"`, cert("alice"), "alice", "ok"},
		{"any name must be a principal of the line", "", `cert-authority,principals="alice"`, cert("alice", "root"), "root", ReasonCertPrincipal},
		{"any name must be a principal of the certificate", "", `cert-authority,principals="alice,bob"`, cert("alice"), "bob", ReasonCertPrincipal},
		{"--user, line without principals=", "alice", "cert-authority", cert("alice"), "alice", "ok"},
		{"--user, other principal", "alice", "cert-authority", cert("bob"), "alice", ReasonCertPrincipal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := New(tt.user, []Key{caLineFor(t, tt.line, ca)})
			a.now = func() time.Time { return certNow }
			if got := outcome(t, a, fakeConn{user: tt.as}, tt.cert); got != tt.want {
				t.Errorf("KnownKey = %s, want %s", got, tt.want)
			}
		})
	}
}

// A cert-authority line never accepts its CA key as a plain key, and a
// plain key line never accepts a certificate of its key.
func TestCertificateLinesApart(t *testing.T) {
	t.Parallel()

	ca, user := newSigner(t), newSigner(t)
	a := trusting([]User{{Name: "alice", Keys: []Key{caLineFor(t, "cert-authority", ca), {Key: user.PublicKey()}}}}, nil, nil)
	if got := outcome(t, a, fakeConn{user: "alice"}, ca.PublicKey()); got != "denied" {
		t.Errorf("the CA key as a plain key: %s", got)
	}
	other := newSigner(t)
	if got := outcome(t, a, fakeConn{user: "alice"}, issue(t, other, user.PublicKey(), nil)); got != "denied" {
		t.Errorf("a certificate of a plain key, from an untrusted CA: %s", got)
	}
	if got := outcome(t, a, fakeConn{user: "alice"}, user.PublicKey()); got != "ok" {
		t.Errorf("the plain key: %s", got)
	}
}

// A certificate entry in the revocation list revokes its key: every
// certificate of it, however its signature is encoded, and the plain key.
func TestRevokedKeys(t *testing.T) {
	t.Parallel()

	ca, user := newSigner(t), newSigner(t)
	listed := issue(t, ca, user.PublicKey(), nil)
	r := &RevokedKeys{}
	if err := r.Add([]byte("# revoked\r\n"+`command="x" `+string(ssh.MarshalAuthorizedKey(listed))+"\r\n"), "revoked"); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d", r.Len())
	}
	a := trusting([]User{{Name: "alice", Keys: []Key{{Key: user.PublicKey()}}}}, []ssh.PublicKey{ca.PublicKey()}, r)
	renewed := issue(t, ca, user.PublicKey(), func(c *ssh.Certificate) { c.Serial = 8 })
	for name, k := range map[string]ssh.PublicKey{"listed certificate": listed, "renewed certificate": renewed, "plain key": user.PublicKey()} {
		if got := outcome(t, a, fakeConn{user: "alice"}, k); got != ReasonKeyRevoked {
			t.Errorf("%s: %s, want %s", name, got, ReasonKeyRevoked)
		}
	}
	var nilList *RevokedKeys
	if nilList.Revoked(user.PublicKey()) || nilList.Len() != 0 {
		t.Error("a nil list revokes")
	}
}

func TestRevokedKeysFailClosed(t *testing.T) {
	t.Parallel()

	k := string(ssh.MarshalAuthorizedKey(newKey(t)))
	for name, data := range map[string]string{
		"KRL":     "SSHKRL\n\x00\x00\x00\x00\x01",
		"garbage": k + "not a key\n",
		"typo":    strings.Replace(k, "AAAA", "AAA", 1),
	} {
		r := &RevokedKeys{}
		if err := r.Add([]byte(data), "revoked"); err == nil {
			t.Errorf("%s: no error", name)
		} else if r.Len() != 0 {
			t.Errorf("%s: %d entries added despite the error", name, r.Len())
		}
	}
	r := &RevokedKeys{}
	if err := r.Add([]byte("\n# nothing\n"), "revoked"); err != nil || r.Len() != 0 {
		t.Errorf("empty list: %v, %d", err, r.Len())
	}
}

func TestParseCAKeys(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newKey(t)
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := ssh.NewPublicKey(&smallRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	data := strings.Join([]string{
		"# CAs",
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey()))) + " corp-ca",
		"cert-authority " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(issue(t, ca, key, nil)))),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(weak))),
		"garbage",
	}, "\n")
	keys, warns := ParseCAKeys([]byte(data), "cas")
	if len(keys) != 1 || string(keys[0].Marshal()) != string(ca.PublicKey().Marshal()) {
		t.Errorf("keys = %d", len(keys))
	}
	want := []string{"cas:3: a CA key line takes no options", "cas:4: this is a certificate", "cas:5: RSA key has 1024 bits", "cas:6: cannot parse"}
	if len(warns) != len(want) {
		t.Fatalf("warnings %q", warns)
	}
	for i, w := range want {
		if !strings.HasPrefix(warns[i], w) {
			t.Errorf("warning %q, want prefix %q", warns[i], w)
		}
	}
}

// Refusal checks again after the handshake, Recheck the open connections
// after a reload: a certificate that expired since the login does not close
// its connection, but a revocation or a removed CA does.
func TestCertificateRecheck(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newKey(t)
	cert := issue(t, ca, key, nil)
	users := []User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,principals="alice"`, ca)}}}
	a := trusting(users, nil, nil)
	conn := fakeConn{user: "alice"}
	perms, err := a.KnownKey(conn, cert)
	if err != nil {
		t.Fatal(err)
	}
	later := trusting(users, nil, nil)
	later.now = func() time.Time { return certNow.Add(2 * time.Hour) }

	tests := []struct {
		name    string
		a       *Authenticator
		refusal string
		open    bool
	}{
		{"unchanged", a, "", true},
		{"certificate expired since", later, ReasonCertExpired, true},
		{"CA removed", trusting([]User{{Name: "alice"}}, nil, nil), ReasonRemoved, false},
		{"principals= changed", trusting([]User{{Name: "alice", Keys: []Key{caLineFor(t, `cert-authority,principals="ops"`, ca)}}}, nil, nil), ReasonCertPrincipal, false},
		{"now trusted only through trusted CAs", trusting([]User{{Name: "alice"}}, []ssh.PublicKey{ca.PublicKey()}, nil), "", true},
		{"revoked", trusting(users, nil, revokedOf(t, key)), ReasonKeyRevoked, false},
		{"disabled", trusting([]User{{Name: "alice", Disabled: true, Keys: users[0].Keys}}, nil, nil), ReasonDisabled, false},
		{"user removed", trusting(nil, nil, nil), ReasonRemoved, false},
	}
	for _, tt := range tests {
		if got := tt.a.Refusal(conn, perms); got != tt.refusal {
			t.Errorf("%s: Refusal = %q, want %q", tt.name, got, tt.refusal)
		}
		if got := tt.a.Recheck(conn, perms); got != tt.open {
			t.Errorf("%s: Recheck = %v, want %v", tt.name, got, tt.open)
		}
		_, err := tt.a.VerifiedKey(conn, cert, perms)
		if re, ok := errors.AsType[*RefusedError](err); (tt.refusal == "") != (err == nil) || ok && (re.Cert == nil || re.Reason != tt.refusal) {
			t.Errorf("%s: VerifiedKey error %v", tt.name, err)
		}
	}
}

// The CA signature of a certificate from a known CA is verified before the
// user is looked up, so a user that does not exist costs the same; the
// result is cached, failures are not.
func TestCertificateVerification(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newKey(t)
	a := trusting([]User{{Name: "alice"}}, []ssh.PublicKey{ca.PublicKey()}, nil)
	mallory := issue(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{"mallory"} })
	if got := outcome(t, a, fakeConn{user: "mallory"}, mallory); got != "denied" {
		t.Fatalf("unknown user: %s", got)
	}
	if len(a.verified.ok) != 1 {
		t.Errorf("the certificate of an unknown user was not verified (%d cached)", len(a.verified.ok))
	}
	outcome(t, a, fakeConn{user: "mallory"}, forge(mallory))
	if len(a.verified.ok) != 1 {
		t.Error("a forged certificate was cached")
	}
	for range maxVerified + 1 {
		a.verified.verify(issue(t, ca, key, nil))
	}
	if len(a.verified.ok) > maxVerified {
		t.Errorf("cache grew to %d", len(a.verified.ok))
	}
}

func TestCertValidity(t *testing.T) {
	t.Parallel()

	now := certNow
	at := func(d time.Duration) uint64 { return uint64(now.Add(d).Unix()) }
	for _, tt := range []struct {
		after, before uint64
		want          string
	}{
		{at(-time.Hour), at(time.Hour), ""},
		{at(0), at(time.Second), ""},
		{at(time.Second), at(time.Hour), ReasonCertNotYetValid},
		{at(-time.Hour), at(0), ReasonCertExpired},
		{0, ssh.CertTimeInfinity, ""},
		{math.MaxInt64 + 1, ssh.CertTimeInfinity, ReasonCertNotYetValid},
		{0, math.MaxInt64 + 1, ReasonCertExpired},
	} {
		c := &ssh.Certificate{ValidAfter: tt.after, ValidBefore: tt.before}
		if got := certValidity(c, now); got != tt.want {
			t.Errorf("after %d before %d: %q, want %q", tt.after, tt.before, got, tt.want)
		}
	}
}

func TestSFTPOnlyCommand(t *testing.T) {
	t.Parallel()

	for cmd, want := range map[string]bool{
		"internal-sftp":                   true,
		"/usr/lib/openssh/sftp-server":    true,
		"sftp-server":                     true,
		"internal-sftp -R":                false,
		"/usr/lib/openssh/sftp-server -R": false,
		"/bin/sh":                         false,
		"":                                false,
		"/tmp/sftp-server\t-d/":           false,
	} {
		if got := SFTPOnlyCommand(cmd); got != want {
			t.Errorf("SFTPOnlyCommand(%q) = %v", cmd, got)
		}
	}
}

func TestParseCertAuthorityLines(t *testing.T) {
	t.Parallel()

	k := newKey(t)
	cert := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(issue(t, newSigner(t), k, nil))))
	for _, tt := range []struct {
		line, warning string
	}{
		{authorizedLine(t, "cert-authority", k), ""},
		{authorizedLine(t, `cert-authority,principals="alice,alice@corp",from="10.0.0.0/8",expiry-time="20990101",no-touch-required`, k), ""},
		{authorizedLine(t, `command="internal-sftp"`, k), ""},
		{authorizedLine(t, `principals="alice"`, k), "only with cert-authority"},
		{authorizedLine(t, `cert-authority,principals=""`, k), "empty principal"},
		{authorizedLine(t, `cert-authority,principals="a,,b"`, k), "empty principal"},
		{authorizedLine(t, `cert-authority="x"`, k), "unsupported option"},
		{authorizedLine(t, `command="internal-sftp -R"`, k), "command="},
		{cert, "this is a certificate"},
	} {
		keys, warns := ParseAuthorizedKeys([]byte(tt.line), "keys")
		if tt.warning == "" {
			if len(keys) != 1 || len(warns) != 0 {
				t.Errorf("%q rejected: %v", tt.line, warns)
			}
			continue
		}
		if len(keys) != 0 || len(warns) != 1 || !strings.Contains(warns[0], tt.warning) {
			t.Errorf("%q: keys %d, warnings %q, want %q", tt.line, len(keys), warns, tt.warning)
		}
	}
}
