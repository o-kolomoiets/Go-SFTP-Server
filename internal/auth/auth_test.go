// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func authorizedLine(t *testing.T, options string, k ssh.PublicKey) string {
	t.Helper()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if options != "" {
		line = options + " " + line
	}
	return line + " test@example"
}

func TestParseAuthorizedKeys(t *testing.T) {
	t.Parallel()

	k := newKey(t)
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := ssh.NewPublicKey(&smallRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		line    string
		ok      bool
		warning string
	}{
		{"plain", authorizedLine(t, "", k), true, ""},
		{"restrictions are ignored", authorizedLine(t, "restrict,no-pty,no-port-forwarding", k), true, ""},
		{"from CIDR", authorizedLine(t, `from="10.0.0.0/8,192.0.2.7"`, k), true, ""},
		{"from hostname", authorizedLine(t, `from="*.example.org"`, k), false, "only IP addresses"},
		{"expiry", authorizedLine(t, `expiry-time="20990101"`, k), true, ""},
		{"bad expiry", authorizedLine(t, `expiry-time="tomorrow"`, k), false, "expiry-time"},
		{"command is rejected", authorizedLine(t, `command="/bin/sh"`, k), false, "unsupported option"},
		{"cert-authority", authorizedLine(t, "cert-authority", k), false, "cert-authority"},
		{"verify-required", authorizedLine(t, "verify-required", k), false, "verify-required"},
		{"weak RSA", authorizedLine(t, "", weak), false, "1024 bits"},
		{"garbage", "ssh-ed25519 not-base64", false, "cannot parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keys, warnings := ParseAuthorizedKeys([]byte("# comment\n\n"+tt.line+"\n"), "keys")
			if got := len(keys) == 1; got != tt.ok {
				t.Fatalf("accepted = %v, want %v (warnings %q)", got, tt.ok, warnings)
			}
			if tt.ok {
				if keys[0].Source != "keys:3" {
					t.Errorf("Source = %q, want keys:3", keys[0].Source)
				}
				return
			}
			if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "keys:3: ") || !strings.Contains(warnings[0], tt.warning) {
				t.Errorf("warnings = %q, want one for keys:3 containing %q", warnings, tt.warning)
			}
		})
	}
}

type fakeConn struct {
	ssh.ConnMetadata
	user string
	addr net.Addr
}

func (c fakeConn) User() string { return c.user }
func (c fakeConn) RemoteAddr() net.Addr {
	if c.addr != nil {
		return c.addr
	}
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}
}
func (c fakeConn) SessionID() []byte     { return nil }
func (c fakeConn) ClientVersion() []byte { return nil }

func TestPublicKey(t *testing.T) {
	t.Parallel()

	good, other := newKey(t), newKey(t)
	keys, _ := ParseAuthorizedKeys([]byte(authorizedLine(t, `from="10.0.0.0/8"`, good)), "keys")
	a := New("", keys)

	perms, err := a.PublicKey(fakeConn{user: "alice"}, good)
	if err != nil {
		t.Fatalf("PublicKey(good) error = %v", err)
	}
	if u, ok := UserFrom(perms); !ok || u != "alice" {
		t.Errorf("UserFrom() = %q, %v", u, ok)
	}
	if perms.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("source-address = %q", perms.CriticalOptions["source-address"])
	}
	if perms.Extensions[ExtFingerprint] != ssh.FingerprintSHA256(good) {
		t.Errorf("fingerprint extension = %q", perms.Extensions[ExtFingerprint])
	}

	if _, err := a.PublicKey(fakeConn{user: "alice"}, other); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := a.PublicKey(fakeConn{user: "bad\x00name"}, good); err == nil {
		t.Error("control characters in the user name accepted")
	}

	restricted := New("alice", keys)
	if _, err := restricted.PublicKey(fakeConn{user: "bob"}, good); err == nil {
		t.Error("--user restriction ignored")
	}
}

func TestPublicKeyExpired(t *testing.T) {
	t.Parallel()

	k := newKey(t)
	keys, _ := ParseAuthorizedKeys([]byte(authorizedLine(t, `expiry-time="20300101Z"`, k)), "keys")
	a := New("", keys)
	a.now = func() time.Time { return time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC) }
	if _, err := a.PublicKey(fakeConn{user: "alice"}, k); err == nil {
		t.Error("expired key accepted")
	}
	a.now = func() time.Time { return time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC) }
	if _, err := a.PublicKey(fakeConn{user: "alice"}, k); err != nil {
		t.Errorf("key before expiry rejected: %v", err)
	}
}

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	return ps
}

func TestUsers(t *testing.T) {
	t.Parallel()

	aliceKey, bobKey, carolKey, daveKey := newKey(t), newKey(t), newKey(t), newKey(t)
	key := func(k ssh.PublicKey) []Key { return []Key{{Key: k}} }
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	a := NewUsers([]User{
		{Name: "alice", Keys: key(aliceKey)},
		{Name: "bob", Keys: key(bobKey), AllowFrom: mustPrefixes(t, "10.0.0.0/8", "2001:db8::/32")},
		{Name: "carol", Keys: key(carolKey), Expires: now.Add(-time.Minute)},
		{Name: "dave", Keys: key(daveKey), Disabled: true},
	})
	a.now = func() time.Time { return now }
	if a.Len() != 4 {
		t.Errorf("Len() = %d", a.Len())
	}

	tcp := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 5000} }
	for _, tt := range []struct {
		name string
		user string
		key  ssh.PublicKey
		addr net.Addr
		ok   bool
	}{
		{"own key", "alice", aliceKey, nil, true},
		{"another user's key", "alice", bobKey, nil, false},
		{"unknown user", "mallory", aliceKey, nil, false},
		{"zero-config names are not users", "Alice", aliceKey, nil, false},
		{"allowed IPv4", "bob", bobKey, tcp("10.1.2.3"), true},
		{"allowed IPv4-mapped", "bob", bobKey, tcp("::ffff:10.1.2.3"), true},
		{"allowed IPv6", "bob", bobKey, tcp("2001:db8::7"), true},
		{"disallowed address", "bob", bobKey, tcp("192.0.2.1"), false},
		{"expired", "carol", carolKey, nil, false},
		{"disabled", "dave", daveKey, nil, false},
	} {
		_, err := a.PublicKey(fakeConn{user: tt.user, addr: tt.addr}, tt.key)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok = %v", tt.name, err, tt.ok)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"10.0.0.0/8":           "10.0.0.0/8",
		"10.1.2.3/8":           "10.0.0.0/8",
		"192.0.2.7":            "192.0.2.7/32",
		"2001:db8::1":          "2001:db8::1/128",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
	} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	if p, err := ParsePrefix("\t127.0.0.1\n"); err != nil || p.String() != "127.0.0.1/32" {
		t.Errorf("surrounding space: %v, %v", p, err)
	}
	for _, in := range []string{"", "example.org", "10.0.0.0/33", "fe80::1%eth0"} {
		if _, err := ParsePrefix(in); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", in)
		}
	}
}

func TestValidUserName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]bool{
		"alice": true, "partner-acme": true, "a.b_c": true, "0": true,
		"": false, "Alice": false, "-x": false, ".x": false, "a b": false, strings.Repeat("a", 33): false,
	} {
		if got := ValidUserName(name); got != want {
			t.Errorf("ValidUserName(%q) = %v", name, got)
		}
	}
}
