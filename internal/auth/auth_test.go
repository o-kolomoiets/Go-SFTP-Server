// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
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
}

func (c fakeConn) User() string          { return c.user }
func (c fakeConn) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1} }
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
