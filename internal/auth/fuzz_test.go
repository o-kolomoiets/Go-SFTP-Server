// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// FuzzAuthorizedKeys (ROADMAP §8.3): parsing never panics, every line is
// either accepted or reported, and an accepted line carries only the
// options gosftpd enforces.
func FuzzAuthorizedKeys(f *testing.F) {
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		f.Fatal(err)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	for _, s := range []string{
		key + " alice@laptop",
		`from="10.0.0.0/8,192.0.2.1",expiry-time="20300101Z",restrict ` + key,
		`no-touch-required,no-pty ` + key,
		`command="/bin/sh" ` + key,
		`from="*.example.org" ` + key,
		`cert-authority ` + key,
		`cert-authority,principals="alice,ops",from="10.0.0.0/8" ` + key,
		`principals="alice" ` + key,
		`cert-authority,principals="a,,b" ` + key,
		`command="internal-sftp" ` + key,
		`cert-authority,principals="a",principals="b" ` + key,
		`from="10.0.0.1",from="0.0.0.0/0" ` + key,
		`expiry-time="20200101",expiry-time="20990101" ` + key,
		`environment="A=B" ` + key,
		"# comment\n\n" + key + "\r\n" + key,
		"ssh-dss AAAA",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, warnings := ParseAuthorizedKeys(data, "fuzz")
		lines := 0
		for l := range bytes.SplitSeq(data, []byte("\n")) {
			if l = bytes.TrimSpace(l); len(l) > 0 && l[0] != '#' {
				lines++
			}
		}
		if len(keys)+len(warnings) != lines {
			t.Fatalf("%d keys and %d warnings for %d lines", len(keys), len(warnings), lines)
		}
		all := bytes.Split(data, []byte("\n"))
		for _, k := range keys {
			n, err := strconv.Atoi(strings.TrimPrefix(k.Source, "fuzz:"))
			if err != nil || n < 1 || n > len(all) {
				t.Fatalf("bad source %q", k.Source)
			}
			if err := checkKeyType(k.Key); err != nil {
				t.Fatalf("accepted key: %v", err)
			}
			_, _, options, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(all[n-1]))
			if err != nil {
				t.Fatalf("accepted line does not parse: %v", err)
			}
			for _, opt := range options {
				name, value, _ := strings.Cut(opt, "=")
				switch name = strings.ToLower(name); {
				case ignoredOptions[name], name == "from", name == "expiry-time", name == "no-touch-required":
				case name == "cert-authority":
					if !k.CertAuthority() {
						t.Fatal("cert-authority line kept as a plain key")
					}
				case name == "principals":
					if !k.CertAuthority() || slices.Contains(k.Principals(), "") {
						t.Fatalf("accepted principals %q", value)
					}
				case name == "command":
					if !SFTPOnlyCommand(unquote(value)) {
						t.Fatalf("accepted command %q", value)
					}
				default:
					t.Fatalf("accepted a line with option %q", opt)
				}
			}
			if k.sourceAddress != "" {
				for p := range strings.SplitSeq(k.sourceAddress, ",") {
					if net.ParseIP(p) == nil {
						if _, _, err := net.ParseCIDR(p); err != nil {
							t.Fatalf("from= kept %q", p)
						}
					}
				}
			}
		}
	})
}

// FuzzCertificate: arbitrary bytes offered as a certificate. A login is
// accepted, and a refusal reason recorded, only for a certificate whose CA
// signature verifies. An accepted one carries a principal the user allows,
// is valid now, has no option gosftpd refuses, and gives Permissions with
// nothing of the certificate's own options but source-address.
func FuzzCertificate(f *testing.F) {
	ca, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)))
	if err != nil {
		f.Fatal(err)
	}
	user, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)).Public())
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	sign := func(edit func(*ssh.Certificate)) []byte {
		c := &ssh.Certificate{
			Key: user, CertType: ssh.UserCert, KeyId: "id", Serial: 1, ValidPrincipals: []string{"alice"},
			ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix()),
		}
		edit(c)
		if err := c.SignCert(bytes.NewReader(make([]byte, 64)), ca); err != nil {
			f.Fatal(err)
		}
		return c.Marshal()
	}
	for _, edit := range []func(*ssh.Certificate){
		func(*ssh.Certificate) {},
		func(c *ssh.Certificate) { c.ValidPrincipals = []string{"ops", "bob"} },
		func(c *ssh.Certificate) { c.ValidPrincipals = nil },
		func(c *ssh.Certificate) { c.ValidBefore = uint64(now.Unix()) },
		func(c *ssh.Certificate) { c.CertType = ssh.HostCert },
		func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{forceCommand: "internal-sftp"} },
		func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{sourceAddress: "192.0.2.0/24"} },
		func(c *ssh.Certificate) { c.Extensions = map[string]string{ExtUser: "root", noTouchRequired: ""} },
	} {
		f.Add(sign(edit))
	}
	lines, warns := ParseAuthorizedKeys([]byte(`cert-authority,principals="ops" `+string(ssh.MarshalAuthorizedKey(ca.PublicKey()))), "line")
	if len(warns) > 0 {
		f.Fatal(warns)
	}
	a := NewUsers([]User{{Name: "alice"}, {Name: "bob", Principals: []string{}, Keys: lines}})
	a.Trust([]ssh.PublicKey{ca.PublicKey()}, nil)
	a.now = func() time.Time { return now }
	allowed := map[string]string{"alice": "alice", "bob": "ops"}

	f.Fuzz(func(t *testing.T, blob []byte) {
		pub, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			return
		}
		for _, name := range []string{"alice", "bob", "mallory"} {
			conn := fakeConn{user: name, addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}}
			perms, err := a.KnownKey(conn, cert)
			_, refused := errors.AsType[*RefusedError](err)
			if (err == nil || refused) && (!verifySignature(cert) || cert.CertType != ssh.UserCert) {
				t.Fatalf("%s: accepted or refused with a reason (%v), but the CA signature does not verify", name, err)
			}
			if err != nil {
				continue
			}
			if !slices.Contains(cert.ValidPrincipals, allowed[name]) {
				t.Fatalf("%s logged in with principals %q", name, cert.ValidPrincipals)
			}
			if r := certValidity(cert, now); r != "" {
				t.Fatalf("%s logged in with a certificate that is %s", name, r)
			}
			if d := certInvalid(cert); d != "" {
				t.Fatalf("%s logged in although %s", name, d)
			}
			if u, _ := UserFrom(perms); u != name || len(perms.CriticalOptions) > 1 {
				t.Fatalf("permissions %v", perms)
			}
			for k := range perms.Extensions {
				if !strings.HasPrefix(k, "gosftpd-") && k != ExtFingerprint {
					t.Fatalf("certificate extension %q in Permissions", k)
				}
			}
		}
	})
}
