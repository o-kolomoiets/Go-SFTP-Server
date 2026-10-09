// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"strconv"
	"strings"
	"testing"

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
				name, _, _ := strings.Cut(opt, "=")
				switch name = strings.ToLower(name); {
				case ignoredOptions[name], name == "from", name == "expiry-time", name == "no-touch-required":
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
