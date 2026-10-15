// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

// server.trusted_proxies takes addresses and CIDR blocks as allow_from
// does; a block of every address is refused, also as ::ffff:0:0/96 (ADR
// 0011).
func TestTrustedProxies(t *testing.T) {
	t.Parallel()

	base := "config_version = 1\n[mounts.m]\npath = \"{dir}/m\"\n[users.u]\nauthorized_keys = [\"" + pubKey(t) + "\"]\naccess = { m = \"read\" }\n[server]\nhost_keys = [\"k\"]\n"
	for _, tt := range []struct {
		value string
		want  []string // the prefixes, or the error
		err   bool
	}{
		{`[]`, nil, false},
		{`["10.0.0.5"]`, []string{"10.0.0.5/32"}, false},
		{`["10.0.1.7/28", " 2001:db8::5 "]`, []string{"10.0.1.0/28", "2001:db8::5/128"}, false},
		{`["::ffff:10.0.0.5"]`, []string{"10.0.0.5/32"}, false},
		{`["::ffff:10.0.0.0/120"]`, []string{"10.0.0.0/24"}, false},
		{`["0.0.0.0/0"]`, []string{`"0.0.0.0/0" holds every address`}, true},
		{`["::/0"]`, []string{`"::/0" holds every address`}, true},
		{`["::ffff:0:0/96"]`, []string{`"::ffff:0:0/96" holds every address`}, true},
		{`["::ffff:0:0/95"]`, []string{`"::ffff:0:0/95" is not a valid CIDR block`}, true},
		{`["10.0.0.0/33"]`, []string{`"10.0.0.0/33" is not an IP address or CIDR block`}, true},
		{`["lb.example"]`, []string{`"lb.example" is not an IP address or CIDR block`}, true},
		{`["fe80::1%eth0"]`, []string{`"fe80::1%eth0" is not an IP address or CIDR block`}, true},
	} {
		c, _ := load(t, base+"trusted_proxies = "+tt.value+"\n")
		_, err := c.Validate()
		if tt.err {
			if err == nil || !strings.Contains(err.Error(), "server.trusted_proxies: "+tt.want[0]) {
				t.Errorf("%s: error %v, want %q", tt.value, err, tt.want[0])
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tt.value, err)
			continue
		}
		var got []string
		for _, p := range c.TrustedProxyPrefixes() {
			got = append(got, p.String())
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: TrustedProxyPrefixes = %v, want %v", tt.value, got, tt.want)
		}
	}
	if Default().TrustedProxyPrefixes() != nil {
		t.Error("proxies trusted by default")
	}
}

// config validate warns about a handshake_timeout too short for a header
// and about trusted proxies that auth.ban.exempt covers.
func TestTrustedProxiesWarnings(t *testing.T) {
	t.Parallel()

	base := "config_version = 1\n[mounts.m]\npath = \"{dir}/m\"\n[users.u]\nauthorized_keys = [\"" + pubKey(t) + "\"]\naccess = { m = \"read\" }\n[server]\nhost_keys = [\"k\"]\n"
	const (
		short   = "server.handshake_timeout: 2s is below 3s"
		overlap = "overlaps auth.ban.exempt"
	)
	for _, tt := range []struct {
		conf string
		want []string
	}{
		{`trusted_proxies = ["10.0.0.5"]`, nil},
		{"trusted_proxies = [\"10.0.0.5\"]\nhandshake_timeout = \"2s\"", []string{short}},
		{"trusted_proxies = [\"10.0.0.5\"]\nhandshake_timeout = \"3s\"", nil},
		{`handshake_timeout = "2s"`, nil}, // no proxy, no header
		// The default exempt list is loopback.
		{`trusted_proxies = ["127.0.0.1"]`, []string{"server.trusted_proxies: 127.0.0.1/32 overlaps auth.ban.exempt (127.0.0.0/8)"}},
		{`trusted_proxies = ["::1"]`, []string{"::1/128 overlaps auth.ban.exempt (::1/128)"}},
		{"trusted_proxies = [\"10.0.0.0/8\"]\n[auth.ban]\nexempt = [\"10.1.2.3\"]", []string{"10.0.0.0/8 overlaps auth.ban.exempt (10.1.2.3/32)"}},
		{"trusted_proxies = [\"10.0.0.5\"]\n[auth.ban]\nexempt = [\"10.0.1.0/24\"]", nil},
		// Without bans nothing is exempt from them.
		{"trusted_proxies = [\"127.0.0.1\"]\n[auth.ban]\nafter_failures = 0", nil},
	} {
		c, _ := load(t, base+tt.conf+"\n")
		var got []string
		for _, w := range mustValidate(t, c) {
			if strings.Contains(w, "PROXY") || strings.Contains(w, "trusted_proxies") {
				got = append(got, w)
			}
		}
		if len(got) != len(tt.want) {
			t.Errorf("%q: warnings %q, want %q", tt.conf, got, tt.want)
			continue
		}
		for i, w := range tt.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%q: warning %q, want %q", tt.conf, got[i], w)
			}
		}
	}
}
