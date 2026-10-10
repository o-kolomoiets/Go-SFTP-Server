// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// MinRSABits is the smallest accepted RSA user key.
const MinRSABits = 2048

// Key is one accepted line of an authorized_keys file: a key, or with
// cert-authority the key of a CA whose user certificates the line accepts.
type Key struct {
	Key     ssh.PublicKey
	Comment string
	Source  string // "file:line", for messages and audit

	sourceAddress  string         // validated from="..." value (comma-separated IPs/CIDRs)
	from           []netip.Prefix // sourceAddress, parsed
	expires        time.Time      // expiry-time="..."; zero means never
	noTouchRequire bool
	certAuthority  bool
	principals     []string // principals= of a cert-authority line; nil: the login name
}

// CertAuthority reports whether k is a cert-authority line.
func (k Key) CertAuthority() bool { return k.certAuthority }

// Principals returns the principals= of a cert-authority line, nil if it
// has none.
func (k Key) Principals() []string { return k.principals }

// ignoredOptions are restrictions gosftpd always enforces anyway.
var ignoredOptions = map[string]bool{
	"restrict":            true,
	"no-pty":              true,
	"no-port-forwarding":  true,
	"no-agent-forwarding": true,
	"no-x11-forwarding":   true,
	"no-user-rc":          true,
}

// ParseAuthorizedKeys parses authorized_keys data. Lines with unsupported key
// types or options are skipped and reported in warnings, as "source:line: reason";
// a line is never accepted with an option silently dropped.
func ParseAuthorizedKeys(data []byte, source string) (keys []Key, warnings []string) {
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s:%d", source, n+1)
		k, err := parseLine(line)
		if err != nil {
			warnings = append(warnings, where+": "+err.Error())
			continue
		}
		k.Source = where
		keys = append(keys, k)
	}
	return keys, warnings
}

func parseLine(line []byte) (Key, error) {
	pub, comment, options, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return Key{}, fmt.Errorf("cannot parse key: %w", err)
	}
	if err := checkKeyType(pub); err != nil {
		return Key{}, err
	}
	k := Key{Key: pub, Comment: comment}
	for _, opt := range options {
		name, value, hasValue := strings.Cut(opt, "=")
		name = strings.ToLower(name)
		switch {
		case ignoredOptions[name] && !hasValue:
		case name == "from" && hasValue:
			addrs, err := parseFrom(unquote(value))
			if err != nil {
				return Key{}, err
			}
			k.sourceAddress = addrs
		case name == "expiry-time" && hasValue:
			t, err := parseExpiry(unquote(value))
			if err != nil {
				return Key{}, err
			}
			k.expires = t
		case name == "no-touch-required" && !hasValue:
			k.noTouchRequire = true
		case name == "cert-authority" && !hasValue:
			k.certAuthority = true
		case name == "principals" && hasValue:
			p, err := parsePrincipals(unquote(value))
			if err != nil {
				return Key{}, err
			}
			k.principals = p
		case name == "command" && hasValue && SFTPOnlyCommand(unquote(value)):
			// gosftpd serves only SFTP.
		case name == "command":
			return Key{}, errors.New("command= is supported only as internal-sftp or a path to sftp-server, without arguments; line rejected")
		case name == "verify-required":
			return Key{}, errors.New("verify-required cannot be enforced (user verification is not checked), line rejected")
		default:
			return Key{}, fmt.Errorf("unsupported option %q, line rejected", name)
		}
	}
	if k.principals != nil && !k.certAuthority {
		return Key{}, errors.New("principals= is valid only with cert-authority, line rejected")
	}
	if k.sourceAddress != "" {
		from, err := parsePrefixes(k.sourceAddress)
		if err != nil {
			return Key{}, fmt.Errorf("from=%q: %w", k.sourceAddress, err)
		}
		k.from = from
	}
	return k, nil
}

// SFTPOnlyCommand reports whether a forced command (command= in
// authorized_keys, force-command in a certificate) only starts an SFTP
// server, which is all gosftpd serves anyway: internal-sftp, or a path to
// sftp-server, without arguments, which could change what it allows.
func SFTPOnlyCommand(cmd string) bool {
	return cmd == "internal-sftp" || path.Base(cmd) == "sftp-server" && !strings.ContainsAny(cmd, " \t")
}

// parsePrincipals parses a principals= list. An empty list or entry would
// match differently in OpenSSH (which stops at it), so it is an error.
func parsePrincipals(v string) ([]string, error) {
	p := strings.Split(v, ",")
	if slices.Contains(p, "") {
		return nil, fmt.Errorf("principals=%q: empty principal, line rejected", v)
	}
	return p, nil
}

func checkKeyType(pub ssh.PublicKey) error {
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("cannot inspect RSA key")
		}
		rsaKey, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return errors.New("cannot inspect RSA key")
		}
		if bits := rsaKey.N.BitLen(); bits < MinRSABits {
			return fmt.Errorf("RSA key has %d bits, at least %d are required", bits, MinRSABits)
		}
		return nil
	default:
		if strings.HasSuffix(pub.Type(), "-cert-v01@openssh.com") {
			return errors.New("this is a certificate, not a key; trust its CA instead (cert-authority, or auth.trusted_user_ca_keys)")
		}
		return fmt.Errorf("key type %s is not supported", pub.Type())
	}
}

// parseFrom accepts only IP addresses and CIDR blocks (no host patterns or
// negations), so that the value can be enforced as an SSH "source-address".
func parseFrom(v string) (string, error) {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) == nil {
			if _, _, err := net.ParseCIDR(p); err != nil {
				return "", fmt.Errorf("from=%q: only IP addresses and CIDR blocks are supported", p)
			}
		}
		parts[i] = p
	}
	return strings.Join(parts, ","), nil
}

// parsePrefixes parses a comma-separated list of IP addresses and CIDR
// blocks, as a certificate's source-address.
func parsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for s := range strings.SplitSeq(list, ",") {
		p, err := ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// parseExpiry parses OpenSSH's YYYYMMDD[HHMM[SS]][Z] timespec; without Z it
// is local time.
func parseExpiry(v string) (time.Time, error) {
	loc := time.Local
	if s, ok := strings.CutSuffix(v, "Z"); ok {
		v, loc = s, time.UTC
	}
	for _, layout := range []string{"20060102", "200601021504", "20060102150405"} {
		if len(v) == len(layout) {
			if t, err := time.ParseInLocation(layout, v, loc); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("expiry-time=%q: want YYYYMMDD[HHMM[SS]][Z]", v)
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}
