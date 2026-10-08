// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// MinRSABits is the smallest accepted RSA user key.
const MinRSABits = 2048

// Key is one accepted line of an authorized_keys file.
type Key struct {
	Key     ssh.PublicKey
	Comment string
	Source  string // "file:line", for messages and audit

	sourceAddress  string    // validated from="..." value (comma-separated IPs/CIDRs)
	expires        time.Time // expiry-time="..."; zero means never
	noTouchRequire bool
}

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
		case name == "cert-authority":
			return Key{}, errors.New("cert-authority is not supported yet (planned for v0.4)")
		case name == "verify-required":
			return Key{}, errors.New("verify-required cannot be enforced (user verification is not checked), line rejected")
		default:
			return Key{}, fmt.Errorf("unsupported option %q, line rejected", name)
		}
	}
	return k, nil
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
