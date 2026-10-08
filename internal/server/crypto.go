// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"
)

// Crypto policies (ROADMAP §7.6). There are no per-algorithm settings:
// x/crypto silently drops names it does not know, so a typo would weaken
// nothing visibly, and its default lists still contain SHA-1 variants.
const (
	PolicyModern = "modern"
	PolicyCompat = "compat"
)

// CryptoPolicies lists the valid crypto_policy values.
var CryptoPolicies = []string{PolicyModern, PolicyCompat}

type algorithms struct {
	kex, ciphers, macs []string
}

var modern = algorithms{
	kex: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
	ciphers: []string{
		ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM,
		ssh.CipherAES256CTR, ssh.CipherAES128CTR,
	},
	macs: []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
}

// compat adds NIST curves, 2048- and 4096-bit DH with SHA-2 and MACs without
// encrypt-then-MAC, for older clients and devices. ssh-audit flags some of
// them; see docs/security.md.
var compat = algorithms{
	kex: append(slices.Clone(modern.kex),
		ssh.KeyExchangeECDHP256, ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP521,
		ssh.KeyExchangeDH16SHA512, ssh.KeyExchangeDH14SHA256),
	ciphers: modern.ciphers,
	macs:    append(slices.Clone(modern.macs), ssh.HMACSHA256, ssh.HMACSHA512),
}

func policy(name string) (algorithms, error) {
	switch name {
	case "", PolicyModern:
		return modern, nil
	case PolicyCompat:
		return compat, nil
	default:
		return algorithms{}, fmt.Errorf("unknown crypto policy %q (want modern or compat)", name)
	}
}
