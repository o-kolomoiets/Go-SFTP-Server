// SPDX-License-Identifier: Apache-2.0

// Package auth authenticates SSH users.
//
// Identity flows only through ssh.Permissions: callbacks are pure lookups
// without side effects, because x/crypto may call PublicKeyCallback for keys
// the client never proves it owns (see CVE-2024-45337).
package auth

import (
	"errors"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Permission extension keys set on successful authentication.
const (
	ExtUser        = "gosftpd-user"
	ExtFingerprint = "pubkey-fp"
)

// maxUserLen bounds user names accepted from clients.
const maxUserLen = 64

var errDenied = errors.New("authentication failed")

// Authenticator checks public keys against an authorized_keys set.
type Authenticator struct {
	user string // required SSH user name; empty accepts any valid name
	keys map[string]Key
	now  func() time.Time
}

// New returns an Authenticator for keys. If user is not empty, only that SSH
// user name is accepted.
func New(user string, keys []Key) *Authenticator {
	m := make(map[string]Key, len(keys))
	for _, k := range keys {
		m[string(k.Key.Marshal())] = k
	}
	return &Authenticator{user: user, keys: m, now: time.Now}
}

// Len returns the number of accepted keys.
func (a *Authenticator) Len() int { return len(a.keys) }

// PublicKey is an ssh.ServerConfig.PublicKeyCallback.
func (a *Authenticator) PublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	name := conn.User()
	if !validUser(name) || (a.user != "" && name != a.user) {
		return nil, errDenied
	}
	k, ok := a.keys[string(key.Marshal())]
	if !ok {
		return nil, errDenied
	}
	if !k.expires.IsZero() && a.now().After(k.expires) {
		return nil, errDenied
	}
	perms := &ssh.Permissions{
		Extensions: map[string]string{
			ExtUser:        name,
			ExtFingerprint: ssh.FingerprintSHA256(key),
		},
	}
	if k.noTouchRequire {
		perms.Extensions["no-touch-required"] = ""
	}
	if k.sourceAddress != "" {
		// Enforced by x/crypto after authentication.
		perms.CriticalOptions = map[string]string{"source-address": k.sourceAddress}
	}
	return perms, nil
}

// UserFrom returns the authenticated user recorded in perms.
func UserFrom(perms *ssh.Permissions) (string, bool) {
	if perms == nil {
		return "", false
	}
	u, ok := perms.Extensions[ExtUser]
	return u, ok && u != ""
}

// validUser accepts printable names up to maxUserLen bytes.
func validUser(name string) bool {
	if name == "" || len(name) > maxUserLen || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) || r == '/' {
			return false
		}
	}
	return true
}
