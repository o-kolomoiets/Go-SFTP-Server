// SPDX-License-Identifier: Apache-2.0

// Package auth authenticates SSH users.
//
// Identity flows only through ssh.Permissions: callbacks are pure lookups
// without side effects, because x/crypto may call PublicKeyCallback for keys
// the client never proves it owns (see CVE-2024-45337).
package auth

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
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

// maxUserLen bounds user names accepted from clients in zero-config mode.
const maxUserLen = 64

var errDenied = errors.New("authentication failed")

var userNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ValidUserName reports whether name is a valid configured user name.
func ValidUserName(name string) bool { return userNameRE.MatchString(name) }

// User is an account in the configuration.
type User struct {
	Name      string
	Keys      []Key
	AllowFrom []netip.Prefix // empty: any address
	Expires   time.Time      // zero: never
	Disabled  bool
}

type account struct {
	keys      map[string]Key
	allowFrom []netip.Prefix
	expires   time.Time
	disabled  bool
}

func newAccount(keys []Key) *account {
	m := make(map[string]Key, len(keys))
	for _, k := range keys {
		m[string(k.Key.Marshal())] = k
	}
	return &account{keys: m}
}

// noKeys stands in for an unknown user, so that it takes the same path as a
// known user with a wrong key.
var noKeys = newAccount(nil)

// Authenticator checks public keys of configured users, or, in zero-config
// mode, of any user name against one authorized_keys set.
type Authenticator struct {
	users map[string]*account
	any   *account // zero-config: accepts every valid user name
	now   func() time.Time
}

// New returns a zero-config Authenticator for keys. If user is not empty,
// only that SSH user name is accepted; otherwise any valid name is.
func New(user string, keys []Key) *Authenticator {
	a := &Authenticator{users: map[string]*account{}, now: time.Now}
	if user != "" {
		a.users[user] = newAccount(keys)
	} else {
		a.any = newAccount(keys)
	}
	return a
}

// NewUsers returns an Authenticator for configured users.
func NewUsers(users []User) *Authenticator {
	a := &Authenticator{users: make(map[string]*account, len(users)), now: time.Now}
	for _, u := range users {
		acc := newAccount(u.Keys)
		acc.allowFrom = u.AllowFrom
		acc.expires = u.Expires
		acc.disabled = u.Disabled
		a.users[u.Name] = acc
	}
	return a
}

// Len returns the number of accepted keys.
func (a *Authenticator) Len() int {
	n := 0
	if a.any != nil {
		n += len(a.any.keys)
	}
	for _, acc := range a.users {
		n += len(acc.keys)
	}
	return n
}

func (a *Authenticator) lookup(name string) *account {
	if acc := a.users[name]; acc != nil {
		return acc
	}
	if a.any != nil && validUser(name) {
		return a.any
	}
	return nil
}

// PublicKey is an ssh.ServerConfig.PublicKeyCallback. It is a pure lookup:
// unknown users, wrong keys, disabled or expired accounts and disallowed
// source addresses all fail the same way.
func (a *Authenticator) PublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	name := conn.User()
	acc := a.lookup(name)
	keys := noKeys.keys
	if acc != nil {
		keys = acc.keys
	}
	k, ok := keys[string(key.Marshal())]
	switch {
	case acc == nil, !ok, acc.disabled:
		return nil, errDenied
	case !acc.expires.IsZero() && a.now().After(acc.expires):
		return nil, errDenied
	case !k.expires.IsZero() && a.now().After(k.expires):
		return nil, errDenied
	case !addrAllowed(acc.allowFrom, conn.RemoteAddr()):
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

// validUser accepts printable names up to maxUserLen bytes (zero-config).
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

// ParsePrefix parses an IP address or CIDR block for allow_from.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR block", s)
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func addrAllowed(prefixes []netip.Prefix, addr net.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	if addr == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap().WithZone("")
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
