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
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Permission extension keys set on successful authentication.
const (
	ExtUser        = "gosftpd-user"
	ExtMethod      = "gosftpd-method"
	ExtFingerprint = "pubkey-fp"
	// extKey holds the public key a login used, extPassword the identity of
	// the password hash (see Recheck).
	extKey      = "gosftpd-key"
	extPassword = "gosftpd-password"
)

// Authentication methods.
const (
	MethodPublicKey = "publickey"
	MethodPassword  = "password"
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
	Password  PasswordHash   // nil: no password login
	AllowFrom []netip.Prefix // empty: any address
	Expires   time.Time      // zero: never
	Disabled  bool
}

type account struct {
	keys      map[string]Key
	password  PasswordHash
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
	users   map[string]*account
	any     *account // zero-config: accepts every valid user name
	now     func() time.Time
	hashing *hashSlots
	pad     *padder // equalizes the time of failures
}

// hashSlots bounds concurrent password verifications, and so the memory and
// CPU they take before authentication: one slot per lane, one lane per
// available CPU. multi serializes taking several slots, so that two
// multi-lane verifications cannot each hold half. The authenticators of
// successive configurations share one (Inherit).
type hashSlots struct {
	slots chan struct{}
	multi sync.Mutex
}

func newAuthenticator(n int) *Authenticator {
	return &Authenticator{
		users:   make(map[string]*account, n),
		now:     time.Now,
		hashing: &hashSlots{slots: make(chan struct{}, runtime.GOMAXPROCS(0))},
		pad:     newPadder(nil),
	}
}

// New returns a zero-config Authenticator for keys. If user is not empty,
// only that SSH user name is accepted; otherwise any valid name is.
func New(user string, keys []Key) *Authenticator {
	a := newAuthenticator(1)
	if user != "" {
		a.users[user] = newAccount(keys)
	} else {
		a.any = newAccount(keys)
	}
	return a
}

// NewUsers returns an Authenticator for configured users.
func NewUsers(users []User) *Authenticator {
	a := newAuthenticator(len(users))
	var hashes []PasswordHash
	for _, u := range users {
		acc := newAccount(u.Keys)
		acc.password = u.Password
		if u.Password != nil {
			hashes = append(hashes, u.Password)
		}
		acc.allowFrom = u.AllowFrom
		acc.expires = u.Expires
		acc.disabled = u.Disabled
		a.users[u.Name] = acc
	}
	a.pad = newPadder(hashes)
	return a
}

// Inherit makes a, built for a reloaded configuration, the successor of
// prev, before a is used. They share the password hashing slots, so that
// logins under both configurations together verify no more passwords at
// once than one would. a also keeps prev's padding when both have the same
// kinds and costs of hashes; otherwise a measures its own, so that a new,
// costlier hash cannot reveal its users.
func (a *Authenticator) Inherit(prev *Authenticator) {
	a.hashing = prev.hashing
	if slices.EqualFunc(a.pad.classes, prev.pad.classes, func(x, y PasswordHash) bool { return x.class() == y.class() }) {
		a.pad = prev.pad
	}
}

// Recheck reports whether the login that produced perms would still
// succeed under a, without verifying a password again: the user exists, is
// neither disabled nor expired and may log in from conn's address, and
// still has the key the login used, unexpired and with the same options, or
// the same password hash. After a reload the server rechecks every login
// against the current configuration, and, if configured to, every open
// connection.
func (a *Authenticator) Recheck(conn ssh.ConnMetadata, perms *ssh.Permissions) bool {
	user, ok := UserFrom(perms)
	if !ok {
		return false
	}
	acc := a.lookup(user)
	if !a.allowed(acc, conn) {
		return false
	}
	switch perms.Extensions[ExtMethod] {
	case MethodPublicKey:
		k, ok := acc.keys[perms.Extensions[extKey]]
		if !ok || !k.expires.IsZero() && a.now().After(k.expires) {
			return false
		}
		_, noTouch := perms.Extensions["no-touch-required"]
		return k.noTouchRequire == noTouch && k.sourceAddress == perms.CriticalOptions["source-address"]
	case MethodPassword:
		return acc.password != nil && acc.password.id() == perms.Extensions[extPassword]
	}
	return false
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
	if !ok || !a.allowed(acc, conn) {
		return nil, errDenied
	}
	if !k.expires.IsZero() && a.now().After(k.expires) {
		return nil, errDenied
	}
	perms := newPermissions(name, MethodPublicKey)
	perms.Extensions[ExtFingerprint] = ssh.FingerprintSHA256(key)
	perms.Extensions[extKey] = string(key.Marshal())
	if k.noTouchRequire {
		perms.Extensions["no-touch-required"] = ""
	}
	if k.sourceAddress != "" {
		// Enforced by x/crypto after authentication.
		perms.CriticalOptions = map[string]string{"source-address": k.sourceAddress}
	}
	return perms, nil
}

// Password is an ssh.ServerConfig.PasswordCallback: CheckPassword, and a
// failure waits as long as CheckPassword says.
func (a *Authenticator) Password(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	perms, wait, err := a.CheckPassword(conn, password)
	if err != nil {
		a.pad.sleep(wait)
	}
	return perms, err
}

// CheckPassword verifies one hash, the user's own or a dummy (see padder).
// After a failure the caller must wait for the returned duration before
// answering, so that the failure takes as long whichever user it names; the
// caller can count the failure first.
func (a *Authenticator) CheckPassword(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, time.Duration, error) {
	if len(password) == 0 || len(password) > MaxPasswordLen {
		return nil, 0, errDenied
	}
	a.pad.measure(a)
	name := conn.User()
	acc := a.lookup(name)
	h := a.pad.dummy
	if acc != nil && acc.password != nil {
		h = acc.password
	}
	n := a.acquire(h)
	start := time.Now()
	ok := h.verify(password)
	took := time.Since(start)
	a.release(n)
	a.pad.observe(took)
	if !ok || acc == nil || acc.password == nil || !a.allowed(acc, conn) {
		return nil, a.pad.rest(took), errDenied
	}
	perms := newPermissions(name, MethodPassword)
	perms.Extensions[extPassword] = acc.password.id()
	return perms, 0, nil
}

// acquire takes a hashing slot per lane of h, at most all of them, and
// returns how many it took.
func (a *Authenticator) acquire(h PasswordHash) int {
	n := min(h.lanes(), cap(a.hashing.slots))
	if n > 1 {
		a.hashing.multi.Lock()
		defer a.hashing.multi.Unlock()
	}
	for range n {
		a.hashing.slots <- struct{}{}
	}
	return n
}

func (a *Authenticator) release(n int) {
	for range n {
		<-a.hashing.slots
	}
}

// allowed checks the account-wide conditions of a login.
func (a *Authenticator) allowed(acc *account, conn ssh.ConnMetadata) bool {
	switch {
	case acc == nil, acc.disabled:
		return false
	case !acc.expires.IsZero() && a.now().After(acc.expires):
		return false
	}
	return addrAllowed(acc.allowFrom, conn.RemoteAddr())
}

func newPermissions(user, method string) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{ExtUser: user, ExtMethod: method}}
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
