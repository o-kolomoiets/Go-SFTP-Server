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
	ExtFingerprint = "pubkey-fp" // of the key, or of the certified key
	// Set for a login with a certificate, from CertAudit.
	ExtCertKeyID  = "gosftpd-cert-key-id"
	ExtCertSerial = "gosftpd-cert-serial"
	ExtCertCA     = "gosftpd-cert-ca-fp"
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
	// Principals a certificate from a trusted CA (Trust) needs one of to
	// log in as the user; nil means the user's name, empty none.
	Principals []string
}

type account struct {
	keys       map[string]Key
	cas        []caLine // cert-authority lines, in order
	principals []string
	password   PasswordHash
	allowFrom  []netip.Prefix
	expires    time.Time
	disabled   bool
}

// caLine is a cert-authority line and the id of its CA key.
type caLine struct {
	id string
	Key
}

// newAccount keeps cert-authority lines apart from keys: a plain key line
// never accepts a certificate, and a cert-authority line never its CA key.
func newAccount(keys []Key) *account {
	m := make(map[string]Key, len(keys))
	acc := &account{keys: m}
	for _, k := range keys {
		id := string(k.Key.Marshal())
		if k.certAuthority {
			acc.cas = append(acc.cas, caLine{id: id, Key: k})
		} else {
			m[id] = k
		}
	}
	return acc
}

// noKeys stands in for an unknown user, so that it takes the same path as a
// known user with a wrong key.
var noKeys = newAccount(nil)

// Authenticator checks public keys of configured users, or, in zero-config
// mode, of any user name against one authorized_keys set.
type Authenticator struct {
	users    map[string]*account
	any      *account            // zero-config: accepts every valid user name
	cas      map[string]struct{} // CAs trusted for every configured user (Trust)
	lineCAs  map[string]struct{} // CAs of cert-authority lines
	revoked  *RevokedKeys
	verified *certCache
	now      func() time.Time
	hashing  *hashSlots
	pad      *padder // equalizes the time of failures
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
		users:    make(map[string]*account, n),
		lineCAs:  map[string]struct{}{},
		verified: newCertCache(),
		now:      time.Now,
		hashing:  &hashSlots{slots: make(chan struct{}, runtime.GOMAXPROCS(0))},
		pad:      newPadder(nil),
	}
}

// addAccount adds acc under name ("" for any name) and indexes its CAs.
func (a *Authenticator) addAccount(name string, acc *account) {
	if name == "" {
		a.any = acc
	} else {
		a.users[name] = acc
	}
	for _, l := range acc.cas {
		a.lineCAs[l.id] = struct{}{}
	}
}

// New returns a zero-config Authenticator for keys. If user is not empty,
// only that SSH user name is accepted; otherwise any valid name is.
func New(user string, keys []Key) *Authenticator {
	a := newAuthenticator(1)
	acc := newAccount(keys)
	acc.principals = []string{user}
	a.addAccount(user, acc)
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
		acc.principals = u.Principals
		if acc.principals == nil {
			acc.principals = []string{u.Name}
		}
		a.addAccount(u.Name, acc)
	}
	a.pad = newPadder(hashes)
	return a
}

// Trust sets the CAs trusted for every configured user and the revocation
// list, before a is used.
func (a *Authenticator) Trust(cas []ssh.PublicKey, revoked *RevokedKeys) {
	a.cas = make(map[string]struct{}, len(cas))
	for _, k := range cas {
		a.cas[string(k.Marshal())] = struct{}{}
	}
	a.revoked = revoked
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

// Refusal returns why the login that produced perms would not succeed
// under a, or "", without verifying a password or signature again: the
// user exists, is neither disabled nor expired and may log in from conn's
// address, and still has the key the login used, unrevoked, unexpired and
// with the same options, or a certificate that a source still accepts, or
// the same password hash. The server rechecks every login against the
// configuration current after the handshake (a reload may have come in
// between).
func (a *Authenticator) Refusal(conn ssh.ConnMetadata, perms *ssh.Permissions) string {
	reason, _ := a.recheck(conn, perms, false)
	return reason
}

// Refused is Refusal as a *RefusedError, with the detail, the key and the
// certificate; nil when the login would succeed.
func (a *Authenticator) Refused(conn ssh.ConnMetadata, perms *ssh.Permissions) *RefusedError {
	reason, detail := a.recheck(conn, perms, false)
	if reason == "" {
		return nil
	}
	re := &RefusedError{Reason: reason, Detail: detail}
	if cert, err := parseCert(perms.Extensions[extKey]); err == nil {
		re.Key, re.Cert = cert.Key, cert
	} else if k, err := ssh.ParsePublicKey([]byte(perms.Extensions[extKey])); err == nil {
		re.Key = k
	}
	return re
}

// Recheck reports whether a connection logged in with perms may stay open
// under a, after a reload with reload.disconnect_removed_users: as
// Refusal, but a certificate whose validity period has passed since the
// login does not count, as in sshd.
func (a *Authenticator) Recheck(conn ssh.ConnMetadata, perms *ssh.Permissions) bool {
	reason, _ := a.recheck(conn, perms, true)
	return reason == ""
}

func (a *Authenticator) recheck(conn ssh.ConnMetadata, perms *ssh.Permissions, open bool) (reason, detail string) {
	user, ok := UserFrom(perms)
	if !ok {
		return ReasonRemoved, ""
	}
	acc := a.lookup(user)
	if acc == nil {
		return ReasonRemoved, "the user"
	}
	switch perms.Extensions[ExtMethod] {
	case MethodPublicKey:
		blob := perms.Extensions[extKey]
		k, ok := acc.keys[blob]
		if !ok {
			cert, err := parseCert(blob)
			if err != nil {
				return ReasonRemoved, "the key"
			}
			// The certificate is the one the login verified.
			reason, detail, users := a.certRefusal(acc, user, conn, cert, open)
			if !users {
				return ReasonRemoved, "the CA"
			}
			return reason, detail
		}
		_, noTouch := perms.Extensions[noTouchRequired]
		if k.noTouchRequire != noTouch || k.sourceAddress != perms.CriticalOptions[sourceAddress] {
			return ReasonRemoved, "the key's options" // changed
		}
		return a.keyRefusal(acc, k, conn), ""
	case MethodPassword:
		if reason := a.refusal(acc, conn); reason != "" {
			return reason, ""
		}
		if acc.password == nil || acc.password.id() != perms.Extensions[extPassword] {
			return ReasonRemoved, "the password" // changed
		}
		return "", ""
	}
	return ReasonRemoved, ""
}

// Len returns the number of accepted keys and cert-authority lines.
func (a *Authenticator) Len() int {
	n := 0
	if a.any != nil {
		n += len(a.any.keys) + len(a.any.cas)
	}
	for _, acc := range a.users {
		n += len(acc.keys) + len(acc.cas)
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
// unknown users, wrong keys or certificates, disabled or expired accounts
// and disallowed source addresses all fail the same way.
func (a *Authenticator) PublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	perms, err := a.KnownKey(conn, key)
	if err != nil {
		return nil, errDenied
	}
	return perms, nil
}

// KnownKey is PublicKey for a server that audits why logins fail: the
// client sees the same failure, but when key is one of the user's keys, or
// a certificate that a source trusts for the user, and the account or the
// key may not log in, the error is a *RefusedError with the reason. The
// client has only offered the key, so the reason is about the key, not
// about who offered it.
func (a *Authenticator) KnownKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if cert, ok := key.(*ssh.Certificate); ok {
		return a.certificate(conn, cert)
	}
	name := conn.User()
	acc := a.lookup(name)
	keys := noKeys.keys
	if acc != nil {
		keys = acc.keys
	}
	k, ok := keys[string(key.Marshal())]
	if !ok {
		return nil, errDenied
	}
	if reason := a.keyRefusal(acc, k, conn); reason != "" {
		return nil, &RefusedError{Reason: reason, Key: key}
	}
	perms := newPermissions(name, MethodPublicKey)
	perms.Extensions[ExtFingerprint] = ssh.FingerprintSHA256(key)
	perms.Extensions[extKey] = string(key.Marshal())
	if k.noTouchRequire {
		perms.Extensions[noTouchRequired] = ""
	}
	if k.sourceAddress != "" {
		// Enforced by x/crypto after authentication.
		perms.CriticalOptions = map[string]string{sourceAddress: k.sourceAddress}
	}
	return perms, nil
}

// certificate is KnownKey for a certificate (ADR 0007).
func (a *Authenticator) certificate(conn ssh.ConnMetadata, cert *ssh.Certificate) (*ssh.Permissions, error) {
	if !a.authentic(cert) {
		return nil, errDenied
	}
	name := conn.User()
	reason, detail, users := a.certRefusal(a.lookup(name), name, conn, cert, false)
	switch {
	case !users:
		return nil, errDenied
	case reason != "":
		return nil, &RefusedError{Reason: reason, Detail: detail, Key: cert.Key, Cert: cert}
	}
	return certPermissions(name, cert), nil
}

// VerifiedKey is a VerifiedPublicKeyCallback: the client has proved that
// it holds the key KnownKey accepted with perms. It checks the login again
// against a, which is the authenticator of a newer configuration when a
// reload happened in between: x/crypto does not ask KnownKey again for the
// signed request.
func (a *Authenticator) VerifiedKey(conn ssh.ConnMetadata, _ ssh.PublicKey, perms *ssh.Permissions) (*ssh.Permissions, error) {
	if re := a.Refused(conn, perms); re != nil {
		return nil, re
	}
	return perms, nil
}

// keyRefusal returns why acc may not log in with k now, or "".
func (a *Authenticator) keyRefusal(acc *account, k Key, conn ssh.ConnMetadata) string {
	if a.revoked.Revoked(k.Key) {
		return ReasonKeyRevoked
	}
	if reason := a.refusal(acc, conn); reason != "" {
		return reason
	}
	if !k.expires.IsZero() && a.now().After(k.expires) {
		return ReasonKeyExpired
	}
	return ""
}

// Reasons a login is refused although the key offered is one of the
// user's, or a certificate a source trusts for the user, or the password is
// right (RefusedError).
const (
	ReasonDisabled        = "disabled"           // the account is disabled
	ReasonExpired         = "expired"            // the account has expired
	ReasonAddress         = "address"            // allow_from, from= or the certificate's source-address does not match the client
	ReasonKeyExpired      = "key_expired"        // the expiry-time of the key or cert-authority line has passed
	ReasonKeyRevoked      = "key_revoked"        // the key, the certified key or the CA is in the revocation list
	ReasonCertPrincipal   = "cert_principal"     // no principal of the certificate may log in as the user
	ReasonCertInvalid     = "cert_invalid"       // a SHA-1 CA signature, an unsupported option, an empty principal
	ReasonCertNotYetValid = "cert_not_yet_valid" // before the certificate's validity period
	ReasonCertExpired     = "cert_expired"       // after the certificate's validity period
	ReasonRemoved         = "removed"            // a reload removed or changed the user, the key or the password
)

// RefusedError refuses a login with credentials of the user: one of the
// user's keys or a certificate that a source trusts for the user (offered;
// the client may not hold the private key), or the right password. The
// client is told no more than for any failure; the fields are for the
// audit and operational logs.
type RefusedError struct {
	Reason string
	Detail string           // more for the operational log, may be ""
	Key    ssh.PublicKey    // the key offered, or the certified key; nil for a password
	Cert   *ssh.Certificate // the certificate offered, if any
}

func (e *RefusedError) Error() string { return "authentication failed: " + e.Reason }

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
	if !ok || acc == nil || acc.password == nil {
		return nil, a.pad.rest(took), errDenied
	}
	if reason := a.refusal(acc, conn); reason != "" {
		return nil, a.pad.rest(took), &RefusedError{Reason: reason}
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

// refusal returns why the account-wide conditions refuse a login, or "".
func (a *Authenticator) refusal(acc *account, conn ssh.ConnMetadata) string {
	switch {
	case acc.disabled:
		return ReasonDisabled
	case !acc.expires.IsZero() && a.now().After(acc.expires):
		return ReasonExpired
	case !addrAllowed(acc.allowFrom, conn.RemoteAddr()):
		return ReasonAddress
	}
	return ""
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
