// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// User certificates (ADR 0007). x/crypto's CertChecker is not used to
// decide: it takes a certificate without principals as valid for every
// user, accepts SHA-1 CA signatures, checks the signature last and returns
// the certificate's own option maps as Permissions. It only verifies the
// signature here (verifySignature).

const (
	sourceAddress   = "source-address"
	forceCommand    = "force-command"
	noTouchRequired = "no-touch-required"

	// maxKeyIDLen bounds the key ID recorded for audit; the CA sets it.
	maxKeyIDLen = 256
	// maxVerified bounds the cache of verified certificates.
	maxVerified = 1024
)

// ParseCAKeys parses trusted CA keys: bare public keys, one per line. A
// line with options, a certificate or a key that fails the checks of
// authorized_keys is skipped and reported in warnings, as "source:line:
// reason".
func ParseCAKeys(data []byte, source string) (keys []ssh.PublicKey, warnings []string) {
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s:%d", source, n+1)
		pub, _, options, _, err := ssh.ParseAuthorizedKey(line)
		switch {
		case err != nil:
			warnings = append(warnings, fmt.Sprintf("%s: cannot parse key: %v", where, err))
		case len(options) > 0:
			warnings = append(warnings, where+": a CA key line takes no options, line skipped")
		default:
			if err := checkKeyType(pub); err != nil {
				warnings = append(warnings, where+": "+err.Error())
				continue
			}
			keys = append(keys, pub)
		}
	}
	return keys, warnings
}

// RevokedKeys is a revocation list. An entry revokes a key: a certificate
// entry revokes its certified key, as in OpenSSH's plain RevokedKeys file.
// Keys are compared in their parsed form, so a re-encoded signature or key
// does not escape. The zero value and nil revoke nothing.
type RevokedKeys struct {
	keys map[string]struct{}
}

// krlMagic starts an OpenSSH key revocation list (ssh-keygen -k).
var krlMagic = []byte("SSHKRL\n\x00")

// Add parses data, public keys or certificates one per line, with or
// without authorized_keys options, and adds them to r. It fails closed: any
// line that is not a key, and a KRL, is an error, and nothing of data is
// added then.
func (r *RevokedKeys) Add(data []byte, source string) error {
	if bytes.HasPrefix(data, krlMagic) {
		return fmt.Errorf("%s: a KRL (binary key revocation list) is not supported; list the keys or certificates as text", source)
	}
	var add []string
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return fmt.Errorf("%s:%d: cannot parse key: %w", source, n+1, err)
		}
		if c, ok := pub.(*ssh.Certificate); ok {
			pub = c.Key
		}
		add = append(add, string(pub.Marshal()))
	}
	if r.keys == nil {
		r.keys = make(map[string]struct{}, len(add))
	}
	for _, k := range add {
		r.keys[k] = struct{}{}
	}
	return nil
}

// Revoked reports whether k is revoked.
func (r *RevokedKeys) Revoked(k ssh.PublicKey) bool {
	if r == nil || len(r.keys) == 0 {
		return false
	}
	_, ok := r.keys[string(k.Marshal())]
	return ok
}

// Len returns the number of revoked keys.
func (r *RevokedKeys) Len() int {
	if r == nil {
		return 0
	}
	return len(r.keys)
}

// CertAudit returns the audit fields of a certificate: its key ID (bounded,
// valid UTF-8), its serial as a decimal string (CAs use random 64-bit
// serials, which JSON numbers do not keep) and the fingerprint of its CA.
func CertAudit(cert *ssh.Certificate) (keyID, serial, caFingerprint string) {
	keyID = strings.ToValidUTF8(cert.KeyId, "\uFFFD")
	if len(keyID) > maxKeyIDLen {
		keyID = keyID[:maxKeyIDLen]
		for !utf8.ValidString(keyID) { // only the cut can split a rune
			keyID = keyID[:len(keyID)-1]
		}
	}
	return keyID, strconv.FormatUint(cert.Serial, 10), ssh.FingerprintSHA256(cert.SignatureKey)
}

// certPermissions returns the Permissions of a login with cert. They are
// built afresh: nothing of the certificate's own option maps is copied but
// its source-address, which x/crypto enforces. no-touch-required is left
// out: x/crypto honors the certificate's own extension, and caLineRefusal
// refuses it where the accepting line does not allow it.
func certPermissions(name string, cert *ssh.Certificate) *ssh.Permissions {
	perms := newPermissions(name, MethodPublicKey)
	keyID, serial, ca := CertAudit(cert)
	perms.Extensions[ExtFingerprint] = ssh.FingerprintSHA256(cert.Key)
	perms.Extensions[extKey] = string(cert.Marshal())
	perms.Extensions[ExtCertKeyID] = keyID
	perms.Extensions[ExtCertSerial] = serial
	perms.Extensions[ExtCertCA] = ca
	if sa, ok := cert.CriticalOptions[sourceAddress]; ok {
		perms.CriticalOptions = map[string]string{sourceAddress: sa}
	}
	return perms
}

// authentic reports whether cert is a user certificate of acceptable keys,
// signed, with a signature that verifies, by a CA that some source trusts.
// It does not depend on the user, so that a user that does not exist costs
// the same work.
func (a *Authenticator) authentic(cert *ssh.Certificate) bool {
	if cert.CertType != ssh.UserCert || !a.knownCA(cert.SignatureKey) ||
		checkKeyType(cert.Key) != nil || checkKeyType(cert.SignatureKey) != nil {
		return false
	}
	return a.verified.check(cert)
}

func (a *Authenticator) knownCA(k ssh.PublicKey) bool {
	blob := k.Marshal()
	_, global := a.cas[string(blob)]
	_, line := a.lineCAs[string(blob)]
	return global || line
}

// certRefusal checks a login of acc, as name, with cert, which must be
// authentic, in the order of ADR 0007. users is false when cert is not a
// credential of acc at all (no source trusts its CA for acc): the login
// fails like a wrong key. Otherwise reason is "" when the login is
// accepted, and detail tells the operational log more. With open, the
// certificate's validity period is not checked: an open connection is not
// closed because its certificate expired since it logged in.
func (a *Authenticator) certRefusal(acc *account, name string, conn ssh.ConnMetadata, cert *ssh.Certificate, open bool) (reason, detail string, users bool) {
	if acc == nil {
		return "", "", false
	}
	sources := a.sources(acc, cert.SignatureKey)
	if len(sources) == 0 {
		return "", "", false
	}
	switch {
	case a.revoked.Revoked(cert.Key):
		return ReasonKeyRevoked, "the certified key is revoked", true
	case a.revoked.Revoked(cert.SignatureKey):
		return ReasonKeyRevoked, "the CA is revoked", true
	case acc.disabled:
		return ReasonDisabled, "", true
	case !acc.expires.IsZero() && a.now().After(acc.expires):
		return ReasonExpired, "", true
	}
	if d := certInvalid(cert); d != "" {
		return ReasonCertInvalid, d, true
	}
	if !open {
		if r := certValidity(cert, a.now()); r != "" {
			return r, "", true
		}
	}
	addr := conn.RemoteAddr()
	if !addrAllowed(acc.allowFrom, addr) {
		return ReasonAddress, "allow_from", true
	}
	if sa, ok := cert.CriticalOptions[sourceAddress]; ok && !sourceAddressAllows(sa, addr) {
		return ReasonAddress, "the certificate's source-address", true
	}
	best := -1
	for _, line := range sources {
		stage, r, d := a.sourceRefusal(acc, name, addr, cert, line)
		if r == "" {
			return "", "", true
		}
		if stage > best {
			best, reason, detail = stage, r, d
		}
	}
	return reason, detail, true
}

// sources returns what trusts the CA ca for acc, in order: nil for the
// trusted CAs of every configured user, then its cert-authority lines.
// When any login name is accepted, a line without principals= trusts
// nothing: it would let every principal of the CA in (config warns).
func (a *Authenticator) sources(acc *account, ca ssh.PublicKey) []*Key {
	id := string(ca.Marshal())
	var s []*Key
	if _, ok := a.cas[id]; ok && acc != a.any {
		s = append(s, nil)
	}
	for i := range acc.cas {
		if l := &acc.cas[i]; l.id == id && (acc != a.any || l.principals != nil) {
			s = append(s, &l.Key)
		}
	}
	return s
}

// sourceRefusal checks what depends on the source that trusts the CA:
// line is a cert-authority line, or nil for the trusted CAs. stage says how
// far the check got, so that a refusal can name the source that came
// closest.
func (a *Authenticator) sourceRefusal(acc *account, name string, addr net.Addr, cert *ssh.Certificate, line *Key) (stage int, reason, detail string) {
	if !a.principalAllowed(acc, name, cert, line) {
		return 0, ReasonCertPrincipal, "no principal of the certificate may log in as " + strconv.Quote(name)
	}
	if line == nil {
		return 4, "", ""
	}
	if line.sourceAddress != "" && !sourceAddressAllows(line.sourceAddress, addr) {
		return 1, ReasonAddress, "from= of " + line.Source
	}
	if _, noTouch := cert.Extensions[noTouchRequired]; noTouch && isSK(cert.Key) && !line.noTouchRequire {
		return 2, ReasonCertInvalid, "no-touch-required certificate, but " + line.Source + " does not allow no-touch-required"
	}
	if !line.expires.IsZero() && a.now().After(line.expires) {
		return 3, ReasonKeyExpired, "expiry-time= of " + line.Source
	}
	return 4, "", ""
}

// principalAllowed reports whether a principal of cert may log in as name
// through line (nil: the trusted CAs).
func (a *Authenticator) principalAllowed(acc *account, name string, cert *ssh.Certificate, line *Key) bool {
	has := func(allowed []string) bool {
		return slices.ContainsFunc(cert.ValidPrincipals, func(p string) bool { return p != "" && slices.Contains(allowed, p) })
	}
	switch {
	case line == nil:
		return has(acc.principals)
	case acc == a.any:
		// Any login name is accepted, so the name must be a principal of
		// both the line and the certificate.
		return slices.Contains(line.principals, name) && slices.Contains(cert.ValidPrincipals, name)
	case line.principals == nil:
		return has([]string{name})
	default:
		return has(line.principals)
	}
}

// certInvalid says why cert cannot be accepted as issued, or "".
func certInvalid(cert *ssh.Certificate) string {
	if cert.Signature == nil || cert.Signature.Format == ssh.KeyAlgoRSA {
		return "the CA signed it with ssh-rsa (SHA-1); sign with rsa-sha2-512 (ssh-keygen -t rsa-sha2-512)"
	}
	if slices.Contains(cert.ValidPrincipals, "") {
		return "it has an empty principal"
	}
	names := make([]string, 0, len(cert.CriticalOptions))
	for n := range cert.CriticalOptions {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		v := cert.CriticalOptions[n]
		switch n {
		case sourceAddress:
			if !validSourceAddress(v) {
				return fmt.Sprintf("invalid source-address %q", v)
			}
		case forceCommand:
			if !SFTPOnlyCommand(v) {
				return fmt.Sprintf("force-command %q: only internal-sftp or a path to sftp-server, without arguments, is accepted", v)
			}
		default:
			return fmt.Sprintf("unsupported critical option %q", n)
		}
	}
	return ""
}

// certValidity checks valid_after <= now < valid_before as x/crypto does.
func certValidity(cert *ssh.Certificate, now time.Time) string {
	n := now.Unix()
	if cert.ValidAfter > math.MaxInt64 || n < int64(cert.ValidAfter) {
		return ReasonCertNotYetValid
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && (cert.ValidBefore > math.MaxInt64 || n >= int64(cert.ValidBefore)) {
		return ReasonCertExpired
	}
	return ""
}

func isSK(k ssh.PublicKey) bool {
	t := k.Type()
	return t == ssh.KeyAlgoSKED25519 || t == ssh.KeyAlgoSKECDSA256
}

// certCache remembers certificates whose CA signature verified, so that a
// client alternating certificates in queries cannot make the server verify
// the same signatures again and again. Keyed by the whole certificate,
// signature included.
type certCache struct {
	mu     sync.Mutex
	ok     map[[sha256.Size]byte]struct{}
	verify func(*ssh.Certificate) bool // verifySignature; tests count calls
}

func newCertCache() *certCache {
	return &certCache{ok: map[[sha256.Size]byte]struct{}{}, verify: verifySignature}
}

func (c *certCache) check(cert *ssh.Certificate) bool {
	sum := sha256.Sum256(cert.Marshal())
	c.mu.Lock()
	_, hit := c.ok[sum]
	c.mu.Unlock()
	if hit {
		return true
	}
	if !c.verify(cert) {
		return false
	}
	c.mu.Lock()
	if len(c.ok) >= maxVerified {
		clear(c.ok)
	}
	c.ok[sum] = struct{}{}
	c.mu.Unlock()
	return true
}

// verifySignature verifies the CA signature of cert with CheckCert, so
// that x/crypto's handling of security-key CAs applies, with its other
// checks neutralized: they are made by certRefusal, which records why.
func verifySignature(cert *ssh.Certificate) bool {
	after, before := cert.ValidAfter, cert.ValidBefore
	if after > math.MaxInt64 || before != ssh.CertTimeInfinity && (before > math.MaxInt64 || after >= before) {
		return false // valid at no time: CheckCert cannot verify it, and it could never log in
	}
	opts := make([]string, 0, len(cert.CriticalOptions))
	for n := range cert.CriticalOptions {
		opts = append(opts, n)
	}
	principal := ""
	if len(cert.ValidPrincipals) > 0 {
		principal = cert.ValidPrincipals[0]
	}
	cc := ssh.CertChecker{
		SupportedCriticalOptions: opts,
		Clock:                    func() time.Time { return time.Unix(int64(after), 0) }, //nolint:gosec // G115: after <= math.MaxInt64, checked above
	}
	return cc.CheckCert(principal, cert) == nil
}

var errNotCert = errors.New("not a certificate")

// parseCert parses a certificate blob recorded in Permissions.
func parseCert(blob string) (*ssh.Certificate, error) {
	k, err := ssh.ParsePublicKey([]byte(blob))
	if err != nil {
		return nil, err
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, errNotCert
	}
	return c, nil
}
