// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// minCARSABits is the smallest RSA CA key accepted, as for user keys.
const minCARSABits = 2048

// LoadCertificate reads a host certificate for key from path; see
// ParseCertificate.
func LoadCertificate(path string, key ssh.PublicKey) (*ssh.Certificate, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertificate(data, key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cert, nil
}

// ParseCertificate parses a host certificate (an OpenSSH "-cert.pub" file)
// and checks it as OpenSSH clients do, whatever its validity period: it
// certifies key, has principals and no critical options, and its CA, of a
// supported type, signed it with SHA-2 (ADR 0008).
func ParseCertificate(data []byte, key ssh.PublicKey) (*ssh.Certificate, error) {
	cert, err := parseCert(data)
	if err != nil {
		return nil, err
	}
	switch {
	case cert.CertType != ssh.HostCert:
		return nil, errors.New("a user certificate, not a host certificate (sign with ssh-keygen -h)")
	case !bytes.Equal(cert.Key.Marshal(), key.Marshal()):
		return nil, fmt.Errorf("it certifies another key (%s), not %s", Fingerprint(cert.Key), Fingerprint(key))
	case len(cert.ValidPrincipals) == 0:
		return nil, errors.New("it has no principals, which current OpenSSH refuses (sign with -n NAMES)")
	case slices.Contains(cert.ValidPrincipals, ""):
		return nil, errors.New("it has an empty principal")
	case len(cert.CriticalOptions) > 0:
		return nil, fmt.Errorf("it has critical options (%s), which OpenSSH refuses in a host certificate", strings.Join(sortedKeys(cert.CriticalOptions), ", "))
	case cert.Signature == nil || cert.Signature.Format == ssh.KeyAlgoRSA:
		return nil, errors.New("its CA signed it with ssh-rsa (SHA-1), which OpenSSH refuses; sign again with -t rsa-sha2-512")
	}
	if err := checkCAKey(cert.SignatureKey); err != nil {
		return nil, err
	}
	if !verifies(cert) {
		return nil, errors.New("its CA signature does not verify")
	}
	return cert, nil
}

// parseCert parses a certificate without checking it.
func parseCert(data []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
}

func checkCAKey(ca ssh.PublicKey) error {
	switch ca.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		cpk, ok := ca.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("cannot inspect the RSA CA key")
		}
		k, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return errors.New("cannot inspect the RSA CA key")
		}
		if bits := k.N.BitLen(); bits < minCARSABits {
			return fmt.Errorf("its RSA CA key has %d bits, at least %d are required", bits, minCARSABits)
		}
		return nil
	default:
		return fmt.Errorf("its CA key type %s is not supported", ca.Type())
	}
}

// verifies checks the CA signature with x/crypto, its other checks
// neutralized.
func verifies(cert *ssh.Certificate) bool {
	after, before := cert.ValidAfter, cert.ValidBefore
	if after > math.MaxInt64 || before != ssh.CertTimeInfinity && (before > math.MaxInt64 || after >= before) {
		return false // valid at no time
	}
	cc := ssh.CertChecker{
		Clock: func() time.Time { return time.Unix(int64(after), 0) }, //nolint:gosec // G115: after <= math.MaxInt64, checked above
	}
	return cc.CheckCert(cert.ValidPrincipals[0], cert) == nil
}

// CertValidity is a certificate's validity at some time.
type CertValidity int

// Validity states.
const (
	CertValid CertValidity = iota
	CertExpiring
	CertExpired
	CertNotYetValid
)

// expiryWindow is the longest time before expiry that a certificate is
// reported as expiring; shorter for short-lived certificates (a third of
// their lifetime).
const expiryWindow = 30 * 24 * time.Hour

// Validity returns the state of cert at now.
func Validity(cert *ssh.Certificate, now time.Time) CertValidity {
	if !ValidAt(cert, now) {
		if t := now.Unix(); t < 0 || uint64(t) < cert.ValidAfter {
			return CertNotYetValid
		}
		return CertExpired
	}
	if cert.ValidBefore > math.MaxInt64 { // including CertTimeInfinity
		return CertValid
	}
	window := expiryWindow
	if life := cert.ValidBefore - cert.ValidAfter; life < uint64(3*expiryWindow/time.Second) {
		window = time.Duration(life) * time.Second / 3
	}
	if ValidUntil(cert).Sub(now) <= window {
		return CertExpiring
	}
	return CertValid
}

// ValidAt reports whether cert is valid at now.
func ValidAt(cert *ssh.Certificate, now time.Time) bool {
	t := now.Unix()
	if t < 0 {
		return false
	}
	u := uint64(t)
	return cert.ValidAfter <= u && (cert.ValidBefore == ssh.CertTimeInfinity || u < cert.ValidBefore)
}

// ValidFrom returns the start of cert's validity period, or the zero time
// for "always".
func ValidFrom(cert *ssh.Certificate) time.Time { return certTime(cert.ValidAfter, 0) }

// ValidUntil returns the end of cert's validity period, or the zero time
// for "forever".
func ValidUntil(cert *ssh.Certificate) time.Time {
	return certTime(cert.ValidBefore, ssh.CertTimeInfinity)
}

func certTime(t, never uint64) time.Time {
	if t == never || t > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(int64(t), 0).UTC()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// readFile reads a small file.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return readAll(f, fi.Size())
}
