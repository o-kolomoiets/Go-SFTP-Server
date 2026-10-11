// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func mustLoad(t *testing.T, path string) ssh.Signer {
	t.Helper()
	k, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fp(k ssh.Signer) string { return Fingerprint(k.PublicKey()) }

// pubFile returns the fingerprint of "<path>.pub".
func pubFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return Fingerprint(k)
}

// writeCert certifies the key of key file p as a host certificate in
// p-cert.pub.
func writeCert(t *testing.T, ca ssh.Signer, p string) {
	t.Helper()
	c := &ssh.Certificate{
		Key:             mustLoad(t, p).PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           filepath.Base(p),
		ValidPrincipals: []string{"sftp.example.org"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Cert(p), ssh.MarshalAuthorizedKey(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

func certKeyFP(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseCert(data)
	if err != nil {
		t.Fatal(err)
	}
	return Fingerprint(c.Key)
}

// A rotation creates P.next, makes it P, keeps the previous key as P.old,
// and deletes P.old; certificates and public key files follow their keys.
func TestRotation(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), DefaultFile)
	first, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	ca := mustSigner(t)
	writeCert(t, ca, p)

	var prepared []string
	prepare := func(f string) error { prepared = append(prepared, f); return nil }
	next, err := StartRotation(p, "", prepare)
	if err != nil {
		t.Fatal(err)
	}
	if next.PublicKey().Type() != ssh.KeyAlgoED25519 || len(prepared) != 2 {
		t.Errorf("next key %s, prepared %v; want ed25519, key and .pub", next.PublicKey().Type(), prepared)
	}
	if _, err := StartRotation(p, "", nil); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Errorf("second StartRotation() = %v", err)
	}
	writeCert(t, ca, Next(p))

	f, err := FinishRotation(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp(f.New) != fp(next) || fp(f.Old) != fp(first) || !f.Certified || f.Age <= 0 {
		t.Errorf("Finished = %+v", f)
	}
	if fp(mustLoad(t, p)) != fp(next) || fp(mustLoad(t, Old(p))) != fp(first) || exists(Next(p)) {
		t.Error("keys not rotated")
	}
	if pubFile(t, p) != fp(next) || pubFile(t, Old(p)) != fp(first) || exists(Next(p)+".pub") {
		t.Error("public key files not rotated")
	}
	if certKeyFP(t, Cert(p)) != fp(next) || certKeyFP(t, Cert(Old(p))) != fp(first) || exists(Cert(Next(p))) {
		t.Error("certificates not rotated")
	}
	if _, err := StartRotation(p, "", nil); err == nil || !strings.Contains(err.Error(), "retire") {
		t.Errorf("StartRotation() before retiring = %v", err)
	}

	if completed, err := RollbackRotation(p, nil); err != nil || completed {
		t.Fatalf("RollbackRotation() = %v, %v", completed, err)
	}
	if fp(mustLoad(t, p)) != fp(first) || fp(mustLoad(t, Next(p))) != fp(next) || exists(Old(p)) {
		t.Error("rollback did not swap the keys back")
	}
	if pubFile(t, p) != fp(first) || pubFile(t, Next(p)) != fp(next) || certKeyFP(t, Cert(p)) != fp(first) || certKeyFP(t, Cert(Next(p))) != fp(next) {
		t.Error("rollback did not swap the files back")
	}

	if _, err := FinishRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	if err := RetireRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{Old(p), Old(p) + ".pub", Cert(Old(p))} {
		if exists(f) {
			t.Errorf("%s still exists", f)
		}
	}
	if err := RetireRotation(p, nil); err == nil {
		t.Error("RetireRotation() without P.old succeeded")
	}

	// Another rotation, to another type, aborted.
	if k, err := StartRotation(p, TypeECDSA, nil); err != nil || k.PublicKey().Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("StartRotation(ecdsa) = %v", err)
	}
	if err := AbortRotation(p); err != nil {
		t.Fatal(err)
	}
	if exists(Next(p)) || exists(Next(p)+".pub") {
		t.Error("abort left P.next")
	}
	if err := AbortRotation(p); err == nil {
		t.Error("AbortRotation() without P.next succeeded")
	}
	if fp(mustLoad(t, p)) != fp(next) {
		t.Error("abort changed P")
	}
}

// An interrupted finish (P.old made, P.next not yet renamed, or renamed
// without the certificates and public keys) is completed by running it
// again; P exists throughout.
func TestFinishRotationInterrupted(t *testing.T) {
	t.Parallel()

	p := filepath.Join(t.TempDir(), DefaultFile)
	first, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	next, err := StartRotation(p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Interrupted after the link.
	if err := os.Link(p, Old(p)); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishRotation(p, nil); err != nil {
		t.Fatalf("FinishRotation() after an interrupted one: %v", err)
	}
	if fp(mustLoad(t, p)) != fp(next) || fp(mustLoad(t, Old(p))) != fp(first) {
		t.Error("keys not rotated")
	}

	// Interrupted after the rename: the .pub files are stale.
	if err := os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(first.PublicKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := FinishRotation(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Age != 0 || pubFile(t, p) != fp(next) {
		t.Errorf("completion: age %v, P.pub %s", f.Age, pubFile(t, p))
	}

	// P.old that holds another key is not replaced.
	q := filepath.Join(t.TempDir(), DefaultFile)
	if _, err := Generate(q); err != nil {
		t.Fatal(err)
	}
	if _, err := StartRotation(q, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(Old(q)); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishRotation(q, nil); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("FinishRotation() over a foreign P.old = %v", err)
	}
}

// An interrupted rollback, abort or retire is completed by running it
// again, and leaves no certificate that a later step would take for
// another key's.
func TestRotationStepsInterrupted(t *testing.T) {
	t.Parallel()

	ca := mustSigner(t)
	setup := func(t *testing.T) (p string, first, next ssh.Signer) {
		t.Helper()
		p = filepath.Join(t.TempDir(), DefaultFile)
		first, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, p)
		if next, err = StartRotation(p, "", nil); err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, Next(p))
		return p, first, next
	}
	consistent := func(t *testing.T, p string, cur, other ssh.Signer, otherFile string) {
		t.Helper()
		if fp(mustLoad(t, p)) != fp(cur) || pubFile(t, p) != fp(cur) || certKeyFP(t, Cert(p)) != fp(cur) {
			t.Errorf("%s, its .pub or its certificate is not %s", p, fp(cur))
		}
		if fp(mustLoad(t, otherFile)) != fp(other) || pubFile(t, otherFile) != fp(other) || certKeyFP(t, Cert(otherFile)) != fp(other) {
			t.Errorf("%s, its .pub or its certificate is not %s", otherFile, fp(other))
		}
	}

	t.Run("rollback after its rename", func(t *testing.T) {
		t.Parallel()
		p, first, next := setup(t)
		if _, err := FinishRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		// The rollback stopped once P.old had replaced P.
		if err := os.Link(p, Next(p)); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(Old(p), p); err != nil {
			t.Fatal(err)
		}
		completed, err := RollbackRotation(p, nil)
		if err != nil || !completed {
			t.Fatalf("RollbackRotation() again = %v, %v", completed, err)
		}
		consistent(t, p, first, next, Next(p))
		if anyExists(Old(p)+".pub", Cert(Old(p))) {
			t.Error("files of P.old are left")
		}
		// During an ordinary rotation there is nothing to roll back.
		if _, err := RollbackRotation(p, nil); err == nil {
			t.Error("RollbackRotation() before a finish succeeded")
		}
	})

	t.Run("abort without its key", func(t *testing.T) {
		t.Parallel()
		p, first, _ := setup(t)
		if err := os.Remove(Next(p)); err != nil {
			t.Fatal(err)
		}
		if err := AbortRotation(p); err != nil {
			t.Fatalf("AbortRotation() of the files left: %v", err)
		}
		if anyExists(Next(p)+".pub", Cert(Next(p))) {
			t.Error("files of P.next are left")
		}
		// A stale certificate of an earlier next key never moves to P.
		writeCert(t, ca, p)
		data, err := os.ReadFile(Cert(p))
		if err != nil {
			t.Fatal(err)
		}
		next, err := StartRotation(p, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(Cert(Next(p)), data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := FinishRotation(p, nil); err == nil || !strings.Contains(err.Error(), "another key") {
			t.Errorf("FinishRotation() with a foreign next certificate = %v", err)
		}
		if err := os.Remove(Cert(Next(p))); err != nil {
			t.Fatal(err)
		}
		f, err := FinishRotation(p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if f.Certified || exists(Cert(p)) || fp(f.New) != fp(next) || fp(f.Old) != fp(first) {
			t.Errorf("Finished = %+v; P-cert.pub exists: %v", f, exists(Cert(p)))
		}
	})

	t.Run("retire after an interrupted finish", func(t *testing.T) {
		t.Parallel()
		p, _, next := setup(t)
		// The finish stopped after its rename.
		if err := os.Link(p, Old(p)); err != nil {
			t.Fatal(err)
		}
		if err := RetireRotation(p, nil); err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Errorf("RetireRotation() between the link and the rename = %v", err)
		}
		if err := AbortRotation(p); err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Errorf("AbortRotation() between the link and the rename = %v", err)
		}
		if err := os.Rename(Next(p), p); err != nil {
			t.Fatal(err)
		}
		if err := RetireRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		if fp(mustLoad(t, p)) != fp(next) || pubFile(t, p) != fp(next) || certKeyFP(t, Cert(p)) != fp(next) {
			t.Error("retire did not complete the finish")
		}
		if anyExists(Old(p), Old(p)+".pub", Cert(Old(p)), Next(p)+".pub", Cert(Next(p))) {
			t.Error("files left after retire")
		}
	})
}

func TestRotationRefusals(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, DefaultFile)
	if _, err := FinishRotation(p, nil); err == nil {
		t.Error("FinishRotation() without keys succeeded")
	}
	if _, err := StartRotation(p, "", nil); err == nil {
		t.Error("StartRotation() without P succeeded")
	}
	if _, err := RollbackRotation(p, nil); err == nil || !strings.Contains(err.Error(), "no previous key") {
		t.Errorf("RollbackRotation() without P.old = %v", err)
	}
	if _, err := Generate(p); err != nil {
		t.Fatal(err)
	}
	if _, err := StartRotation(p, "dsa", nil); err == nil {
		t.Error("StartRotation(dsa) succeeded")
	}
	// P.next with P's key.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Next(p), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FinishRotation(p, nil); err == nil || !strings.Contains(err.Error(), "same key") {
		t.Errorf("FinishRotation() with P.next = P: %v", err)
	}
	// A missing P is not generated next to P.next.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerate(p); err == nil || !strings.Contains(err.Error(), "generated only when") {
		t.Errorf("LoadOrGenerate() next to P.next = %v", err)
	}
}

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := GenerateType(filepath.Join(t.TempDir(), "ca"), TypeED25519)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// hostCertFor signs a host certificate of key, changed by edit first.
func hostCertFor(t *testing.T, ca, key ssh.Signer, edit func(*ssh.Certificate)) []byte {
	t.Helper()
	c := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "host",
		ValidPrincipals: []string{"sftp.example.org"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(365 * 24 * time.Hour).Unix()),
	}
	if edit != nil {
		edit(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(c)
}

func TestParseCertificate(t *testing.T) {
	t.Parallel()

	ca, key, other := mustSigner(t), mustSigner(t), mustSigner(t)
	if _, err := ParseCertificate(hostCertFor(t, ca, key, nil), key.PublicKey()); err != nil {
		t.Fatalf("valid certificate: %v", err)
	}
	// An expired certificate is still a valid file: it is just not offered.
	expired := hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix()) })
	if _, err := ParseCertificate(expired, key.PublicKey()); err != nil {
		t.Errorf("expired certificate: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCA, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	sha1CA, err := ssh.NewSignerWithAlgorithms(rsaCA.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	tampered := hostCertFor(t, ca, key, nil)
	pub, _, _, _, err := ssh.ParseAuthorizedKey(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tc := pub.(*ssh.Certificate)
	tc.ValidPrincipals = []string{"evil.example.org"}
	tampered = ssh.MarshalAuthorizedKey(tc)

	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"user certificate", hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.CertType = ssh.UserCert }), "user certificate"},
		{"another key", hostCertFor(t, ca, other, nil), "another key"},
		{"no principals", hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = nil }), "no principals"},
		{"empty principal", hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.ValidPrincipals = []string{""} }), "empty principal"},
		{"critical option", hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "x"} }), "critical options"},
		{"SHA-1 CA signature", hostCertFor(t, sha1CA, key, nil), "SHA-1"},
		{"tampered", tampered, "does not verify"},
		{"valid at no time", hostCertFor(t, ca, key, func(c *ssh.Certificate) { c.ValidAfter, c.ValidBefore = 10, 5 }), "does not verify"},
		{"plain key", ssh.MarshalAuthorizedKey(key.PublicKey()), "not a certificate"},
		{"garbage", []byte("nonsense"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseCertificate(tc.data, key.PublicKey()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseCertificate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidity(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	day := 24 * time.Hour
	cert := func(after, before time.Time) *ssh.Certificate {
		return &ssh.Certificate{ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix())}
	}
	for _, tc := range []struct {
		name string
		cert *ssh.Certificate
		want CertValidity
	}{
		{"forever", &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, CertValid},
		{"a year, 60 days left", cert(now.Add(-300*day), now.Add(60*day)), CertValid},
		{"a year, 20 days left", cert(now.Add(-340*day), now.Add(20*day)), CertExpiring},
		{"a week, 3 days left", cert(now.Add(-4*day), now.Add(3*day)), CertValid},
		{"a week, 2 days left", cert(now.Add(-5*day), now.Add(2*day)), CertExpiring},
		{"expired", cert(now.Add(-2*day), now.Add(-time.Second)), CertExpired},
		{"not yet valid", cert(now.Add(time.Minute), now.Add(day)), CertNotYetValid},
	} {
		if got := Validity(tc.cert, now); got != tc.want {
			t.Errorf("%s: Validity() = %d, want %d", tc.name, got, tc.want)
		}
	}
	if !ValidUntil(&ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}).IsZero() || !ValidFrom(&ssh.Certificate{}).IsZero() {
		t.Error("open ends are not the zero time")
	}
}

// A key file is written whole or not at all, and never over an existing
// one; the temporary file is gone.
func TestGenerateWithPrepare(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	errPrepare := os.ErrPermission
	if _, err := GenerateWith(p, TypeED25519, func(string) error { return errPrepare }); err == nil {
		t.Fatal("GenerateWith() with a failing prepare succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("left %d files behind", len(entries))
	}
	k, err := GenerateWith(p, TypeED25519, nil)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("files = %v, want the key and its .pub", entries)
	}
	if !bytes.Equal(mustLoad(t, p).PublicKey().Marshal(), k.PublicKey().Marshal()) {
		t.Error("loaded key differs")
	}
}
