// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"slices"
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
	next, _, err := StartRotation(p, "", prepare)
	if err != nil {
		t.Fatal(err)
	}
	if next.PublicKey().Type() != ssh.KeyAlgoED25519 || len(prepared) != 2 {
		t.Errorf("next key %s, prepared %v; want ed25519, key and .pub", next.PublicKey().Type(), prepared)
	}
	if _, _, err := StartRotation(p, "", nil); err == nil || !strings.Contains(err.Error(), "in progress") {
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
	consistent(t, p, next)
	consistent(t, Old(p), first)
	if anyExists(Next(p), Next(p)+".pub", Cert(Next(p))) {
		t.Error("files of P.next are left")
	}
	if _, _, err := StartRotation(p, "", nil); err == nil || !strings.Contains(err.Error(), "retire") {
		t.Errorf("StartRotation() before retiring = %v", err)
	}

	if _, err := RollbackRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	consistent(t, p, first)
	consistent(t, Next(p), next)
	if anyExists(Old(p), Old(p)+".pub", Cert(Old(p))) {
		t.Error("files of P.old are left")
	}

	if _, err := FinishRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := RetireRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	consistent(t, p, next)
	if anyExists(Old(p), Old(p)+".pub", Cert(Old(p))) {
		t.Error("files of P.old are left")
	}
	if _, err := RetireRotation(p, nil); err == nil {
		t.Error("RetireRotation() without P.old succeeded")
	}

	// Another rotation, to another type, aborted.
	if k, _, err := StartRotation(p, TypeECDSA, nil); err != nil || k.PublicKey().Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("StartRotation(ecdsa) = %v", err)
	}
	if _, err := AbortRotation(p, nil); err != nil {
		t.Fatal(err)
	}
	if anyExists(Next(p), Next(p)+".pub") {
		t.Error("abort left P.next")
	}
	if _, err := AbortRotation(p, nil); err == nil {
		t.Error("AbortRotation() without P.next succeeded")
	}
	consistent(t, p, next)
}

// consistent checks that key file f holds key, with its public key file and
// certificate.
func consistent(t *testing.T, f string, key ssh.Signer) {
	t.Helper()
	if fp(mustLoad(t, f)) != fp(key) || pubFile(t, f) != fp(key) || certKeyFP(t, Cert(f)) != fp(key) {
		t.Errorf("%s, its .pub or its certificate is not %s", f, fp(key))
	}
}

func anyExists(paths ...string) bool { return slices.ContainsFunc(paths, exists) }

// Every step, interrupted between its file operations, is completed by
// running it again; the other steps then neither lose a certificate nor
// take a half-done step for something else.
func TestRotationInterrupted(t *testing.T) {
	t.Parallel()

	ca := mustSigner(t)
	// rotating returns P (key A, certified) with P.next (key B, certified).
	rotating := func(t *testing.T) (p string, a, b ssh.Signer) {
		t.Helper()
		p = filepath.Join(t.TempDir(), DefaultFile)
		a, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, p)
		if b, _, err = StartRotation(p, "", nil); err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, Next(p))
		return p, a, b
	}
	link := func(t *testing.T, from, to string) {
		t.Helper()
		if err := os.Link(from, to); err != nil {
			t.Fatal(err)
		}
	}
	rename := func(t *testing.T, from, to string) {
		t.Helper()
		if err := os.Rename(from, to); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(t *testing.T, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
	}

	t.Run("finish after its link", func(t *testing.T) {
		t.Parallel()
		p, a, b := rotating(t)
		link(t, p, Old(p))
		_, err := RetireRotation(p, nil)
		refused(t, err, "run rotate --finish again")
		_, err = AbortRotation(p, nil)
		refused(t, err, "run rotate --finish again")
		if _, err := FinishRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, b)
		consistent(t, Old(p), a)
	})

	// After its rename, before the files follow the keys: P is B, P.old A.
	finishRenamed := func(t *testing.T) (p string, a, b ssh.Signer) {
		t.Helper()
		p, a, b = rotating(t)
		link(t, p, Old(p))
		rename(t, Next(p), p)
		return p, a, b
	}
	t.Run("finish after its rename", func(t *testing.T) {
		t.Parallel()
		p, a, b := finishRenamed(t)
		f, err := FinishRotation(p, nil)
		if err != nil || f.Age != 0 || !f.Certified || len(f.Changes) == 0 {
			t.Fatalf("FinishRotation() again = %+v, %v", f, err)
		}
		consistent(t, p, b)
		consistent(t, Old(p), a)
	})
	t.Run("abort after an interrupted finish", func(t *testing.T) {
		t.Parallel()
		p, a, b := finishRenamed(t)
		_, err := AbortRotation(p, nil)
		refused(t, err, "no rotation is in progress")
		consistent(t, p, b) // B's certificate is kept, with B
		consistent(t, Old(p), a)
	})
	t.Run("retire after an interrupted finish", func(t *testing.T) {
		t.Parallel()
		p, _, b := finishRenamed(t)
		if _, err := RetireRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, b)
		if anyExists(Old(p), Old(p)+".pub", Cert(Old(p)), Next(p)+".pub", Cert(Next(p))) {
			t.Error("files left after retire")
		}
	})

	// A rollback after its link: P is B, P.next a link to it, P.old A.
	t.Run("rollback after its link", func(t *testing.T) {
		t.Parallel()
		p, a, b := rotating(t)
		if _, err := FinishRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		link(t, p, Next(p))
		_, err := RetireRotation(p, nil)
		refused(t, err, "run rotate --rollback again")
		_, err = AbortRotation(p, nil)
		refused(t, err, "run rotate --rollback again")
		if _, err := RollbackRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, a)
		consistent(t, Next(p), b)
	})

	// After its rename, before the files follow the keys: P is A, P.next B.
	rollbackRenamed := func(t *testing.T) (p string, a, b ssh.Signer) {
		t.Helper()
		p, a, b = rotating(t)
		if _, err := FinishRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		link(t, p, Next(p))
		rename(t, Old(p), p)
		return p, a, b
	}
	t.Run("rollback after its rename", func(t *testing.T) {
		t.Parallel()
		p, a, b := rollbackRenamed(t)
		changes, err := RollbackRotation(p, nil)
		if err != nil || len(changes) == 0 {
			t.Fatalf("RollbackRotation() again = %q, %v", changes, err)
		}
		consistent(t, p, a)
		consistent(t, Next(p), b)
		if anyExists(Old(p)+".pub", Cert(Old(p))) {
			t.Error("files of P.old are left")
		}
	})
	t.Run("retire after an interrupted rollback", func(t *testing.T) {
		t.Parallel()
		p, a, b := rollbackRenamed(t)
		_, err := RetireRotation(p, nil)
		refused(t, err, "no previous key")
		consistent(t, p, a) // A's certificate is kept, with A
		consistent(t, Next(p), b)
	})
	t.Run("abort after an interrupted rollback", func(t *testing.T) {
		t.Parallel()
		p, a, _ := rollbackRenamed(t)
		if _, err := AbortRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, a)
		if anyExists(Next(p), Next(p)+".pub", Cert(Next(p)), Old(p)+".pub", Cert(Old(p))) {
			t.Error("files left after abort")
		}
	})

	// A previous key not retired yet, and a next key copied from another
	// server: nothing is half done, so retire and abort work, and keep the
	// other key's files.
	t.Run("previous and copied next key", func(t *testing.T) {
		t.Parallel()
		p, a, b := rotating(t)
		if _, err := Generate(Old(p)); err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, Old(p))
		_, err := FinishRotation(p, nil)
		refused(t, err, "holds another key; retire it first")
		_, err = RollbackRotation(p, nil)
		refused(t, err, "holds another key; abort that rotation first")
		if _, err := RetireRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, a)
		consistent(t, Next(p), b)
		if _, err := Generate(Old(p)); err != nil {
			t.Fatal(err)
		}
		if _, err := AbortRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		consistent(t, p, a)
	})

	// Files of a previous key that is gone are removed; a rollback without
	// a previous key changes no key.
	t.Run("stale files of a previous key", func(t *testing.T) {
		t.Parallel()
		p, a, b := rotating(t)
		if err := os.WriteFile(Old(p)+".pub", ssh.MarshalAuthorizedKey(b.PublicKey()), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := RollbackRotation(p, nil); err != nil {
			t.Fatal(err)
		}
		if exists(Old(p) + ".pub") {
			t.Error("the stale file is left")
		}
		consistent(t, p, a)
		consistent(t, Next(p), b)
	})
}

func TestRotationRefusals(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, DefaultFile)
	if _, err := FinishRotation(p, nil); err == nil {
		t.Error("FinishRotation() without keys succeeded")
	}
	if _, _, err := StartRotation(p, "", nil); err == nil {
		t.Error("StartRotation() without P succeeded")
	}
	if _, err := RollbackRotation(p, nil); err == nil || !strings.Contains(err.Error(), "no previous key") {
		t.Errorf("RollbackRotation() without P.old = %v", err)
	}
	if _, err := Generate(p); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StartRotation(p, "dsa", nil); err == nil {
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
