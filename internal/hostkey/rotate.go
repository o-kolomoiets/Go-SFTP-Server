// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// Rotation (ADR 0008). Next to a host key file P, P.next is the next key
// and P.old the previous one: both are announced to clients after login,
// and neither is used for key exchange. P-cert.pub is P's certificate.

// Next returns the name of P's next key.
func Next(p string) string { return p + ".next" }

// Old returns the name of P's previous key.
func Old(p string) string { return p + ".old" }

// Cert returns the name of the certificate of key file p, as ssh-keygen -s
// writes it for p.pub.
func Cert(p string) string { return p + "-cert.pub" }

// TypeOf returns the GenerateType type of key, or "" for a key type
// gosftpd does not generate.
func TypeOf(key ssh.PublicKey) string {
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		return TypeED25519
	case ssh.KeyAlgoECDSA256:
		return TypeECDSA
	case ssh.KeyAlgoRSA:
		return TypeRSA
	}
	return ""
}

// StartRotation creates P.next of type typ, or of P's type when typ is
// empty, with P.next.pub. It refuses while P.next or P.old exists.
func StartRotation(p, typ string, prepare func(string) error) (ssh.Signer, error) {
	if exists(Next(p)) {
		return nil, fmt.Errorf("%s exists: a rotation is in progress; finish it (rotate --finish) or abort it (rotate --abort)", Next(p))
	}
	if exists(Old(p)) {
		return nil, fmt.Errorf("%s exists: retire the previous key first (rotate --retire)", Old(p))
	}
	cur, err := Load(p)
	if err != nil {
		return nil, err
	}
	if typ == "" {
		if typ = TypeOf(cur.PublicKey()); typ == "" {
			return nil, fmt.Errorf("%s is a %s key, which gosftpd does not generate; choose a type with --type", p, cur.PublicKey().Type())
		}
	}
	// Files of an earlier next key that is gone: its certificate would
	// otherwise be taken for the new key's.
	if err := removeAll(Next(p)+".pub", Cert(Next(p))); err != nil {
		return nil, err
	}
	return GenerateWith(Next(p), typ, prepare)
}

// Finished describes a finished rotation.
type Finished struct {
	New, Old ssh.Signer
	// Age is how long P.next existed; zero when the rotation was finished
	// before and only its certificates and public key files were completed.
	Age time.Duration
	// Certified reports whether the new key has a certificate.
	Certified bool
}

// FinishRotation makes P.next the host key: P.old becomes a link to P (a
// copy where the filesystem has no links), then P.next replaces P
// atomically, so that P always exists. Certificates and public key files
// follow their keys. Run again, it completes an interrupted finish.
func FinishRotation(p string, prepare func(string) error) (*Finished, error) {
	next, err := Load(Next(p))
	if errors.Is(err, fs.ErrNotExist) {
		if !exists(Old(p)) {
			return nil, fmt.Errorf("%s does not exist: start a rotation with rotate first", Next(p))
		}
		return completeFinish(p, prepare)
	}
	if err != nil {
		return nil, err
	}
	cur, err := Load(p)
	if err != nil {
		return nil, err
	}
	if sameKey(cur, next) {
		return nil, fmt.Errorf("%s holds the same key as %s", Next(p), p)
	}
	if err := checkCert(Next(p), next); err != nil {
		return nil, err
	}
	fi, err := os.Stat(Next(p))
	if err != nil {
		return nil, err
	}
	age := time.Since(fi.ModTime())
	if err := keep(p, Old(p), cur, prepare); err != nil {
		return nil, err
	}
	if err := os.Rename(Next(p), p); err != nil {
		return nil, err
	}
	if err := SyncDir(filepath.Dir(p)); err != nil {
		return nil, err
	}
	f, err := completeFinish(p, prepare)
	if err != nil {
		return nil, err
	}
	f.Age = age
	return f, nil
}

// completeFinish moves the certificates and rewrites the public key files
// after P.next replaced P.
func completeFinish(p string, prepare func(string) error) (*Finished, error) {
	cur, err := Load(p)
	if err != nil {
		return nil, err
	}
	old, err := Load(Old(p))
	if err != nil {
		return nil, err
	}
	certified, err := moveCerts(p, Next(p), Old(p), cur.PublicKey(), old.PublicKey(), prepare)
	if err != nil {
		return nil, err
	}
	if err := writePublic(prepare, p, cur, Old(p), old); err != nil {
		return nil, err
	}
	if err := removeAll(Next(p) + ".pub"); err != nil {
		return nil, err
	}
	return &Finished{New: cur, Old: old, Certified: certified}, nil
}

// RollbackRotation undoes FinishRotation: the new key becomes P.next again
// and P.old becomes P. Both stay announced, so clients keep both. Run
// again, it completes an interrupted rollback; completed reports that.
func RollbackRotation(p string, prepare func(string) error) (completed bool, err error) {
	old, err := Load(Old(p))
	if errors.Is(err, fs.ErrNotExist) {
		if interruptedRollback(p) {
			return true, completeRollback(p, prepare)
		}
		return false, fmt.Errorf("%s does not exist: there is no previous key to return to", Old(p))
	}
	if err != nil {
		return false, err
	}
	cur, err := Load(p)
	if err != nil {
		return false, err
	}
	if next, err := Load(Next(p)); err == nil && !sameKey(next, cur) || err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("%s exists: abort that rotation first (rotate --abort)", Next(p))
	}
	if err := checkCert(Old(p), old); err != nil {
		return false, err
	}
	if err := keep(p, Next(p), cur, prepare); err != nil {
		return false, err
	}
	if err := os.Rename(Old(p), p); err != nil {
		return false, err
	}
	if err := SyncDir(filepath.Dir(p)); err != nil {
		return false, err
	}
	return false, completeRollback(p, prepare)
}

// interruptedRollback reports whether a rollback stopped after P.old
// replaced P: P.next exists, and P.old's files, or P's that describe
// P.next, are left.
func interruptedRollback(p string) bool {
	next, err := Load(Next(p))
	if err != nil {
		return false
	}
	cur, err := Load(p)
	if err != nil {
		return false
	}
	pub, err := readPublic(p + ".pub")
	return exists(Old(p)+".pub") || exists(Cert(Old(p))) || certifies(Cert(p), next.PublicKey()) ||
		err == nil && !bytes.Equal(pub.Marshal(), cur.PublicKey().Marshal())
}

// completeRollback moves the certificates and rewrites the public key
// files after P.old replaced P.
func completeRollback(p string, prepare func(string) error) error {
	cur, err := Load(p)
	if err != nil {
		return err
	}
	next, err := Load(Next(p))
	if err != nil {
		return err
	}
	if _, err := moveCerts(p, Old(p), Next(p), cur.PublicKey(), next.PublicKey(), prepare); err != nil {
		return err
	}
	if err := writePublic(prepare, p, cur, Next(p), next); err != nil {
		return err
	}
	return removeAll(Old(p) + ".pub")
}

// RetireRotation deletes P.old and its files: after a reload the old key
// is no longer announced, and OpenSSH clients remove it. It first
// completes an interrupted finish, whose files P.old is needed for.
func RetireRotation(p string, prepare func(string) error) error {
	files := []string{Old(p) + ".pub", Cert(Old(p)), Old(p)}
	switch {
	case exists(Old(p)) && exists(Next(p)):
		return fmt.Errorf("both %s and %s exist: a --finish or --rollback was interrupted; run it again first", Next(p), Old(p))
	case exists(Old(p)):
		// An unreadable P.old is retired all the same.
		if _, err := Load(Old(p)); err == nil {
			if _, err := completeFinish(p, prepare); err != nil {
				return err
			}
		}
	case !anyExists(files...):
		return fmt.Errorf("%s does not exist: there is no previous key to retire", Old(p))
	}
	return removeAll(files...)
}

// AbortRotation deletes P.next and its files, the key last, so that an
// interrupted abort can be run again.
func AbortRotation(p string) error {
	files := []string{Next(p) + ".pub", Cert(Next(p)), Next(p)}
	if exists(Next(p)) && exists(Old(p)) {
		return fmt.Errorf("both %s and %s exist: a --finish or --rollback was interrupted; run it again first", Next(p), Old(p))
	}
	if !anyExists(files...) {
		return fmt.Errorf("%s does not exist: no rotation is in progress", Next(p))
	}
	return removeAll(files...)
}

// checkCert checks the certificate of key file f, which holds key, if it
// has one: a certificate the server would refuse must not move to P.
func checkCert(f string, key ssh.Signer) error {
	if !exists(Cert(f)) {
		return nil
	}
	if _, err := LoadCertificate(Cert(f), key.PublicKey()); err != nil {
		return fmt.Errorf("host certificate %w; fix or remove it first", err)
	}
	return nil
}

// keep makes dst a link to (or copy of) the key file p, which holds key,
// unless dst already holds that key: then an interrupted step made it.
func keep(p, dst string, key ssh.Signer, prepare func(string) error) error {
	err := os.Link(p, dst)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		if prev, lerr := Load(dst); lerr == nil && sameKey(prev, key) {
			return nil
		}
		return fmt.Errorf("%s exists and holds another key; retire it first (rotate --retire)", dst)
	}
	data, rerr := readFile(p)
	if rerr != nil {
		return rerr
	}
	return writeNew(dst, data, 0o600, prepare)
}

// moveCerts moves the certificates after p's key changed from prev (now in
// file to) to key (from file from): from's certificate replaces p's, which
// is kept as to's if it certifies prev. It reports whether p has a
// certificate afterwards.
func moveCerts(p, from, to string, key, prev ssh.PublicKey, prepare func(string) error) (bool, error) {
	if certifies(Cert(p), prev) && !exists(Cert(to)) {
		if err := keepFile(Cert(p), Cert(to), prepare); err != nil {
			return false, err
		}
	}
	// A certificate is moved to P only if it certifies P's new key.
	if certifies(Cert(from), key) {
		if err := os.Rename(Cert(from), Cert(p)); err != nil {
			return false, err
		}
	}
	if err := removeAll(Cert(from)); err != nil {
		return false, err
	}
	if exists(Cert(p)) && !certifies(Cert(p), key) {
		if err := os.Remove(Cert(p)); err != nil {
			return false, err
		}
	}
	return certifies(Cert(p), key), SyncDir(filepath.Dir(p))
}

// keepFile makes dst a link to, or a copy of, src.
func keepFile(src, dst string, prepare func(string) error) error {
	err := os.Link(src, dst)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return err
	}
	data, err := readFile(src)
	if err != nil {
		return err
	}
	return writeNew(dst, data, 0o644, prepare)
}

// writePublic rewrites the public key files of two key files.
func writePublic(prepare func(string) error, p string, key ssh.Signer, q string, qkey ssh.Signer) error {
	if err := WritePublic(p, key.PublicKey(), prepare); err != nil {
		return err
	}
	return WritePublic(q, qkey.PublicKey(), prepare)
}

// certifies reports whether the certificate file path certifies key.
func certifies(path string, key ssh.PublicKey) bool {
	data, err := readFile(path)
	if err != nil {
		return false
	}
	cert, err := parseCert(data)
	return err == nil && bytes.Equal(cert.Key.Marshal(), key.Marshal())
}

func removeAll(paths ...string) error {
	for _, f := range paths {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if len(paths) > 0 {
		return SyncDir(filepath.Dir(paths[0]))
	}
	return nil
}

func anyExists(paths ...string) bool { return slices.ContainsFunc(paths, exists) }

// readPublic reads a public key file.
func readPublic(path string) (ssh.PublicKey, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return key, err
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func sameKey(a, b ssh.Signer) bool {
	return bytes.Equal(a.PublicKey().Marshal(), b.PublicKey().Marshal())
}
