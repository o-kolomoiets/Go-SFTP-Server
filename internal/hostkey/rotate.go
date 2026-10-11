// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// Rotation (ADR 0008). Next to a host key file P, P.next is the next key
// and P.old the previous one: both are announced to clients after login,
// and neither is used for key exchange. P-cert.pub is P's certificate.
//
// The steps decide by what the key files hold, never by which other files
// exist: the key files are linked and renamed so that P always exists, and
// SyncFiles then puts every public key file and certificate with its key.
// Each step can therefore be run again after an interruption.

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
func StartRotation(p, typ string, prepare func(string) error) (ssh.Signer, []string, error) {
	if exists(Next(p)) {
		return nil, nil, fmt.Errorf("%s exists: a rotation is in progress; finish it (rotate --finish) or abort it (rotate --abort)", Next(p))
	}
	if exists(Old(p)) {
		return nil, nil, fmt.Errorf("%s exists: retire the previous key first (rotate --retire)", Old(p))
	}
	cur, err := Load(p)
	if err != nil {
		return nil, nil, err
	}
	if typ == "" {
		if typ = TypeOf(cur.PublicKey()); typ == "" {
			return nil, nil, fmt.Errorf("%s is a %s key, which gosftpd does not generate; choose a type with --type", p, cur.PublicKey().Type())
		}
	}
	// Files left by an earlier next key would be taken for the new one's.
	changes, err := SyncFiles(p, prepare)
	if err != nil {
		return nil, changes, err
	}
	k, err := GenerateWith(Next(p), typ, prepare)
	return k, changes, err
}

// Finished describes a finished rotation.
type Finished struct {
	New, Old ssh.Signer
	// Age is how long P.next existed; zero when the rotation was finished
	// before (an interrupted finish).
	Age time.Duration
	// Certified reports whether the new key has a certificate.
	Certified bool
	// Changes lists the public key and certificate files that SyncFiles
	// changed.
	Changes []string
}

// FinishRotation makes P.next the host key: P.old becomes a link to P (a
// copy where the filesystem has no links), then P.next replaces P
// atomically, so that P always exists. Run again, it completes an
// interrupted finish.
func FinishRotation(p string, prepare func(string) error) (*Finished, error) {
	next, err := Load(Next(p))
	if errors.Is(err, fs.ErrNotExist) {
		if !exists(Old(p)) {
			return nil, fmt.Errorf("%s does not exist: start a rotation with rotate first", Next(p))
		}
		return finished(p, 0, prepare)
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
	fi, err := os.Stat(Next(p))
	if err != nil {
		return nil, err
	}
	age := time.Since(fi.ModTime())
	if err := keep(p, Old(p), cur, "retire it first (rotate --retire)", prepare); err != nil {
		return nil, err
	}
	if err := os.Rename(Next(p), p); err != nil {
		return nil, err
	}
	if err := SyncDir(filepath.Dir(p)); err != nil {
		return nil, err
	}
	return finished(p, age, prepare)
}

func finished(p string, age time.Duration, prepare func(string) error) (*Finished, error) {
	changes, err := SyncFiles(p, prepare)
	if err != nil {
		return nil, err
	}
	cur, err := Load(p)
	if err != nil {
		return nil, err
	}
	old, err := Load(Old(p))
	if err != nil {
		return nil, err
	}
	return &Finished{New: cur, Old: old, Age: age, Certified: certifies(Cert(p), cur.PublicKey()), Changes: changes}, nil
}

// RollbackRotation undoes FinishRotation: the new key becomes P.next again
// and P.old becomes P. Both stay announced, so clients keep both. Run
// again, it completes an interrupted rollback.
func RollbackRotation(p string, prepare func(string) error) ([]string, error) {
	old, err := Load(Old(p))
	if errors.Is(err, fs.ErrNotExist) {
		// Perhaps a rollback that stopped after its rename: bring the
		// files in line, and say that there is nothing left to undo.
		changes, serr := SyncFiles(p, prepare)
		if serr != nil {
			return changes, serr
		}
		return changes, fmt.Errorf("%s does not exist: there is no previous key to return to", Old(p))
	}
	if err != nil {
		return nil, err
	}
	cur, err := Load(p)
	if err != nil {
		return nil, err
	}
	if sameKey(cur, old) {
		return nil, fmt.Errorf("%s holds the same key as %s: a --finish was interrupted; run rotate --finish again", Old(p), p)
	}
	if err := keep(p, Next(p), cur, "abort that rotation first (rotate --abort)", prepare); err != nil {
		return nil, err
	}
	if err := os.Rename(Old(p), p); err != nil {
		return nil, err
	}
	if err := SyncDir(filepath.Dir(p)); err != nil {
		return nil, err
	}
	return SyncFiles(p, prepare)
}

// RetireRotation deletes P.old: after a reload the old key is no longer
// announced, and OpenSSH clients remove it.
func RetireRotation(p string, prepare func(string) error) ([]string, error) {
	if !exists(Old(p)) {
		changes, err := SyncFiles(p, prepare)
		if err != nil {
			return changes, err
		}
		return changes, fmt.Errorf("%s does not exist: there is no previous key to retire", Old(p))
	}
	if err := interrupted(p); err != nil {
		return nil, err
	}
	if err := removeAll(Old(p)); err != nil {
		return nil, err
	}
	return SyncFiles(p, prepare)
}

// AbortRotation deletes P.next.
func AbortRotation(p string, prepare func(string) error) ([]string, error) {
	if !exists(Next(p)) {
		changes, err := SyncFiles(p, prepare)
		if err != nil {
			return changes, err
		}
		return changes, fmt.Errorf("%s does not exist: no rotation is in progress", Next(p))
	}
	if err := interrupted(p); err != nil {
		return nil, err
	}
	if err := removeAll(Next(p)); err != nil {
		return nil, err
	}
	return SyncFiles(p, prepare)
}

// interrupted refuses to retire or abort while a finish or rollback is
// half done: P.next and P.old both exist, and one holds P's key.
func interrupted(p string) error {
	if !exists(Next(p)) || !exists(Old(p)) {
		return nil
	}
	cur, err := Load(p)
	if err != nil {
		return err
	}
	if k, err := Load(Old(p)); err == nil && sameKey(k, cur) {
		return fmt.Errorf("%s holds the key of %s: a --finish was interrupted; run rotate --finish again", Old(p), p)
	}
	if k, err := Load(Next(p)); err == nil && sameKey(k, cur) {
		return fmt.Errorf("%s holds the key of %s: a --rollback was interrupted; run rotate --rollback again", Next(p), p)
	}
	return nil
}

// keep makes dst a link to (or copy of) the key file p, which holds key,
// unless dst already holds that key: then an interrupted step made it.
// Another key at dst is refused with hint.
func keep(p, dst string, key ssh.Signer, hint string, prepare func(string) error) error {
	err := os.Link(p, dst)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrExist):
		if prev, lerr := Load(dst); lerr == nil && sameKey(prev, key) {
			return nil
		}
		return fmt.Errorf("%s exists and holds another key; %s", dst, hint)
	}
	data, rerr := readFile(p)
	if rerr != nil {
		return rerr
	}
	return writeNew(dst, data, 0o600, prepare)
}

// keyFile is P, P.next or P.old.
type keyFile struct {
	path    string
	present bool          // the key file exists
	key     ssh.PublicKey // nil when it is missing or cannot be read
}

// SyncFiles puts the public key and certificate files of P, P.next and
// P.old with their keys: each "<file>.pub" holds the public key of
// <file>, a certificate moves to the key file whose key it certifies, and
// the files of a key file that does not exist are removed. A key file that
// cannot be read, and a certificate file that cannot be parsed, are left
// alone. It returns what it changed.
func SyncFiles(p string, prepare func(string) error) ([]string, error) {
	files := []*keyFile{{path: p}, {path: Next(p)}, {path: Old(p)}}
	for _, f := range files {
		if !exists(f.path) {
			continue
		}
		f.present = true
		if k, err := Load(f.path); err == nil {
			f.key = k.PublicKey()
		}
	}
	var changes []string

	for _, f := range files {
		pub := f.path + ".pub"
		switch {
		case f.key != nil:
			if k, err := readPublic(pub); err != nil || !bytes.Equal(k.Marshal(), f.key.Marshal()) {
				if err := WritePublic(f.path, f.key, prepare); err != nil {
					return changes, err
				}
				changes = append(changes, "wrote "+pub)
			}
		case !f.present && exists(pub):
			if err := os.Remove(pub); err != nil {
				return changes, err
			}
			changes = append(changes, "removed "+pub+": "+f.path+" does not exist")
		}
	}

	// The certificates, read first, so that two can trade places.
	type certFile struct {
		f    *keyFile
		data []byte
		of   *keyFile // the key file whose key it certifies, if any
	}
	var certs []certFile
	for _, f := range files {
		data, err := readFile(Cert(f.path))
		if err != nil {
			continue
		}
		c, err := parseCert(data)
		if err != nil {
			continue // not a certificate: the server reports it
		}
		cf := certFile{f: f, data: data}
		for _, g := range files {
			if g.key != nil && bytes.Equal(c.Key.Marshal(), g.key.Marshal()) {
				cf.of = g
			}
		}
		certs = append(certs, cf)
	}
	want := map[*keyFile][]byte{}
	for _, c := range certs {
		if c.of == nil {
			continue
		}
		if _, ok := want[c.of]; !ok || c.f == c.of {
			want[c.of] = c.data // its own file first
		}
	}
	for _, f := range files {
		if f.present && f.key == nil {
			continue // cannot be read: leave its certificate alone
		}
		var cur []byte
		parsed := false
		for _, c := range certs {
			if c.f == f {
				cur, parsed = c.data, true
			}
		}
		data, ok := want[f]
		switch {
		case ok && !bytes.Equal(cur, data):
			tmp, err := writeTemp(Cert(f.path), data, 0o644, prepare)
			if err != nil {
				return changes, err
			}
			if err := os.Rename(tmp, Cert(f.path)); err != nil {
				_ = os.Remove(tmp)
				return changes, err
			}
			changes = append(changes, "moved the certificate of "+f.path+" to "+Cert(f.path))
		case !ok && parsed:
			if err := os.Remove(Cert(f.path)); err != nil {
				return changes, err
			}
			changes = append(changes, "removed "+Cert(f.path)+": it certifies no key of "+p)
		}
	}
	return changes, SyncDir(filepath.Dir(p))
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
