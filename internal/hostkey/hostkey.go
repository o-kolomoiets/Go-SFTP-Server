// SPDX-License-Identifier: Apache-2.0

// Package hostkey creates, loads and describes SSH host keys.
package hostkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// DefaultFile is the name of the generated host key inside the state directory.
const DefaultFile = "ssh_host_ed25519_key"

// Load reads a private host key. Like sshd, it refuses key files that are
// readable or writable by group or others (on Unix). RSA keys are restricted
// to SHA-2 signatures.
func Load(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("host key %s: permissions %#o are too open, use 0600", path, fi.Mode().Perm())
	}
	data, err := readAll(f, fi.Size())
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("host key %s: %w", path, err)
	}
	return restrictRSA(signer)
}

// Key types for GenerateType.
const (
	TypeED25519 = "ed25519"
	TypeECDSA   = "ecdsa" // P-256
	TypeRSA     = "rsa"   // 3072 bits
)

// rsaBits is the size of generated RSA host keys.
const rsaBits = 3072

// Generate creates a new ed25519 host key at path; see GenerateType.
func Generate(path string) (ssh.Signer, error) { return GenerateType(path, TypeED25519) }

// GenerateType creates a new host key of type typ at path with mode 0600,
// plus a "<path>.pub" public key, and returns the signer. It never
// overwrites an existing key file.
func GenerateType(path, typ string) (ssh.Signer, error) { return GenerateWith(path, typ, nil) }

// GenerateWith is GenerateType; prepare, if not nil, is called with each
// new file before it is moved into place, to set its owner. The key is
// written to a temporary file and linked into place, so that no one reads
// half a key.
func GenerateWith(path, typ string, prepare func(string) error) (ssh.Signer, error) {
	var (
		priv crypto.Signer
		err  error
	)
	switch typ {
	case TypeED25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case TypeECDSA:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case TypeRSA:
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	default:
		return nil, fmt.Errorf("unknown key type %q (want ed25519, ecdsa or rsa)", typ)
	}
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "gosftpd host key")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writePEM(&buf, block); err != nil {
		return nil, err
	}
	if err := writeNew(path, buf.Bytes(), 0o600, prepare); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	if err := WritePublic(path, signer.PublicKey(), prepare); err != nil {
		return nil, err
	}
	return restrictRSA(signer)
}

// WritePublic writes "<path>.pub" for key, replacing the file.
func WritePublic(path string, key ssh.PublicKey, prepare func(string) error) error {
	tmp, err := writeTemp(path+".pub", ssh.MarshalAuthorizedKey(key), 0o644, prepare)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path+".pub"); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// writeNew creates path with data, failing if it exists. It never follows
// a planted symlink: the data goes to a new temporary file, which is then
// linked to path.
func writeNew(path string, data []byte, mode os.FileMode, prepare func(string) error) error {
	tmp, err := writeTemp(path, data, mode, prepare)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return err
		}
		// A filesystem without hard links: check, then rename.
		if _, serr := os.Lstat(path); serr == nil {
			return &fs.PathError{Op: "create", Path: path, Err: fs.ErrExist}
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return SyncDir(filepath.Dir(path))
}

// writeTemp writes data to a new temporary file next to path and returns
// its name.
func writeTemp(path string, data []byte, mode os.FileMode, prepare func(string) error) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && prepare != nil {
		err = prepare(tmp)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// LoadOrGenerate loads the key at path, generating it first if it does not
// exist (nor its next or previous key). generated reports whether a new key
// was created.
func LoadOrGenerate(path string) (signer ssh.Signer, generated bool, err error) {
	signer, err = Load(path)
	if err == nil {
		return signer, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	// A missing key next to a next or previous key is a mistake, not a
	// first start: a new random key would change the server's identity.
	for _, f := range []string{Next(path), Old(path)} {
		if exists(f) {
			return nil, false, fmt.Errorf("%s does not exist, but %s does; a host key is generated only when neither exists", path, f)
		}
	}
	signer, err = Generate(path)
	return signer, err == nil, err
}

// Fingerprint returns the SHA256 fingerprint as printed by ssh-keygen -l.
func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// KnownHostsLine returns the line a client adds to ~/.ssh/known_hosts for
// this key served at host:port.
func KnownHostsLine(host string, port int, key ssh.PublicKey) string {
	// JoinHostPort brackets an IPv6 address, so that Normalize can split it.
	return knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))}, key)
}

// restrictRSA makes RSA host keys sign with SHA-2 only (never ssh-rsa/SHA-1).
func restrictRSA(signer ssh.Signer) (ssh.Signer, error) {
	if signer.PublicKey().Type() != ssh.KeyAlgoRSA {
		return signer, nil
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("RSA host key does not support SHA-2 signatures")
	}
	return ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
}
