// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateAndLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", DefaultFile)
	gen, generated, err := LoadOrGenerate(path)
	if err != nil || !generated {
		t.Fatalf("LoadOrGenerate() = generated %v, err %v; want a new key", generated, err)
	}
	if gen.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %s, want ed25519", gen.PublicKey().Type())
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("key mode = %#o, want 0600", perm)
		}
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil || !strings.HasPrefix(string(pub), "ssh-ed25519 ") {
		t.Errorf("public key file = %q, %v", pub, err)
	}

	loaded, generated, err := LoadOrGenerate(path)
	if err != nil || generated {
		t.Fatalf("second LoadOrGenerate() = generated %v, err %v; want the existing key", generated, err)
	}
	if Fingerprint(loaded.PublicKey()) != Fingerprint(gen.PublicKey()) {
		t.Error("loaded key differs from the generated one")
	}
}

func TestGenerateNeverOverwrites(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultFile)
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(path); err == nil {
		t.Fatal("Generate() over an existing file succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep me" {
		t.Errorf("existing file was modified: %q", got)
	}
}

func TestLoadRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	t.Parallel()

	path := filepath.Join(t.TempDir(), DefaultFile)
	if _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "too open") {
		t.Errorf("Load() error = %v, want a permissions error", err)
	}
}

func TestLoadRSAUsesSHA2(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rsa_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	mas, ok := signer.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("RSA signer is %T, want a MultiAlgorithmSigner", signer)
	}
	for _, algo := range mas.Algorithms() {
		if algo == ssh.KeyAlgoRSA {
			t.Errorf("RSA host key still allows SHA-1 (%s)", algo)
		}
	}
}

func TestKnownHostsLine(t *testing.T) {
	t.Parallel()

	signer, err := Generate(filepath.Join(t.TempDir(), DefaultFile))
	if err != nil {
		t.Fatal(err)
	}
	line := KnownHostsLine("192.168.1.10", 2022, signer.PublicKey())
	if !strings.HasPrefix(line, "[192.168.1.10]:2022 ssh-ed25519 ") {
		t.Errorf("KnownHostsLine() = %q", line)
	}
	if line := KnownHostsLine("example.org", 22, signer.PublicKey()); !strings.HasPrefix(line, "example.org ssh-ed25519 ") {
		t.Errorf("KnownHostsLine() on port 22 = %q", line)
	}
}

func TestGenerateTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for typ, want := range map[string]string{
		TypeED25519: ssh.KeyAlgoED25519,
		TypeECDSA:   ssh.KeyAlgoECDSA256,
		TypeRSA:     ssh.KeyAlgoRSA,
	} {
		path := filepath.Join(dir, typ)
		s, err := GenerateType(path, typ)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if got := s.PublicKey().Type(); got != want {
			t.Errorf("%s: type %s, want %s", typ, got, want)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatalf("%s: Load: %v", typ, err)
		}
		if Fingerprint(loaded.PublicKey()) != Fingerprint(s.PublicKey()) {
			t.Errorf("%s: loaded key differs", typ)
		}
	}
	if _, err := GenerateType(filepath.Join(dir, "dsa"), "dsa"); err == nil {
		t.Error("dsa accepted")
	}
}

func TestKnownHostsLineIPv6(t *testing.T) {
	t.Parallel()

	s, err := Generate(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"2001:db8::1": "[2001:db8::1]:2022 ", "example.org": "[example.org]:2022 "} {
		if got := KnownHostsLine(host, 2022, s.PublicKey()); !strings.HasPrefix(got, want) {
			t.Errorf("KnownHostsLine(%s) = %q", host, got)
		}
	}
	if got := KnownHostsLine("::1", 22, s.PublicKey()); !strings.HasPrefix(got, "::1 ") {
		t.Errorf("port 22: %q", got)
	}
}
