// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
)

type connMeta struct {
	ssh.ConnMetadata
	user string
}

func (c connMeta) User() string         { return c.user }
func (c connMeta) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1} }

func newCA(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func certOf(t *testing.T, ca ssh.Signer, key ssh.PublicKey, principals ...string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key: key, CertType: ssh.UserCert, ValidPrincipals: principals,
		ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: ssh.CertTimeInfinity,
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func authorized(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// login names the result of offering key as user: "ok", "denied" or the
// reason.
func login(a *auth.Authenticator, user string, key ssh.PublicKey) string {
	_, err := a.KnownKey(connMeta{user: user}, key)
	if err == nil {
		return "ok"
	}
	if re, ok := errors.AsType[*auth.RefusedError](err); ok {
		return re.Reason
	}
	return "denied"
}

func TestCertificateConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ca, revokedCA, key, gone := newCA(t), newCA(t), newCA(t).PublicKey(), newCA(t).PublicKey()
	cas := filepath.Join(dir, "cas.pub")
	revoked := filepath.Join(dir, "revoked")
	write := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(cas, authorized(ca.PublicKey())+" corp\ncert-authority "+authorized(revokedCA.PublicKey())+"\n", 0o600)
	write(revoked, "# revoked\n"+authorized(certOf(t, ca, gone, "alice"))+"\n", 0o600)
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["/k"]
[auth]
trusted_user_ca_keys = ["`+authorized(revokedCA.PublicKey())+`"]
trusted_user_ca_keys_file = "cas.pub"
revoked_keys = ["`+authorized(revokedCA.PublicKey())+`"]
revoked_keys_file = "revoked"
[mounts.m]
path = "{dir}/m"
[users.alice]
access = { m = "read" }
[users.bob]
principals = ["bob@corp"]
access = { m = "read" }
[users.carol]
principals = []
authorized_keys = ["cert-authority `+authorized(ca.PublicKey())+`"]
access = { m = "read" }
[users.dave]
authorized_keys = ["cert-authority `+authorized(ca.PublicKey())+`"]
access = { m = "read" }
[users.erin]
principals = []
authorized_keys = ["cert-authority `+authorized(revokedCA.PublicKey())+`"]
access = { m = "read" }
[users.frank]
authorized_keys = ["`+authorized(gone)+`"]
access = { m = "read" }
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth.TrustedUserCAKeysFile != cas || c.Auth.RevokedKeysFile != revoked {
		t.Errorf("paths not relative to the configuration: %q, %q", c.Auth.TrustedUserCAKeysFile, c.Auth.RevokedKeysFile)
	}
	warns := mustValidate(t, c)
	if slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "cannot log in") }) {
		t.Errorf("a user that can log in with a certificate is warned about: %q", warns)
	}
	if !c.CanLogIn("alice") || !c.CanLogIn("carol") {
		t.Error("CanLogIn")
	}
	if got := c.CertificatePrincipals("bob"); !slices.Equal(got, []string{"bob@corp"}) {
		t.Errorf("principals of bob = %q", got)
	}
	if got := c.CertificatePrincipals("carol"); got != nil {
		t.Errorf("principals of carol = %q, want none", got)
	}

	a, _, warns, err := c.BuildAuthenticator(AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cas.pub:2: a CA key line takes no options",
		"auth.trusted_user_ca_keys: CA SHA256:",
		"users.dave: users.dave.authorized_keys[1]:1: this CA is also in auth.trusted_user_ca_keys",
		"users.erin: users.erin.authorized_keys[1]:1: the CA is revoked",
		"users.frank: users.frank.authorized_keys[1]:1: the key is revoked",
	} {
		if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("no warning %q in %q", want, warns)
		}
	}
	if slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "users.carol") }) {
		t.Errorf("carol, kept away from the trusted CAs, is warned about: %q", warns)
	}
	for _, tt := range []struct {
		user string
		key  ssh.PublicKey
		want string
	}{
		{"alice", certOf(t, ca, key, "alice"), "ok"},
		{"bob", certOf(t, ca, key, "bob@corp"), "ok"},
		{"bob", certOf(t, ca, key, "bob"), auth.ReasonCertPrincipal},
		{"carol", certOf(t, ca, key, "carol"), "ok"}, // through her cert-authority line
		{"alice", certOf(t, ca, gone, "alice"), auth.ReasonKeyRevoked},
		{"alice", certOf(t, revokedCA, key, "alice"), auth.ReasonKeyRevoked},
	} {
		if got := login(a, tt.user, tt.key); got != tt.want {
			t.Errorf("%s with %v: %s, want %s", tt.user, tt.key.(*ssh.Certificate).ValidPrincipals, got, tt.want)
		}
	}

	// The CA file: a deleted file trusts no CA on reload, and fails at
	// start.
	if err := os.Rename(cas, cas+".old"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.BuildAuthenticator(AuthOptions{}); err == nil {
		t.Error("a missing CA file is accepted at start")
	}
	a, _, warns, err = c.BuildAuthenticator(AuthOptions{Reload: true})
	if err != nil {
		t.Fatalf("reload without the CA file: %v", err)
	}
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "its CAs are not trusted") }) {
		t.Errorf("warnings = %q", warns)
	}
	if got := login(a, "alice", certOf(t, ca, key, "alice")); got != "denied" {
		t.Errorf("a CA of a deleted file still trusted: %s", got)
	}
	if err := os.Rename(cas+".old", cas); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		write(cas, authorized(ca.PublicKey())+"\n", 0o666)
		if _, _, _, err := c.BuildAuthenticator(AuthOptions{}); err == nil {
			t.Error("a CA file others can write accepted at start")
		}
		a, _, _, err := c.BuildAuthenticator(AuthOptions{Reload: true})
		if err != nil || login(a, "alice", certOf(t, ca, key, "alice")) != "denied" {
			t.Errorf("a CA file others can write trusted on reload: %v", err)
		}
		if _, err := c.CheckFS(); err == nil || !strings.Contains(err.Error(), "cas.pub") {
			t.Errorf("CheckFS of a writable CA file: %v", err)
		}
	}
	c.Auth.TrustedUserCAKeys = nil
	write(cas, "cert-authority "+authorized(ca.PublicKey())+"\n", 0o600)
	_, _, warns, err = c.BuildAuthenticator(AuthOptions{})
	if err == nil || !strings.Contains(err.Error(), "auth.trusted_user_ca_keys_file: "+cas+" has no usable CA keys") || !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "takes no options") }) {
		t.Errorf("a CA file without usable keys at start: %v, %q", err, warns)
	}
	if _, _, warns, err := c.BuildAuthenticator(AuthOptions{Reload: true}); err != nil || !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "no CA is trusted") }) {
		t.Errorf("a CA file without usable keys on reload: %v, %q", err, warns)
	}
	write(cas, authorized(ca.PublicKey())+"\n", 0o600)

	// The revocation list fails closed, also on reload.
	broken := map[string]string{
		"KRL":     "SSHKRL\n\x00\x00\x00\x00\x01",
		"garbage": authorized(gone) + "\nnot a key\n",
	}
	for name, data := range broken {
		write(revoked, data, 0o600)
		for _, reload := range []bool{false, true} {
			if _, _, _, err := c.BuildAuthenticator(AuthOptions{Reload: reload}); err == nil {
				t.Errorf("%s revocation list accepted (reload %v)", name, reload)
			}
		}
	}
	if err := os.Remove(revoked); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.BuildAuthenticator(AuthOptions{Reload: true}); err == nil {
		t.Error("a missing revocation list accepted on reload")
	}
	if runtime.GOOS != "windows" {
		write(revoked, authorized(gone)+"\n", 0o666)
		if _, _, _, err := c.BuildAuthenticator(AuthOptions{Reload: true}); err == nil {
			t.Error("a revocation list others can write accepted on reload")
		}
		if _, err := c.CheckFS(); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Errorf("CheckFS of a writable revocation list: %v", err)
		}
	}
}

func TestValidateCertificateKeys(t *testing.T) {
	t.Parallel()

	ca := authorized(newCA(t).PublicKey())
	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[auth]
methods = ["password"]
trusted_user_ca_keys = ["garbage", "from=\"10.0.0.0/8\" `+ca+`"]
revoked_keys = ["not a key"]
[mounts.m]
path = "{dir}/m"
[users.alice]
principals = ["", "alice"]
password_hash = "`+mustHash(t)+`"
access = { m = "read" }
`)
	warns, err := c.Validate()
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{
		"auth.trusted_user_ca_keys: entry 1:1: cannot parse key",
		"auth.trusted_user_ca_keys: entry 2:1: a CA key line takes no options",
		"auth.revoked_keys: entry 1:1: cannot parse key",
		"users.alice.principals: empty principal",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("errors lack %q:\n%v", want, err)
		}
	}
	if !slices.ContainsFunc(warns, func(w string) bool {
		return strings.Contains(w, "not used: auth.methods does not include \"publickey\"")
	}) {
		t.Errorf("warnings = %q", warns)
	}

	c, _ = load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
[users.alice]
principals = ["alice@corp"]
access = { m = "read" }
`)
	warns = mustValidate(t, c)
	for _, want := range []string{"users.alice.principals: not used", "users.alice: no usable authorized_keys"} {
		if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("no warning %q in %q", want, warns)
		}
	}
}

func mustHash(t *testing.T) string {
	t.Helper()
	h, err := auth.HashPassword([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The CA and revocation files are trusted files: not inside a mount
// clients can write.
func TestCertificateFilesOutsideMounts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rw"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"rw/cas.pub", "rw/revoked"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(authorized(newCA(t).PublicKey())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/host_key"]
host_key_auto_generate = true
[auth]
trusted_user_ca_keys_file = "rw/cas.pub"
revoked_keys_file = "rw/revoked"
[mounts.rw]
path = "{dir}/rw"
[users.alice]
access = { rw = "full" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	_, err = c.CheckFS()
	for _, want := range []string{"covers the trusted CA keys", "covers the revoked keys"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckFS: %v, want %q", err, want)
		}
	}
}

// In zero-config mode without --user, a cert-authority line without
// principals= is ignored with a warning.
func TestZeroConfigCertAuthority(t *testing.T) {
	t.Parallel()

	ca, key := newCA(t), newCA(t).PublicKey()
	keys := filepath.Join(t.TempDir(), "authorized_keys")
	data := "cert-authority " + authorized(ca.PublicKey()) + "\ncert-authority,principals=\"alice\" " + authorized(ca.PublicKey()) + "\n"
	if err := os.WriteFile(keys, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: keys}
	a, _, warns, err := zero.BuildAuthenticator(AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], ":1: cert-authority without principals= is ignored") {
		t.Errorf("warnings = %q", warns)
	}
	// The line without principals= would accept bob; the other one does
	// not list him.
	if got := login(a, "bob", certOf(t, ca, key, "bob")); got != auth.ReasonCertPrincipal {
		t.Errorf("bob: %s", got)
	}
	if got := login(a, "alice", certOf(t, ca, key, "alice")); got != "ok" {
		t.Errorf("alice: %s", got)
	}
}

// The certificate files are read only when publickey is enabled.
func TestCertificateFilesNeedPublickey(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[auth]
methods = ["password"]
trusted_user_ca_keys_file = "missing.pub"
revoked_keys_file = "missing"
[mounts.m]
path = "{dir}/m"
[users.alice]
password_hash = "`+mustHash(t)+`"
access = { m = "read" }
`)
	mustValidate(t, c)
	if _, _, _, err := c.BuildAuthenticator(AuthOptions{}); err != nil {
		t.Errorf("certificate files read without publickey: %v", err)
	}
}

func TestPrincipalsRoundTrip(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[auth]
trusted_user_ca_keys = ["`+authorized(newCA(t).PublicKey())+`"]
[mounts.m]
path = "{dir}/m"
[users.none]
principals = []
access = { m = "read" }
[users.unset]
access = { m = "read" }
[users.mapped]
principals = ["a@corp", "b"]
access = { m = "read" }
[users.comma]
principals = ["a,b"]
access = { m = "read" }
`)
	warns := mustValidate(t, c)
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "ssh-keygen -n cannot sign") }) {
		t.Errorf("no warning about a principal with a comma: %q", warns)
	}
	data, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(writeConfig(t, t.TempDir(), string(data)))
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	for _, name := range []string{"none", "unset", "mapped"} {
		if got, want := again.CertificatePrincipals(name), c.CertificatePrincipals(name); !slices.Equal(got, want) || (got == nil) != (want == nil) {
			t.Errorf("%s: principals %q after a round trip, want %q", name, got, want)
		}
	}
	if again.CertificatePrincipals("none") != nil || !slices.Equal(again.CertificatePrincipals("unset"), []string{"unset"}) {
		t.Error("principals = [] and unset are not kept apart")
	}
}

// Zero-config: a file with only principal-less cert-authority lines has no
// usable keys without --user; with --user the lines work.
func TestZeroConfigOnlyIgnoredLines(t *testing.T) {
	t.Parallel()

	ca, key := newCA(t), newCA(t).PublicKey()
	keys := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(keys, []byte("cert-authority "+authorized(ca.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: keys}
	if _, _, _, err := zero.BuildAuthenticator(AuthOptions{}); err == nil || !errors.Is(err, errNoKeys) {
		t.Errorf("start with only ignored lines: %v", err)
	}
	if _, _, warns, err := zero.BuildAuthenticator(AuthOptions{Reload: true}); err != nil || !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "nobody can log in") }) {
		t.Errorf("reload with only ignored lines: %v, %q", err, warns)
	}
	zero.AnyUser.Name = "alice"
	a, _, warns, err := zero.BuildAuthenticator(AuthOptions{})
	if err != nil || len(warns) != 0 {
		t.Fatalf("--user alice: %v, %q", err, warns)
	}
	if got := login(a, "alice", certOf(t, ca, key, "alice")); got != "ok" {
		t.Errorf("--user alice with a cert-authority line: %s", got)
	}
}
