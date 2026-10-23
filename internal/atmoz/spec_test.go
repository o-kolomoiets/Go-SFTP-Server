// SPDX-License-Identifier: Apache-2.0

package atmoz

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
)

// secret is the password of the test specs: no message may contain it.
const secret = "SECRET"

// bcryptHash returns a bcrypt hash of password with cost.
func bcryptHash(tb testing.TB, password string, cost int) string {
	tb.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		tb.Fatal(err)
	}
	return string(h)
}

func TestLooksLikeSpec(t *testing.T) {
	t.Parallel()
	for arg, want := range map[string]bool{
		"foo:pass:::upload": true,
		"foo:":              true,
		"Foo:x":             true,
		"-x:pass":           true, // atmoz's test; the user name is refused later
		"foo":               false,
		":pass":             false,
		" foo:pass":         false,
		"foo bar:pass":      false,
		"\tfoo:pass":        false,
		"serve":             false,
		"":                  false,
	} {
		if got := LooksLikeSpec(arg); got != want {
			t.Errorf("LooksLikeSpec(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestSourceString(t *testing.T) {
	t.Parallel()
	for src, want := range map[Source]string{
		{Kind: Arg, Pos: 2}: "argument 2",
		{Kind: Env, Pos: 3}: "SFTP_USERS entry 3",
		{Kind: File, Path: "/etc/sftp/users.conf", Pos: 4}: "/etc/sftp/users.conf line 4",
	} {
		if got := src.String(); got != want {
			t.Errorf("%+v: %q, want %q", src, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	argon, err := auth.HashPassword([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	bc := bcryptHash(t, secret, 10)
	arg := Source{Kind: Arg, Pos: 1}
	for _, tc := range []struct {
		raw  string
		want Spec
	}{
		// The atmoz README's examples.
		{"foo:" + secret + ":::upload", Spec{User: "foo", Password: secret, Dirs: []string{"upload"}}},
		{"foo:" + secret + ":1001", Spec{User: "foo", Password: secret, IDs: true}},
		{"foo:123:1001:100", Spec{User: "foo", Password: "123", IDs: true}},
		{"foo::1001", Spec{User: "foo", IDs: true}},
		// :e with the hashes gosftpd verifies.
		{"foo:" + bc + ":e:1001", Spec{User: "foo", Hash: bc, IDs: true}},
		{"foo:" + argon + ":e", Spec{User: "foo", Hash: argon}},
		{"foo:" + bc + ":e:::a,b", Spec{User: "foo", Hash: bc, Dirs: []string{"a", "b"}}},
		// :e without a hash is no password, as atmoz disables it.
		{"foo::e:::up", Spec{User: "foo", Dirs: []string{"up"}}},
		// Split as bash's read -ra: a final empty field is dropped.
		{"foo:" + secret + ":", Spec{User: "foo", Password: secret}},
		{"foo", Spec{User: "foo"}},
		{"foo:" + secret + ":::a,,b,", Spec{User: "foo", Password: secret, Dirs: []string{"a", "b"}}},
		{"foo:" + secret + ":::up,up", Spec{User: "foo", Password: secret, Dirs: []string{"up"}}},
		{"foo:" + secret + ":::my files", Spec{User: "foo", Password: secret, Dirs: []string{"my files"}}},
		{"a.b-c_d:" + secret, Spec{User: "a.b-c_d", Password: secret}},
		{"foo:" + strings.Repeat("x", 255), Spec{User: "foo", Password: strings.Repeat("x", 255)}},
		{"foo:" + strings.Repeat("é", 255), Spec{User: "foo", Password: strings.Repeat("é", 255)}},
	} {
		got, err := Parse(tc.raw, arg)
		tc.want.Source = arg
		if err != nil || !equal(got, tc.want) {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", tc.raw, got, err, tc.want)
		}
	}
}

func equal(a, b Spec) bool {
	return a.Source == b.Source && a.User == b.User && a.Password == b.Password && a.Hash == b.Hash && a.IDs == b.IDs && slices.Equal(a.Dirs, b.Dirs)
}

// TestParseErrors: every error names the source, the user once it is
// valid, and the field, and never the password or the raw spec.
func TestParseErrors(t *testing.T) {
	t.Parallel()
	src := Source{Kind: Env, Pos: 3}
	for _, tc := range []struct{ raw, want string }{
		{"Foo:" + secret, "SFTP_USERS entry 3: the user name is not one gosftpd accepts"},
		{".foo:" + secret, "SFTP_USERS entry 3: the user name is not one gosftpd accepts"},
		{"_foo:" + secret, "SFTP_USERS entry 3: the user name is not one gosftpd accepts"},
		{":" + secret, "SFTP_USERS entry 3: the user name is not one gosftpd accepts"},
		{strings.Repeat("a", 33) + ":" + secret, "SFTP_USERS entry 3: the user name is not one gosftpd accepts"},
		{"foo:" + secret + "\nbar:x", "SFTP_USERS entry 3: contains a line break"},
		{"foo:" + secret + "\r", "SFTP_USERS entry 3: contains a line break"},
		{"foo:" + strings.Repeat("x", 256), "SFTP_USERS entry 3 (user foo): the password is longer than 255 characters"},
		{"foo:" + secret + ":x" + secret, "SFTP_USERS entry 3 (user foo): the uid is not a number"},
		{"foo:" + secret + ":1:-1", "SFTP_USERS entry 3 (user foo): the gid is not a number"},
		{"foo:" + secret + "::::a:b", "SFTP_USERS entry 3 (user foo): too many fields"},
		{"foo:" + secret + ":e:1:2:a:b", "SFTP_USERS entry 3 (user foo): too many fields"},
		{"foo:" + secret + ":::a/b", `SFTP_USERS entry 3 (user foo): directory "a/b": nested directories are not supported`},
		{"foo:" + secret + ":::.ssh", "SFTP_USERS entry 3 (user foo): directory .ssh holds the user's keys"},
		{"foo:" + secret + ":::_data", `SFTP_USERS entry 3 (user foo): directory "_data" is not a valid name`},
		{"foo:" + secret + ":::NUL", `SFTP_USERS entry 3 (user foo): directory "NUL" is not a valid name`},
		{"foo:" + secret + ":::up,Up", `SFTP_USERS entry 3 (user foo): directories "up" and "Up" differ only in case`},
		// The atmoz README's MD5-crypt hash and the other crypt(3) hashes.
		{"foo:$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9.:e:1001", "SFTP_USERS entry 3 (user foo): the password hash (:e) cannot be used: it is an MD5-crypt hash, which gosftpd does not verify (it verifies argon2id and bcrypt); create a hash with 'gosftpd user hash-password'"},
		{"foo:$5$" + secret + ":e", "it is a SHA-crypt hash"},
		{"foo:$6$rounds=5000$" + secret + ":e", "it is a SHA-crypt hash"},
		{"foo:$y$j9T$" + secret + ":e", "it is a yescrypt hash"},
		{"foo:$7$" + secret + ":e", "it is a scrypt hash"},
		{"foo:" + secret + ":e", "not an argon2id or bcrypt hash; create one with 'gosftpd user hash-password'"},
		{"foo:$2b$04$" + strings.Repeat("a", 53) + ":e", "bcrypt cost 4 is outside 10..14"},
		{"foo:$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$" + secret + ":e", "only argon2id is supported"},
	} {
		_, err := Parse(tc.raw, src)
		var se *Error
		if !errors.As(err, &se) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %v, want an *Error with %q", tc.raw, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), tc.raw) {
			t.Errorf("Parse(%q): the error shows the password or the spec: %v", tc.raw, err)
		}
	}
	// The hash itself is never shown either.
	md5 := "$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9."
	if _, err := Parse("foo:"+md5+":e", src); err == nil || strings.Contains(err.Error(), md5) {
		t.Errorf("error %v", err)
	}
}

func TestSpecWarnings(t *testing.T) {
	t.Parallel()
	home := filepath.FromSlash("/home")
	keys := filepath.Join(home, "foo", ".ssh", "keys") + string(filepath.Separator)
	plain := "the password is in plain text, which anyone who can run docker inspect or read the process's command line or environment can see; give an argon2id hash with ':e' ('gosftpd user hash-password') or log in with keys from " + keys
	for _, tc := range []struct {
		raw  string
		src  Source
		want []string
	}{
		{"foo:" + secret + ":::up", Source{Kind: Arg, Pos: 2}, []string{"argument 2 (user foo): " + plain}},
		{"foo:" + secret, Source{Kind: Env, Pos: 1}, []string{"SFTP_USERS entry 1 (user foo): " + plain}},
		{"foo:" + secret, Source{Kind: File, Path: "users.conf", Pos: 4}, nil},
		{"foo::1001", Source{Kind: Arg, Pos: 1}, nil},
		{"foo:" + bcryptHash(t, secret, 10) + ":e", Source{Kind: Arg, Pos: 1}, nil},
		{"foo:$2b$10$" + secret, Source{Kind: File, Path: "users.conf", Pos: 1}, []string{"users.conf line 1 (user foo): the password looks like a hash, but without ':e' after it the hash itself is the password; add ':e'"}},
	} {
		s, err := Parse(tc.raw, tc.src)
		if err != nil {
			t.Fatal(err)
		}
		got := s.Warnings(home)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q from %s: warnings %q, want %q", tc.raw, tc.src, got, tc.want)
		}
		for _, w := range got {
			if strings.Contains(w, secret) {
				t.Errorf("warning shows the password: %s", w)
			}
		}
	}
}
