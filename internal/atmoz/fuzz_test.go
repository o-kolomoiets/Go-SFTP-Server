// SPDX-License-Identifier: Apache-2.0

package atmoz

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// FuzzAtmozSpec checks that no error or warning shows a password (ADR
// 0012). It takes a user and the rest of a spec as separate inputs and
// puts a sentinel password between them, "PW" and 24 hex digits of the
// inputs' SHA-256, which no fixed text contains; an input that contains it
// is skipped, and so is a user with ':', which would move the sentinel out
// of the password field. The spec is read as an argument, an SFTP_USERS
// entry and a users file line, alone and given twice. A third input, a
// raw spec, is only checked not to panic.
func FuzzAtmozSpec(f *testing.F) {
	for _, seed := range []struct{ user, rest, raw string }{
		{"foo", ":::upload", "foo:pass:::upload"},
		{"foo", ":1001", "foo:pass:1001"},
		{"foo", ":1001:100", "foo:123:1001:100"},
		{"foo", ":e:1001", "foo:$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9.:e:1001"},
		{"foo", ":e", "foo:$2b$10$" + strings.Repeat("a", 53) + ":e"},
		{"foo", "::::a,b,,c", "foo::1001"},
		{"foo", ":::a/b", "foo:pass:::.ssh,_data,NUL,Up,up"},
		{"Foo", "", " foo:pass"},
		{"", "x", ":"},
		{"foo", ":x:y:z:a:b", "foo:pass:e:1:2:a:b"},
		{"foo", "\n", "foo:pa\rss"},
		{"foo bar", " baz", "foo\tbar:x"},
	} {
		f.Add(seed.user, seed.rest, seed.raw)
	}
	sources := []Source{{Kind: Arg, Pos: 1}, {Kind: Env, Pos: 1}, {Kind: File, Path: "/etc/sftp/users.conf", Pos: 1}}
	f.Fuzz(func(t *testing.T, user, rest, raw string) {
		for _, src := range sources {
			if s, err := Parse(raw, src); err == nil {
				_ = s.Warnings(Home)
			}
		}
		_, _, _ = collect(append(append(fileInputs("users.conf", []byte(raw)), argInputs([]string{raw})...), envInputs(raw)...), Home)

		sum := sha256.Sum256([]byte(user + "\x00" + rest))
		sentinel := "PW" + hex.EncodeToString(sum[:])[:24]
		if strings.Contains(user, ":") || strings.Contains(user+rest, sentinel) {
			t.Skip()
		}
		spec := user + ":" + sentinel + rest
		check := func(what, msg string) {
			if strings.Contains(msg, sentinel) {
				t.Fatalf("%s shows the password: %s", what, msg)
			}
		}
		for _, src := range sources {
			s, err := Parse(spec, src)
			if err != nil {
				check("error", err.Error())
				continue
			}
			for _, w := range s.Warnings(Home) {
				check("warning", w)
			}
		}
		for _, inputs := range [][]input{
			fileInputs("users.conf", []byte(spec+"\n"+spec)),
			argInputs([]string{spec, spec}),
			envInputs(spec + " " + spec),
		} {
			_, warns, err := collect(inputs, Home)
			if err != nil {
				check("error", err.Error())
			}
			for _, w := range warns {
				check("warning", w)
			}
		}
	})
}
