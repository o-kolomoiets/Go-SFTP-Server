// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		in   string
		ok   bool
		want string
	}{
		{"s3cret\n", true, ""},
		{"s3cret\r\nignored second line\n", true, ""},
		{"no newline", true, ""},
		{"\n", false, "empty password"},
		{strings.Repeat("x", auth.MaxPasswordLen+1) + "\n", false, "longer than"},
	} {
		root := newRootCmd()
		var out, errOut bytes.Buffer
		root.SetArgs([]string{"user", "hash-password", "--stdin"})
		root.SetIn(strings.NewReader(tt.in))
		root.SetOut(&out)
		root.SetErr(&errOut)
		err := root.ExecuteContext(t.Context())
		if (err == nil) != tt.ok {
			t.Errorf("%.20q: err = %v", tt.in, err)
			continue
		}
		if !tt.ok {
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%.20q: err = %v, want %q", tt.in, err, tt.want)
			}
			continue
		}
		h := strings.TrimSpace(out.String())
		if _, err := auth.ParsePasswordHash(h); err != nil || !strings.HasPrefix(h, "$argon2id$") {
			t.Errorf("%.20q: output %q: %v", tt.in, h, err)
		}
	}

	// Without --stdin a terminal is required.
	root := newRootCmd()
	root.SetArgs([]string{"user", "hash-password"})
	root.SetIn(strings.NewReader("s3cret\n"))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "--stdin") {
		t.Errorf("hash-password without a terminal: %v", err)
	}
}

func TestUserAddPassword(t *testing.T) {
	t.Parallel()

	h, err := auth.HashPassword([]byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	block, err := userBlock("partner", userAddOptions{passwordHash: h, access: []string{"inbox=upload"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Users map[string]config.User `toml:"users"`
	}
	if _, err := toml.Decode(block, &parsed); err != nil {
		t.Fatalf("output is not TOML: %v\n%s", err, block)
	}
	if u := parsed.Users["partner"]; u.PasswordHash != h || len(u.AuthorizedKeys) != 0 {
		t.Errorf("decoded user = %+v", u)
	}
}

func TestCheckRoot(t *testing.T) {
	t.Parallel()

	if err := checkRoot(false, 0); err == nil || !strings.Contains(err.Error(), "--allow-root") {
		t.Errorf("root without --allow-root: %v", err)
	}
	for _, tt := range []struct {
		allow bool
		euid  int
	}{{true, 0}, {false, 1000}, {false, -1}} {
		if err := checkRoot(tt.allow, tt.euid); err != nil {
			t.Errorf("checkRoot(%v, %d) = %v", tt.allow, tt.euid, err)
		}
	}
}
