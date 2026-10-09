// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzParseConfig (ROADMAP §8.3): loading and validating arbitrary bytes
// never panics, and a configuration that validates still loads and
// validates after Encode.
func FuzzParseConfig(f *testing.F) {
	for _, name := range []string{"example.toml", "example-full.toml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		f.Fatal(err)
	}
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	f.Add([]byte("config_version = 1\n[server]\nhost_keys = [\"k\"]\n[defaults]\nmax_file_size = 1536\n" +
		"[mounts.m]\npath = \"/srv/m\"\non_conflict = \"version\"\nversions = { keep = 3, max_age = \"1h\" }\n" +
		"[users.a]\nauthorized_keys = [\"" + key + "\"]\naccess = { m = \"upload\" }\n"))
	f.Add([]byte("config_version = 1\n[mounts.m]\npath = \"/srv/m\"\nmax_file_size = \"10GiB\"\nversions = { keep = 3 }\n"))
	f.Add([]byte("config_version = 1\n[users.a]\npassword_hash = \"$2b$10$abc\"\naccess = { m = \"read\" }\n"))
	f.Add([]byte("[defaults]\numask = \"0777\"\non_conflict = \"version\"\nrename_template = \"{n}\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if bytes.Contains(data, []byte("include")) {
			return // would read files of the host
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "c.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			return
		}
		_, verr := c.Validate()
		_, _ = c.MountSpecs()
		for name := range c.Users {
			_ = c.Grants(name)
		}
		_ = c.Bans()
		_ = c.AuditOptions()
		if verr != nil {
			return
		}
		enc, err := c.Encode()
		if err != nil {
			t.Fatalf("a valid configuration does not encode: %v", err)
		}
		again := filepath.Join(dir, "again.toml")
		if err := os.WriteFile(again, enc, 0o600); err != nil {
			t.Fatal(err)
		}
		c2, err := Load(again)
		if err != nil {
			t.Fatalf("encoded configuration does not load: %v\n%s", err, enc)
		}
		if _, err := c2.Validate(); err != nil {
			t.Fatalf("encoded configuration does not validate: %v\n%s", err, enc)
		}
	})
}
