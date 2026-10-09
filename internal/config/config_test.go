// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func pubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// writeConfig writes data (with {dir} replaced by the directory) to
// dir/gosftpd.toml with mode 0600 and returns its path.
func writeConfig(t *testing.T, dir, data string) string {
	t.Helper()
	path := filepath.Join(dir, "gosftpd.toml")
	data = strings.ReplaceAll(data, "{dir}", filepath.ToSlash(dir))
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, data string) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := Load(writeConfig(t, dir, data))
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func mustValidate(t *testing.T, c *Config) []string {
	t.Helper()
	warns, err := c.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return warns
}

func TestLoadDefaultsAndInheritance(t *testing.T) {
	t.Parallel()

	key := pubKey(t)
	c, dir := load(t, `
config_version = 1

[server]
host_keys = ["keys/host"]

[defaults]
on_conflict = "reject"

[mounts.a]
path = "{dir}/a"

[mounts.b]
path = "{dir}/b"
on_conflict = "overwrite"
compound_extensions = [".tar.lz"]

[users.alice]
authorized_keys = ["`+key+`"]
access = { a = "full", b = "read" }
`)
	mustValidate(t, c)

	if c.Server.Listen[0] != ":2022" || time.Duration(c.Server.HandshakeTimeout) != 30*time.Second {
		t.Errorf("server defaults = %+v", c.Server)
	}
	if want := filepath.Join(dir, "keys", "host"); c.Server.HostKeys[0] != want {
		t.Errorf("host key = %q, want it relative to the config: %q", c.Server.HostKeys[0], want)
	}
	if a, b := c.Mounts["a"], c.Mounts["b"]; a.OnConflict != "reject" || b.OnConflict != "overwrite" {
		t.Errorf("on_conflict a=%q b=%q", a.OnConflict, b.OnConflict)
	}
	// Decoding b's list must not overwrite the defaults a inherited.
	if !reflect.DeepEqual(c.Mounts["a"].CompoundExtensions, vfs.DefaultCompoundExtensions) ||
		!reflect.DeepEqual(c.Defaults.CompoundExtensions, vfs.DefaultCompoundExtensions) {
		t.Errorf("compound_extensions a=%q defaults=%q", c.Mounts["a"].CompoundExtensions, c.Defaults.CompoundExtensions)
	}
	if c.Mounts["a"].Umask != 0o027 || !c.Defaults.Flatten {
		t.Errorf("umask %o flatten %v", c.Mounts["a"].Umask, c.Defaults.Flatten)
	}

	specs, err := c.MountSpecs()
	if err != nil || len(specs) != 2 || specs[1].Options.OnConflict != vfs.ConflictOverwrite {
		t.Fatalf("MountSpecs = %+v, %v", specs, err)
	}
	gs := c.Grants("alice")
	if len(gs) != 2 || gs[0] != (vfs.Grant{Mount: "a", Perm: vfs.PermAll}) || gs[1].Perm != vfs.PermReadOnly {
		t.Errorf("Grants = %+v", gs)
	}
	if c.Grants("bob") != nil {
		t.Error("Grants for an unknown user")
	}
}

func TestUnknownKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := Load(writeConfig(t, dir, `
config_version = 1
[mounts.inbox]
pth = "/srv"
[serverr]
listen = [":22"]
`))
	if err == nil {
		t.Fatal("unknown keys accepted")
	}
	for _, want := range []string{"unknown key mounts.inbox.pth", "unknown key serverr"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestSyntaxErrorHasPosition(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := Load(writeConfig(t, dir, "config_version = 1\n[server]\nlisten = [\":2022\"\n"))
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error = %v, want the line number", err)
	}
	_, err = Load(writeConfig(t, dir, "config_version = 1\n[server]\nhandshake_timeout = 30\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("integer duration: %v", err)
	}
	for _, umask := range []string{`27`, `"0999"`, `"1777"`} {
		_, err = Load(writeConfig(t, dir, "config_version = 1\n[defaults]\numask = "+umask+"\n"))
		if err == nil {
			t.Errorf("umask = %s accepted", umask)
		}
	}
	// FuzzParseConfig: an escape cut off by the end of the file on its first
	// line made the TOML library report line 0, and formatting that error
	// panicked.
	for _, data := range []string{`"\`, `a = "C:\`, "config_version = 1\n[mounts.m]\npath = \"C:\\"} {
		path := writeConfig(t, dir, data)
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("Load(%q) = %v, want an error naming the file", data, err)
			continue
		}
		if strings.ContainsFunc(err.Error(), func(r rune) bool { return r < ' ' && r != '\n' && r != '\t' }) {
			t.Errorf("Load(%q): error %q has control characters", data, err)
		}
		if !strings.HasPrefix(data, "config_version") && !strings.Contains(err.Error(), "at the end of the file") {
			t.Errorf("Load(%q): error %q does not say where", data, err)
		}
	}
}

func TestValidateReportsEverything(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 2

[server]
listen = ["2022"]
handshake_timeout = "0s"

[limits]
max_open_handles = 0

[defaults]
rename_template = "{stem} copy{ext}"

[mounts.inbox]
path = "{dir}/sftp/inbox"
setstat_mode = "chmod"

[mounts.Inbox]
path = "{dir}/sftp/inbox/sub"

[mounts.rel]
path = "relative/path"

[mounts.home]
path = "{dir}/{user}/x"

[users.Alice]
authorized_keys = ["<paste alice's key>"]
access = { inbox = "admin", nowhere = "read" }
allow_from = ["example.org"]

[log]
level = "verbose"
`)
	_, err := c.Validate()
	if err == nil {
		t.Fatal("Validate succeeded")
	}
	for _, want := range []string{
		"config_version: 2 is not supported",
		`server.listen: "2022"`,
		"server.host_keys: at least one",
		"server.handshake_timeout",
		"limits.max_open_handles",
		"defaults.rename_template",
		"mounts.inbox.setstat_mode",
		"mounts.inbox: clashes with mount", // case-insensitive clash, reported on the later name
		"overlaps with mount",
		`mounts.rel.path: path "relative/path" is not absolute`,
		"mounts.home.path",
		"users.Alice: invalid user name",
		"users.Alice.authorized_keys: entry 1 is a placeholder",
		`users.Alice.access: inbox: unknown permission "admin"`,
		`users.Alice.access: unknown mount "nowhere"`,
		"users.Alice.allow_from",
		"log.level",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q:\n%v", want, err)
		}
	}
	// The template is reported once, for [defaults], not again per mount.
	if n := strings.Count(err.Error(), "must contain {n}"); n != 1 {
		t.Errorf("rename_template reported %d times", n)
	}
}

func TestValidateMissingVersionAndWarnings(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
`)
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "config_version: missing") {
		t.Errorf("missing version: %v", err)
	}

	c, _ = load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
[users.bob]
expires = 2001-01-01T00:00:00Z
`)
	warns := strings.Join(mustValidate(t, c), "\n")
	for _, want := range []string{"users.bob.access: no mounts", "users.bob.expires: already expired", "users.bob: no usable authorized_keys"} {
		if !strings.Contains(warns, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, warns)
		}
	}

	c, _ = load(t, "config_version = 1\n[server]\nhost_keys = [\"/k\"]\n[mounts.m]\npath = \"{dir}/m\"\n")
	if warns := mustValidate(t, c); len(warns) != 1 || !strings.Contains(warns[0], "no users configured") {
		t.Errorf("warnings = %q", warns)
	}
}

func TestInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := pubKey(t)
	if err := os.MkdirAll(filepath.Join(dir, "users.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, "users.d", name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("bob.toml", "[users.bob]\nauthorized_keys = [\""+key+"\"]\nauthorized_keys_file = \"bob.pub\"\naccess = { m = \"read\" }\n")
	write("carol.toml", "[users.carol]\naccess = { m = \"upload\" }\n")
	main := writeConfig(t, dir, `
config_version = 1
include = ["users.d/*.toml"]
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
[users.alice]
authorized_keys = ["`+key+`"]
access = { m = "full" }
`)
	c, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	if len(c.Users) != 3 || len(c.Files) != 3 {
		t.Fatalf("users = %v, files = %v", c.Users, c.Files)
	}
	if want := filepath.Join(dir, "users.d", "bob.pub"); c.Users["bob"].AuthorizedKeysFile != want {
		t.Errorf("bob's keys file = %q, want relative to the include: %q", c.Users["bob"].AuthorizedKeysFile, want)
	}

	// A user defined twice, and an include with other tables.
	write("dup.toml", "[users.alice]\naccess = { m = \"read\" }\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), `user "alice" is already defined`) {
		t.Errorf("duplicate user: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "users.d", "dup.toml")); err != nil {
		t.Fatal(err)
	}
	write("bad.toml", "[mounts.x]\npath = \"/tmp\"\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), "may only define [users.NAME]") {
		t.Errorf("include with mounts: %v", err)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	t.Parallel()

	key := pubKey(t)
	c, dir := load(t, `
config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
umask = "0077"
[users.alice]
authorized_keys = ["`+key+`"]
expires = 2030-01-01T00:00:00Z
access = { m = "full" }
`)
	data, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`umask = "0077"`, `handshake_timeout = "30s"`, "expires = 2030-01-01T00:00:00Z", `on_conflict = "rename"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("encoded config lacks %q:\n%s", want, data)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "shown.toml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Load(filepath.Join(dir, "shown.toml"))
	if err != nil {
		t.Fatalf("encoded config does not load: %v\n%s", err, data)
	}
	mustValidate(t, again)
	if !reflect.DeepEqual(again.Mounts, c.Mounts) || !reflect.DeepEqual(again.Server, c.Server) {
		t.Errorf("round trip changed the config:\n%s", data)
	}
}

func TestCheckFS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/missing_key"]
[mounts.ok]
path = "{dir}/exists"
[mounts.created]
path = "{dir}/new"
create = true
[mounts.missing]
path = "{dir}/missing"
[mounts.notdir]
path = "{dir}/file"
[mounts.home]
path = "{dir}/homes/{user}"
create = true
[users.alice]
authorized_keys_file = "{dir}/nokeys"
access = { ok = "full" }
[audit]
output = "{dir}/nodir/audit.jsonl"
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	_, err = c.CheckFS()
	if err == nil {
		t.Fatal("CheckFS succeeded")
	}
	msg := err.Error()
	for _, want := range []string{
		"mounts.missing.path", "set create = true",
		"mounts.notdir.path", "is not a directory",
		"server.host_keys", "missing_key does not exist",
		"users.alice.authorized_keys_file",
		"audit.output: directory",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("CheckFS errors do not mention %q:\n%s", want, msg)
		}
	}
	for _, unwanted := range []string{"mounts.ok", "mounts.created", "mounts.home"} {
		if strings.Contains(msg, unwanted) {
			t.Errorf("CheckFS reports %s:\n%s", unwanted, msg)
		}
	}
}

func TestCheckFSPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte(pubKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keys, 0o664); err != nil { // not subject to the umask
		t.Fatal(err)
	}
	host := filepath.Join(dir, "host")
	if err := os.WriteFile(host, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/host"]
[mounts.m]
path = "{dir}/m"
[users.alice]
authorized_keys_file = "{dir}/keys"
access = { m = "full" }
`)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	warns, err := c.CheckFS()
	if err == nil {
		t.Fatal("CheckFS accepted group-writable files")
	}
	for _, want := range []string{"gosftpd.toml: writable by group or others", "keys: writable by group or others", "permissions 0644 are too open"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q:\n%v", want, err)
		}
	}
	if len(warns) == 0 || !strings.Contains(warns[0], "readable by all users") {
		t.Errorf("warnings = %q", warns)
	}

	for _, f := range []string{path, keys} {
		if err := os.Chmod(f, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(host, 0o600); err != nil {
		t.Fatal(err)
	}
	if warns, err := c.CheckFS(); err != nil || len(warns) != 0 {
		t.Errorf("CheckFS after chmod = %q, %v", warns, err)
	}
}

func TestAuthenticator(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	k1, k2 := pubKey(t), pubKey(t)
	if err := os.WriteFile(filepath.Join(dir, "bob.pub"), []byte(k2+"\ncommand=\"x\" "+k1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
[users.alice]
authorized_keys = ["`+k1+`"]
allow_from = ["10.0.0.0/8"]
access = { m = "full" }
[users.bob]
authorized_keys_file = "bob.pub"
access = { m = "read" }
[users.carol]
disabled = true
access = { m = "read" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	a, warns, err := c.Authenticator()
	if err != nil {
		t.Fatal(err)
	}
	if a.Len() != 2 {
		t.Errorf("Len() = %d, want 2", a.Len())
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "bob.pub:2") {
		t.Errorf("warnings = %q", warns)
	}

	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: filepath.Join(dir, "missing")}
	if _, _, err := zero.Authenticator(); err == nil {
		t.Error("missing authorized_keys accepted")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("# none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zero.AnyUser.AuthorizedKeysFile = empty
	if _, _, err := zero.Authenticator(); !errors.Is(err, errNoKeys) {
		t.Errorf("empty authorized_keys: %v", err)
	}
	zero.Mounts = map[string]*Mount{"x": {}, "y": {}}
	if gs := zero.Grants("anyone"); len(gs) != 2 || gs[0].Perm != vfs.PermAll {
		t.Errorf("zero-config grants = %+v", gs)
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }

	explicit := filepath.Join(dir, "explicit.toml")
	if _, err := Find(explicit, getenv); err == nil || !strings.Contains(err.Error(), "--config") {
		t.Errorf("missing --config file: %v", err)
	}
	if err := os.WriteFile(explicit, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := Find(explicit, getenv); err != nil || p != explicit {
		t.Errorf("Find(explicit) = %q, %v", p, err)
	}

	env[EnvConfig] = filepath.Join(dir, "env.toml")
	if _, err := Find("", getenv); err == nil || !strings.Contains(err.Error(), EnvConfig) {
		t.Errorf("missing $%s file: %v", EnvConfig, err)
	}
	delete(env, EnvConfig)

	if err := os.WriteFile(LocalFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := Find("", getenv); err != nil || p != LocalFile {
		t.Errorf("Find() = %q, %v; want ./%s", p, err, LocalFile)
	}
}

func TestExamples(t *testing.T) {
	t.Parallel()

	key := pubKey(t)
	for _, full := range []bool{false, true} {
		dir := t.TempDir()
		data := string(Example(full))
		// Absolute Unix paths are not absolute on Windows.
		for _, prefix := range []string{`"/srv/`, `"/var/`, `"/etc/`} {
			data = strings.ReplaceAll(data, prefix, `"{dir}`+prefix[1:])
		}
		// Replace placeholders with a real key, as a user would.
		for {
			i := strings.Index(data, `"<paste`)
			if i < 0 {
				break
			}
			j := strings.Index(data[i+1:], `"`) + i + 1
			data = data[:i] + `"` + key + `"` + data[j+1:]
		}
		if !strings.Contains(data, "config_version = 1") {
			t.Fatalf("example (full=%v) lacks config_version", full)
		}
		c, err := Load(writeConfig(t, dir, data))
		if err != nil {
			t.Fatalf("example (full=%v): %v", full, err)
		}
		if _, err := c.Validate(); err != nil {
			t.Errorf("example (full=%v) does not validate: %v", full, err)
		}
	}
	// Unchanged, the placeholder is reported.
	c, err := Load(writeConfig(t, t.TempDir(), string(Example(false))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("placeholder not reported: %v", err)
	}
}

// TestExampleFullCoversEveryKey keeps the reference complete: every key of
// the schema appears in example-full.toml.
func TestExampleFullCoversEveryKey(t *testing.T) {
	t.Parallel()

	full := string(Example(true))
	var walk func(t reflect.Type)
	walk = func(typ reflect.Type) {
		for f := range typ.Fields() {
			tag, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
			switch {
			case tag == "-":
				continue
			case f.Anonymous:
				walk(f.Type)
				continue
			}
			if !strings.Contains(full, tag+" =") && !strings.Contains(full, "["+tag) && !strings.Contains(full, "."+tag+"]") {
				t.Errorf("example-full.toml does not show %q", tag)
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Map {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft != reflect.TypeFor[time.Time]() {
				walk(ft)
			}
		}
	}
	walk(reflect.TypeFor[Config]())
}

func TestKeysAreCaseSensitive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, data := range []string{
		"config_version = 1\n[mounts.m]\npath = \"/a\"\nPATH = \"/b\"\n",
		"config_version = 1\n[mounts.m]\npath = \"/a\"\nRead_Only = true\n",
		"config_version = 1\n[Server]\nlisten = [\":22\"]\n",
		"config_version = 1\n[defaults]\nOn_Conflict = \"reject\"\n",
	} {
		_, err := Load(writeConfig(t, dir, data))
		if err == nil || !strings.Contains(err.Error(), "keys are case-sensitive") {
			t.Errorf("%q: %v", data, err)
		}
	}
	_, err := Load(writeConfig(t, dir, "config_version = 1\n[Server]\nlisten = [\":22\"]\nhandshake_timeout = \"5s\"\n"))
	if err == nil || strings.Count(err.Error(), "case-sensitive") != 1 {
		t.Errorf("keys below a reported table are reported again: %v", err)
	}
	// Names (of mounts, users, access entries) keep their case.
	c, err := Load(writeConfig(t, dir, "config_version = 1\n[mounts.Docs]\npath = \"{dir}/d\"\n[users.a]\naccess = { Docs = \"read\" }\n"))
	if err != nil || c.Mounts["Docs"] == nil || c.Users["a"].Access["Docs"] != "read" {
		t.Errorf("names: %+v, %v", c, err)
	}
}

func TestIncludeGlob(t *testing.T) {
	t.Parallel()

	// Glob characters in the configuration directory itself are literal.
	dir := filepath.Join(t.TempDir(), "sftp[prod]")
	if err := os.MkdirAll(filepath.Join(dir, "users.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.d", "bob.toml"), []byte("[users.bob]\naccess = {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, "config_version = 1\ninclude = [\"users.d/*.toml\"]\n"))
	if err != nil || c.Users["bob"] == nil {
		t.Errorf("include below a [bracketed] directory: users = %v, %v", c, err)
	}
	if _, err := Load(writeConfig(t, dir, "config_version = 1\ninclude = [\"../*.toml\"]\n")); err == nil {
		t.Error("relative include outside the directory accepted")
	}
	abs := filepath.ToSlash(filepath.Join(dir, "users.d", "*.toml"))
	if c, err := Load(writeConfig(t, t.TempDir(), "config_version = 1\ninclude = [\""+abs+"\"]\n")); err == nil && c.Users["bob"] != nil {
		t.Log("absolute include patterns are globbed as written")
	}
}

func TestValidateEdgeValues(t *testing.T) {
	t.Parallel()

	base := "config_version = 1\n[mounts.m]\npath = \"{dir}/m\"\n[server]\nhost_keys = [\"k\"]\n"
	c, _ := load(t, base+"handshake_timeout = \"30ms\"\nshutdown_timeout = \"1ns\"\n")
	_, err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "server.handshake_timeout") || !strings.Contains(err.Error(), "server.shutdown_timeout") {
		t.Errorf("sub-second timeouts: %v", err)
	}
	c, _ = load(t, base+"[log]\nlevel = \"DEBUG\"\n")
	if _, err := c.Validate(); err != nil {
		t.Errorf("upper-case level: %v", err)
	}
}

func TestEncodeWithInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "users.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.d", "bob.toml"), []byte("[users.bob]\naccess = { m = \"read\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, "config_version = 1\ninclude = [\"users.d/*.toml\"]\n[server]\nhost_keys = [\"k\"]\n[mounts.m]\npath = \"{dir}/m\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	shown := filepath.Join(dir, "shown.toml")
	if err := os.WriteFile(shown, data, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := Load(shown)
	if err != nil || again.Users["bob"] == nil || len(again.Files) != 1 {
		t.Errorf("shown config with include does not reload: %v\n%s", err, data)
	}
}

func TestCheckFSAuditOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := Default()
	c.Audit.Output = dir
	if _, err := c.CheckFS(); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("directory as audit output: %v", err)
	}
	if runtime.GOOS != "windows" {
		c.Audit.Output = os.DevNull
		if _, err := c.CheckFS(); err != nil {
			t.Errorf("%s as audit output: %v", os.DevNull, err)
		}
	}
}

func TestValidateM2bKeys(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["k"]
[defaults]
resume = "always"
[mounts.m]
path = "{dir}/m"
symlinks = "follow"
[audit]
events = ["conn", "files"]
on_error = "ignore"
`)
	_, err := c.Validate()
	for _, want := range []string{"defaults.resume", "mounts.m.symlinks", `audit.events: unknown audit category "files"`, "audit.on_error"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q: %v", want, err)
		}
	}

	c, _ = load(t, `
config_version = 1
[server]
host_keys = ["k"]
[defaults]
resume = "off"
stat_redirect = false
[mounts.m]
path = "{dir}/m"
symlinks = "deny"
[audit]
events = ["list", "stat"]
on_error = "fail-open"
`)
	mustValidate(t, c)
	specs, err := c.MountSpecs()
	if err != nil {
		t.Fatal(err)
	}
	o := specs[0].Options
	if o.Resume != vfs.ResumeOff || o.StatRedirect || o.Symlinks != vfs.SymlinksDeny {
		t.Errorf("mount options = %+v", o)
	}
	ao := c.AuditOptions()
	if !ao.FailOpen || !reflect.DeepEqual(ao.Categories, []string{"list", "stat"}) {
		t.Errorf("audit options = %+v", ao)
	}
	if d := Default().AuditOptions(); d.FailOpen || len(d.Categories) != 6 {
		t.Errorf("default audit options = %+v", d)
	}
}

func TestValidateM3aKeys(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["k"]
crypto_policy = "legacy"
idle_timeout = "500ms"
keepalive_interval = "2h"
[limits]
max_connections = 0
max_connections_per_ip = -1
max_preauth_connections = 20000
[auth]
methods = ["publickey", "keyboard-interactive"]
[auth.ban]
after_failures = 1000
within = "0s"
duration = "1000h"
exempt = ["example.org"]
[mounts.m]
path = "{dir}/m"
[users.alice]
password_hash = "secret"
access = { m = "read" }
`)
	_, err := c.Validate()
	for _, want := range []string{
		"server.crypto_policy", "server.idle_timeout", "server.keepalive_interval",
		"limits.max_connections:", "limits.max_connections_per_ip", "limits.max_preauth_connections",
		`auth.methods: unknown method "keyboard-interactive"`, "auth.ban.after_failures", "auth.ban.within",
		"auth.ban.duration", "auth.ban.exempt", "users.alice.password_hash: not an argon2id or bcrypt hash",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q: %v", want, err)
		}
	}

	hash, err := auth.HashPassword([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	const base = `
config_version = 1
[server]
host_keys = ["k"]
idle_timeout = "0s"
keepalive_interval = "0s"
crypto_policy = "compat"
[mounts.m]
path = "{dir}/m"
[users.bob]
password_hash = "%s"
access = { m = "read" }
`
	// Without "password" in auth.methods the hash is ignored with a warning.
	c, _ = load(t, fmt.Sprintf(base, hash))
	warns := mustValidate(t, c)
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "password_hash: ignored") }) {
		t.Errorf("warnings = %q", warns)
	}
	if a, _, err := c.Authenticator(); err != nil || a.Len() != 0 {
		t.Errorf("Authenticator() = %v, %v", a, err)
	}
	if b := c.Bans(); b == nil || b.Duration() != auth.DefaultBanDuration {
		t.Errorf("default bans = %+v", b)
	}

	c, _ = load(t, fmt.Sprintf(base, hash)+"[auth]\nmethods = [\"publickey\", \"password\"]\n[auth.ban]\nafter_failures = 0\n")
	warns = mustValidate(t, c)
	if slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "users.bob") }) {
		t.Errorf("warnings about a user with a password: %q", warns)
	}
	if _, warns, err := c.Authenticator(); err != nil || len(warns) != 0 {
		t.Errorf("Authenticator() warnings %q, err %v", warns, err)
	}
	if c.Bans() != nil {
		t.Error("after_failures = 0 did not turn bans off")
	}

	// Zero-config has public keys only.
	for _, methods := range [][]string{{"password"}, {"publickey", "password"}} {
		zero := Default()
		zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: "k"}
		zero.Auth.Methods = methods
		if _, err := zero.Validate(); err == nil || !strings.Contains(err.Error(), "auth.methods") {
			t.Errorf("zero-config with methods %v: %v", methods, err)
		}
	}

	// Keys of a password-only server are ignored, and one address that may
	// hold every pre-authentication slot is worth a warning.
	c, _ = load(t, fmt.Sprintf(base, hash)+`authorized_keys = ["`+pubKey(t)+`"]
[auth]
methods = ["password"]
[limits]
max_connections_per_ip = 64
`)
	warns = mustValidate(t, c)
	for _, want := range []string{"users.bob: keys not used", "limits.max_connections_per_ip: 64 is not below max_preauth_connections"} {
		if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("warnings %q lack %q", warns, want)
		}
	}

	// Keys of a password-only server are not even read: a missing key file
	// does not stop it.
	c, dir := load(t, fmt.Sprintf(base, hash)+`authorized_keys_file = "missing.pub"
[auth]
methods = ["password"]
`)
	mustValidate(t, c)
	if err := os.MkdirAll(filepath.Join(dir, "m"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckFS(); err != nil && strings.Contains(err.Error(), "missing.pub") {
		t.Errorf("CheckFS checks an unused key file: %v", err)
	}
	if a, _, err := c.Authenticator(); err != nil || a.Len() != 0 {
		t.Errorf("Authenticator() with keys off: %v keys, err %v", a, err)
	}

	// The per-address limit against a lower total.
	c, _ = load(t, fmt.Sprintf(base, hash)+"[limits]\nmax_connections = 16\n")
	warns = mustValidate(t, c)
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "is not below max_connections (16)") }) {
		t.Errorf("warnings %q lack the max_connections case", warns)
	}

	// Hashes of several kinds or costs.
	bc, err := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = load(t, fmt.Sprintf(base, hash)+"[users.carol]\npassword_hash = \""+string(bc)+"\"\naccess = { m = \"read\" }\n[auth]\nmethods = [\"password\"]\n")
	warns = mustValidate(t, c)
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "password hashes of 2 different kinds") }) {
		t.Errorf("warnings %q lack the mixed hash kinds", warns)
	}

	// "password" without any password_hash is useless.
	c, _ = load(t, strings.Replace(fmt.Sprintf(base, ""), `password_hash = ""`, `authorized_keys = ["`+pubKey(t)+`"]`, 1)+
		"[auth]\nmethods = [\"publickey\", \"password\"]\n")
	warns = mustValidate(t, c)
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "no user has a password_hash") }) {
		t.Errorf("warnings %q lack the unused password method", warns)
	}
}

// TestConfigurationDocCoversEveryKey keeps docs/configuration.md complete.
func TestConfigurationDocCoversEveryKey(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(typ reflect.Type, table string)
	walk = func(typ reflect.Type, parent string) {
		for f := range typ.Fields() {
			tag, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
			switch {
			case tag == "-":
				continue
			case f.Anonymous:
				walk(f.Type, parent)
				continue
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Map {
				ft = ft.Elem()
			}
			table := ft.Kind() == reflect.Struct && ft != reflect.TypeFor[time.Time]()
			name := tag
			if table && parent != "" {
				name = parent + "." + tag
			}
			if f.Type.Kind() == reflect.Map {
				name += ".NAME" // [mounts.NAME], [users.NAME]
			}
			switch {
			case table && !strings.Contains(string(doc), "`["+name):
				t.Errorf("docs/configuration.md has no section for [%s]", name)
			case !table && !strings.Contains(string(doc), "`"+tag+"`"):
				t.Errorf("docs/configuration.md does not describe `%s`", tag)
			}
			if table {
				walk(ft, name)
			}
		}
	}
	walk(reflect.TypeFor[Config](), "")
}

func TestByteSize(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]ByteSize{
		"0": 0, "1024": 1024, "500MB": 500e6, "1kB": 1000, "1KB": 1000, "2 MiB": 2 << 20,
		"10GiB": 10 << 30, "3TB": 3e12, "1TiB": 1 << 40, "7B": 7, "9223372036854775807B": math.MaxInt64,
	} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1.5GB", "GiB", "10 parsecs", "1gib", "10000000TiB", "9223372036854775808"} {
		if got, err := ParseByteSize(in); err == nil {
			t.Errorf("ParseByteSize(%q) = %d, want an error", in, got)
		}
	}
	for b, want := range map[ByteSize]string{0: "0", 1 << 30: "1GiB", 3 << 20: "3MiB", 1e9: "1000000000", 1536: "1536"} {
		got, _ := b.MarshalText()
		if string(got) != want {
			t.Errorf("MarshalText(%d) = %q, want %q", int64(b), got, want)
		}
		if back, err := ParseByteSize(string(got)); err != nil || back != b {
			t.Errorf("round trip of %d: %d, %v", int64(b), back, err)
		}
	}
}

func TestM3bKeys(t *testing.T) {
	t.Parallel()

	c, _ := load(t, `
config_version = 1
[server]
host_keys = ["k"]
[defaults]
max_file_size = "10GiB"
min_free_space = 0
versions = { keep = 3 }
[mounts.a]
path = "{dir}/a"
[mounts.b]
path = "{dir}/b"
on_conflict = "version"
atomic_uploads = true
fsync = true
max_file_size = 1000
[mounts.b.versions]
max_age = "1h"
[users.alice]
authorized_keys = ["`+pubKey(t)+`"]
access = { a = "full", b = "full" }
`)
	mustValidate(t, c)
	specs, err := c.MountSpecs()
	if err != nil {
		t.Fatal(err)
	}
	a, b := specs[0].Options, specs[1].Options
	if a.MaxFileSize != 10<<30 || a.MinFreeSpace != 0 || a.AtomicUploads || a.Fsync ||
		a.Versions != (vfs.VersionsOptions{Dir: ".versions", Keep: 3, MaxAge: 720 * time.Hour}) {
		t.Errorf("mount a = %+v", a)
	}
	if b.MaxFileSize != 1000 || b.MinFreeSpace != 0 || !b.AtomicUploads || !b.Fsync || b.OnConflict != vfs.ConflictVersion ||
		b.Versions != (vfs.VersionsOptions{Dir: ".versions", Keep: 3, MaxAge: time.Hour}) {
		t.Errorf("mount b = %+v", b)
	}

	for _, bad := range []string{`max_file_size = "10 parsecs"`, `min_free_space = -1`, `max_file_size = 1.5`} {
		dir := t.TempDir()
		_, err := Load(writeConfig(t, dir, "config_version = 1\n[defaults]\n"+bad+"\n"))
		if err == nil || !strings.Contains(err.Error(), strings.Fields(bad)[0]) {
			t.Errorf("%s: %v", bad, err)
		}
	}

	c, _ = load(t, `
config_version = 1
[server]
host_keys = ["k"]
[defaults]
versions = { dir = "a/b" }
[mounts.m]
path = "{dir}/m"
versions = { dir = "v", keep = -1 }
[mounts.n]
path = "{dir}/n"
[users.alice]
authorized_keys = ["`+pubKey(t)+`"]
access = { m = "read" }
`)
	_, err = c.Validate()
	for _, want := range []string{"defaults.versions:", "mounts.m.versions:"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q: %v", want, err)
		}
	}
	if err != nil && strings.Contains(err.Error(), "mounts.n.versions") {
		t.Errorf("an inherited error is reported again: %v", err)
	}
}

// On reload, a mount that fails its checks is unavailable instead of
// blocking the reload, and host keys and key files are not checked.
func TestCheckFSReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, d := range []string{"ok", "disk"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/missing_key"]
[mounts.ok]
path = "{dir}/ok"
[mounts.gone]
path = "{dir}/gone"
[mounts.disk]
path = "{dir}/disk"
create = true
require_mountpoint = true
[users.alice]
authorized_keys_file = "{dir}/nokeys"
access = { ok = "full" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	warns, unavailable, err := c.CheckFSReload(nil)
	if err != nil {
		t.Fatalf("CheckFSReload: %v", err)
	}
	if !slices.Equal(unavailable, []string{"disk", "gone"}) {
		t.Errorf("unavailable = %q", unavailable)
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{"mounts.gone.path", "mounts.disk.require_mountpoint", "unavailable until this is fixed"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "host_keys") || strings.Contains(all, "authorized_keys_file") {
		t.Errorf("reload checks restart-only host keys or key files:\n%s", all)
	}
}

// Trusted files must not be inside a mount clients can write to; secrets
// must not be inside any mount.
func TestTrustedFilesOutsideMounts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, d := range []string{"rw/keys", "ro", "safe"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "rw", "keys", "bob.pub"), []byte(pubKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "rw"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/ro/host_key"]
host_key_auto_generate = true
[mounts.rw]
path = "{dir}/rw"
[mounts.ro]
path = "{dir}/ro"
read_only = true
[mounts.home]
path = "{dir}/safe/{user}"
[users.bob]
authorized_keys_file = "{dir}/link/keys/bob.pub"
access = { rw = "full" }
[audit]
output = "{dir}/safe/audit.jsonl"
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	_, err = c.CheckFS()
	if err == nil {
		t.Fatal("CheckFS accepted trusted files inside mounts")
	}
	for _, want := range []string{
		"mounts.rw.path: covers the authorized_keys file of bob", // through the symlink
		"mounts.ro.path: covers the host key",
		"mounts.home.path: covers the audit log", // the parent of {user}
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("errors do not mention %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "configuration file") {
		t.Errorf("the configuration file is not in a mount:\n%v", err)
	}

	c.Mounts["home"].ReadOnly = true
	c.Mounts["rw"].ReadOnly = true
	c.Server.HostKeys = []string{filepath.Join(dir, "host_key")}
	warns, err := c.CheckFS()
	if err != nil {
		t.Fatalf("read-only mounts with public files: %v", err)
	}
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "covers the audit log") }) {
		t.Errorf("no warning about a readable audit log: %q", warns)
	}

	zero := Default()
	zero.AddMount("home", dir)
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: filepath.Join(dir, "rw", "keys", "bob.pub")}
	zero.Server.HostKeys = []string{filepath.Join(t.TempDir(), "host_key")}
	zero.Server.HostKeyAutoGenerate = true
	if _, err := zero.CheckFS(); err == nil || !strings.Contains(err.Error(), "--dir home: covers the authorized_keys file") {
		t.Errorf("zero-config serving its own authorized_keys: %v", err)
	}
}

// A reload also checks trusted files against the mounts that open
// connections of an earlier configuration still use.
func TestCheckFSReloadLiveMounts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, d := range []string{"data/keys", "safe"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/safe/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "{dir}/data"
read_only = true
[users.bob]
authorized_keys_file = "{dir}/data/keys/bob.pub"
access = { data = "read" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	if _, _, err := c.CheckFSReload(nil); err != nil {
		t.Fatalf("a key file in a read-only mount: %v", err)
	}
	live := []LiveMount{{Name: "data", Path: filepath.Join(dir, "data")}}
	_, _, err = c.CheckFSReload(live)
	if err == nil || !strings.Contains(err.Error(), `mount "data" of open connections: covers the authorized_keys file of bob`) {
		t.Errorf("a key file in a mount open connections can still write: %v", err)
	}
	live[0].ReadOnly = true
	if _, _, err := c.CheckFSReload(live); err != nil {
		t.Errorf("the same read-only mount: %v", err)
	}
}

// On reload, problems of key files revoke their keys instead of failing;
// a file that is not a regular file keeps the keys read before.
func TestBuildAuthenticatorReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	k1, k2 := pubKey(t), pubKey(t)
	bob := filepath.Join(dir, "bob.pub")
	if err := os.WriteFile(bob, []byte(k1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "{dir}/m"
[users.alice]
authorized_keys = ["`+k2+`"]
access = { m = "read" }
[users.bob]
authorized_keys_file = "bob.pub"
access = { m = "read" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	a, files, _, err := c.BuildAuthenticator(AuthOptions{})
	if err != nil || a.Len() != 2 || len(files) != 0 {
		t.Fatalf("BuildAuthenticator = %d keys, %v, %v; want no pipes remembered", a.Len(), files, err)
	}

	if err := os.Remove(bob); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.BuildAuthenticator(AuthOptions{}); err == nil {
		t.Error("a missing key file is accepted at start")
	}
	a, _, warns, err := c.BuildAuthenticator(AuthOptions{Reload: true, Previous: files})
	if err != nil || a.Len() != 1 {
		t.Fatalf("reload without bob's file = %d keys, %v", a.Len(), err)
	}
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "its keys are not used") }) {
		t.Errorf("warnings = %q", warns)
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(bob, []byte(k1+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(bob, 0o666); err != nil {
			t.Fatal(err)
		}
		if a, _, _, err := c.BuildAuthenticator(AuthOptions{Reload: true}); err != nil || a.Len() != 1 {
			t.Errorf("reload with a writable key file = %d keys, %v", a.Len(), err)
		}
	}

	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: filepath.Join(dir, "missing")}
	a, _, warns, err = zero.BuildAuthenticator(AuthOptions{Reload: true})
	if err != nil || a.Len() != 0 || !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "nobody can log in") }) {
		t.Errorf("zero-config reload without keys = %d keys, %q, %v", a.Len(), warns, err)
	}
}
