// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// initSetup isolates HOME and returns a temporary directory with the
// directories inbox and docs and an authorized_keys file keys.
func initSetup(t *testing.T) (dir, keys string) {
	t.Helper()
	isolate(t)
	dir = t.TempDir()
	for _, d := range []string{"inbox", "docs"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keys = filepath.Join(dir, "keys")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n")
	return dir, keys
}

// runInitOK runs init with args and fails the test unless it succeeds.
func runInitOK(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	code, stdout, stderr := execute(t, append([]string{"init"}, args...)...)
	if code != exitOK {
		t.Fatalf("init %q: exit %d\n%s%s", args, code, stdout, stderr)
	}
	return stdout, stderr
}

// initValid fails the test unless config validate --check-fs accepts
// the file at path.
func initValid(t *testing.T, path string) {
	t.Helper()
	if code, stdout, stderr := execute(t, "config", "validate", "--check-fs", "--config", path); code != exitOK {
		t.Errorf("validate --check-fs: exit %d\n%s%s", code, stdout, stderr)
	}
}

func initLoad(t *testing.T, path string) *config.Config {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// initLeftovers returns the temporary files of init --force left in dir.
func initLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var tmp []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			tmp = append(tmp, e.Name())
		}
	}
	return tmp
}

func initRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// initSummary is what TestInitFlags compares of a written file.
type initSummary struct {
	Listen, HostKeys, Methods, Users []string
	OnConflict, AuditOutput          string
	Disconnect                       bool
	Mounts                           map[string]*initMountSummary
}

type initMountSummary struct {
	Path             string
	Create, ReadOnly bool
	OnConflict       string
}

func summarize(c *config.Config) initSummary {
	s := initSummary{
		Listen: c.Server.Listen, HostKeys: c.Server.HostKeys, Methods: c.Auth.Methods,
		Users:      slices.Sorted(maps.Keys(c.Users)),
		OnConflict: c.Defaults.OnConflict, AuditOutput: c.Audit.Output,
		Disconnect: c.Reload.DisconnectRemovedUsers,
		Mounts:     map[string]*initMountSummary{},
	}
	if !c.Server.HostKeyAutoGenerate {
		s.HostKeys = append(s.HostKeys, "(no host_key_auto_generate)")
	}
	for name, m := range c.Mounts {
		s.Mounts[name] = &initMountSummary{m.Path, m.Create, m.ReadOnly, m.OnConflict}
	}
	return s
}

// String shows the mounts, which %+v would show as pointers.
func (s initSummary) String() string {
	var mounts []string
	for _, name := range slices.Sorted(maps.Keys(s.Mounts)) {
		mounts = append(mounts, fmt.Sprintf("%s:%+v", name, *s.Mounts[name]))
	}
	s.Mounts = nil
	type plain initSummary // without this method
	return fmt.Sprintf("%+v %s", plain(s), strings.Join(mounts, " "))
}

// TestInitFlags checks what each flag writes, and only that, by parsing
// the file back, and that the file is valid.
func TestInitFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		edit func(want *initSummary, dir string) // of the defaults
	}{
		{"defaults", nil, nil},
		{"state-dir", []string{"--state-dir", "elsewhere"}, func(want *initSummary, dir string) {
			// Relative to the working directory, as serve's.
			want.HostKeys = []string{filepath.Join(dir, "elsewhere", hostkey.DefaultFile)}
		}},
		{"listen", []string{"--listen", "127.0.0.1:2222", "--listen", "[::1]:2222"}, func(want *initSummary, _ string) {
			want.Listen = []string{"127.0.0.1:2222", "[::1]:2222"}
		}},
		{"on-conflict", []string{"--on-conflict", "reject"}, func(want *initSummary, _ string) {
			want.OnConflict = "reject"
			for _, m := range want.Mounts {
				m.OnConflict = "reject"
			}
		}},
		{"audit-output", []string{"--audit-output", filepath.Join("logs", "audit.jsonl")}, func(want *initSummary, dir string) {
			want.AuditOutput = filepath.Join(dir, "logs", "audit.jsonl")
		}},
		{"audit-output stdout", []string{"--audit-output", "stdout"}, nil},
		{"read-only", []string{"--read-only", "docs"}, func(want *initSummary, _ string) {
			want.Mounts["docs"].ReadOnly = true
		}},
		{"password-logins", []string{"--password-logins"}, func(want *initSummary, _ string) {
			want.Methods = []string{"publickey", "password"}
		}},
		{"disconnect-removed-users", []string{"--disconnect-removed-users"}, func(want *initSummary, _ string) {
			want.Disconnect = true
		}},
		{"no-user", []string{"--no-user"}, func(want *initSummary, _ string) {
			want.Users = nil
		}},
		{"no-create", []string{"--no-create"}, func(want *initSummary, _ string) {
			for _, m := range want.Mounts {
				m.Create = false
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, keys := initSetup(t)
			t.Chdir(dir)
			// As init sees it, for the relative paths.
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "gosftpd.toml")
			args := []string{"--out", out, "--dir", "inbox=" + filepath.Join(dir, "inbox"), "--dir", "docs=" + filepath.Join(dir, "docs")}
			if !slices.Contains(tc.args, "--state-dir") {
				args = append(args, "--state-dir", filepath.Join(dir, "state"))
			}
			if !slices.Contains(tc.args, "--no-user") {
				args = append(args, "--user", "alice", "--authorized-keys", keys)
			}
			runInitOK(t, append(args, tc.args...)...)

			want := initSummary{
				Listen:     []string{":2022"},
				HostKeys:   []string{filepath.Join(dir, "state", hostkey.DefaultFile)},
				Methods:    []string{"publickey"},
				Users:      []string{"alice"},
				OnConflict: "rename", AuditOutput: "stdout",
				Mounts: map[string]*initMountSummary{
					"inbox": {filepath.Join(dir, "inbox"), true, false, "rename"},
					"docs":  {filepath.Join(dir, "docs"), true, false, "rename"},
				},
			}
			if tc.edit != nil {
				tc.edit(&want, dir)
			}
			if got := summarize(initLoad(t, out)); !reflect.DeepEqual(got, want) {
				t.Errorf("got  %v\nwant %v", got, want)
			}
			initValid(t, out)
		})
	}
}

// TestInitEveryCombination writes the file over and over with --force,
// with every combination of the switches, and checks that each one is
// valid and says what the flags asked.
func TestInitEveryCombination(t *testing.T) {
	dir, keys := initSetup(t)
	out := filepath.Join(dir, "state", "config.toml")
	if err := os.Mkdir(filepath.Dir(out), 0o700); err != nil {
		t.Fatal(err)
	}
	switches := [][]string{{"--password-logins"}, {"--disconnect-removed-users"}, {"--no-user"}, {"--no-create"}, {"--read-only", "docs"}}
	policies := []string{"rename", "reject", "overwrite", "version"}
	for mask := range 1 << len(switches) {
		on := func(i int) bool { return mask&(1<<i) != 0 }
		policy := policies[mask%len(policies)]
		args := []string{
			"--force", "--out", out, "--state-dir", filepath.Dir(out),
			"--dir", "inbox=" + filepath.Join(dir, "inbox"), "--dir", "docs=" + filepath.Join(dir, "docs"),
			"--listen", ":2022", "--on-conflict", policy,
			"--audit-output", filepath.Join(dir, "state", "audit", "audit.jsonl"),
		}
		for i, s := range switches {
			if on(i) {
				args = append(args, s...)
			}
		}
		if !on(2) {
			args = append(args, "--user", "alice", "--authorized-keys", keys)
		}
		_, stderr := runInitOK(t, args...)
		c := initLoad(t, out)
		if c.Auth.HasMethod("password") != on(0) || c.Reload.DisconnectRemovedUsers != on(1) ||
			(len(c.Users) == 0) != on(2) || c.Mounts["inbox"].Create == on(3) || c.Mounts["docs"].ReadOnly != on(4) ||
			c.Defaults.OnConflict != policy {
			t.Errorf("%q: config = %+v", args, c)
		}
		// The warnings of the check, as validate prints them.
		if on(2) && !strings.Contains(stderr, "warning: users: no users configured: nobody can log in") {
			t.Errorf("%q: no warning about the missing users:\n%s", args, stderr)
		}
		initValid(t, out)
	}
	if tmp := initLeftovers(t, filepath.Dir(out)); len(tmp) > 0 {
		t.Errorf("temporary files left: %q", tmp)
	}
}

func TestInitErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(dir, keys string) []string
		want string
	}{
		{
			"no-user without dir", func(string, string) []string { return []string{"--no-user"} },
			"Error: --no-user needs at least one --dir",
		},
		{"no-user with an invalid name", func(dir, _ string) []string {
			return []string{"--no-user", "--dir", "Фото=" + filepath.Join(dir, "inbox")}
		}, `"Фото" is not a valid mount name`},
		{"no-user with user", func(dir, _ string) []string {
			return []string{"--no-user", "--user", "bob", "--dir", filepath.Join(dir, "inbox")}
		}, "Error: --user and --no-user cannot be used together"},
		{"no-user with authorized-keys", func(dir, keys string) []string {
			return []string{"--no-user", "--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox")}
		}, "Error: --authorized-keys and --no-user cannot be used together"},
		{"read-only of an unknown mount", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", "inbox=" + filepath.Join(dir, "inbox"), "--read-only", "Inbox"}
		}, `Error: --read-only "Inbox": no --dir has this mount name (the names are "inbox")`},
		{"listen without port", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--listen", "2022"}
		}, `Error: --listen "2022": want HOST:PORT or :PORT`},
		{"listen with a bad port", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--listen", ":70000"}
		}, `Error: --listen ":70000": want HOST:PORT or :PORT`},
		{"listen twice", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--listen", ":2022", "--listen", ":2022"}
		}, `Error: --listen ":2022" is given twice`},
		{"on-conflict", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--on-conflict", "merge"}
		}, `Error: --on-conflict: unknown conflict policy "merge"`},
		{"empty audit-output", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--audit-output", ""}
		}, "Error: --audit-output: want stdout or a file path"},
		{"audit-output a directory", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--audit-output", dir}
		}, "is a directory; name a file in it"},
		{"audit-output two directories down", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"), "--audit-output", filepath.Join(dir, "a", "b", "audit.jsonl")}
		}, "Error: --audit-output: mkdir "},
		{"no-create with a missing directory", func(dir, keys string) []string {
			return []string{"--authorized-keys", keys, "--no-create", "--dir", "data=" + filepath.Join(dir, "data")}
		}, "does not exist, and with --no-create it is never created"},
		{"force without keys", func(dir, _ string) []string {
			return []string{"--force", "--dir", filepath.Join(dir, "inbox")}
		}, "Error: no authorized_keys file for alice: with --force, pass --authorized-keys FILE, or --no-user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, keys := initSetup(t)
			out := filepath.Join(dir, "gosftpd.toml")
			args := append([]string{"init", "--out", out, "--state-dir", filepath.Join(dir, "state")}, tc.args(dir, keys)...)
			if !slices.Contains(args, "--no-user") && !slices.Contains(args, "--user") {
				args = append(args, "--user", "alice")
			}
			code, _, stderr := execute(t, args...)
			if code != exitUsage || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, want %d and %q:\n%s", code, exitUsage, tc.want, stderr)
			}
			for _, p := range []string{out, filepath.Join(dir, "state"), filepath.Join(dir, "a"), filepath.Join(dir, "users.d")} {
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("%s was created", p)
				}
			}
		})
	}
}

// TestInitDirWithEqualsSign: without --no-user, a --dir whose part before
// '=' is not a valid mount name is a path, as before.
func TestInitDirWithEqualsSign(t *testing.T) {
	dir, keys := initSetup(t)
	t.Chdir(dir)
	out := filepath.Join(dir, "gosftpd.toml")
	runInitOK(t, "--out", out, "--state-dir", filepath.Join(dir, "state"), "--user", "alice", "--authorized-keys", keys, "--dir", "Фото=/sub")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	c := initLoad(t, out)
	if m := c.Mounts["sub"]; len(c.Mounts) != 1 || m == nil || m.Path != filepath.Join(cwd, "Фото=", "sub") {
		t.Errorf("mounts = %+v", c.Mounts)
	}
}

func TestInitStateDir(t *testing.T) {
	dir, keys := initSetup(t)
	out := filepath.Join(dir, "gosftpd.toml")
	state := filepath.Join(dir, "state")
	stdout, _ := runInitOK(t, "--out", out, "--state-dir", state, "--user", "alice", "--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"))
	key := filepath.Join(state, hostkey.DefaultFile)
	if !strings.Contains(stdout, "Host key (generated): "+key+"\n") {
		t.Errorf("output does not name the key %s:\n%s", key, stdout)
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatalf("host key not generated in --state-dir: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("host key mode %04o", fi.Mode().Perm())
	}
	if _, err := hostkey.Load(key); err != nil {
		t.Error(err)
	}
	// Not in the default state directory.
	if def, err := defaultStateDir(); err == nil && fileExists(filepath.Join(def, hostkey.DefaultFile)) {
		t.Errorf("a key was generated in %s too", def)
	}
	if c := initLoad(t, out); !slices.Equal(c.Server.HostKeys, []string{key}) {
		t.Errorf("host_keys = %q", c.Server.HostKeys)
	}
}

func TestInitAuditDirectory(t *testing.T) {
	dir, keys := initSetup(t)
	out := filepath.Join(dir, "gosftpd.toml")
	logs := filepath.Join(dir, "logs")
	args := []string{
		"--out", out, "--state-dir", filepath.Join(dir, "state"), "--user", "alice", "--authorized-keys", keys,
		"--dir", filepath.Join(dir, "inbox"), "--audit-output", filepath.Join(logs, "audit.jsonl"),
	}

	stdout, _ := runInitOK(t, args...)
	fi, err := os.Stat(logs)
	if err != nil || !fi.IsDir() {
		t.Fatalf("audit directory: %v, %v", fi, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("audit directory mode %04o, want 0700", fi.Mode().Perm())
	}
	if want := "Created " + logs + string(filepath.Separator) + " for the audit log\n"; !strings.Contains(stdout, want) {
		t.Errorf("output lacks %q:\n%s", want, stdout)
	}
	initValid(t, out)

	// An existing directory is used as it is.
	stdout, _ = runInitOK(t, append(args, "--force")...)
	if strings.Contains(stdout, "for the audit log") {
		t.Errorf("the directory was created again:\n%s", stdout)
	}

	// When init fails, the directory it created is removed again.
	other := filepath.Join(dir, "other")
	code, _, stderr := execute(t, "init", "--out", out, "--state-dir", filepath.Join(dir, "state"), "--user", "alice", "--authorized-keys", keys,
		"--dir", filepath.Join(dir, "inbox"), "--audit-output", filepath.Join(other, "audit.jsonl"))
	if code != exitUsage || !strings.Contains(stderr, "already exists") {
		t.Errorf("init without --force: exit %d: %s", code, stderr)
	}
	if fileExists(other) {
		t.Errorf("%s is left after a failed init", other)
	}
}

// TestInitForceRefusesInvalid: a person in users.d whose folder is no
// longer shared makes the new file invalid, and it is not written.
func TestInitForceRefusesInvalid(t *testing.T) {
	dir, keys := initSetup(t)
	out := filepath.Join(dir, "gosftpd.toml")
	state := filepath.Join(dir, "state")
	runInitOK(t, "--out", out, "--state-dir", state, "--user", "alice", "--authorized-keys", keys,
		"--dir", "inbox="+filepath.Join(dir, "inbox"), "--dir", "docs="+filepath.Join(dir, "docs"))
	if code, _, stderr := execute(t, "user", "add", "bob", "--key", authorizedKey(newSigner(t)), "--access", "docs=upload", "--write", "--config", out); code != exitOK {
		t.Fatalf("user add: exit %d: %s", code, stderr)
	}
	bob := filepath.Join(dir, "users.d", "bob.toml")
	before, bobBefore := initRead(t, out), initRead(t, bob)
	logs := filepath.Join(dir, "logs")

	for _, extra := range [][]string{
		{"--user", "alice", "--authorized-keys", keys},
		{"--no-user", "--password-logins"}, // as the GUI runs it
	} {
		args := append([]string{
			"init", "--force", "--out", out, "--state-dir", state, "--dir", "inbox=" + filepath.Join(dir, "inbox"),
			"--audit-output", filepath.Join(logs, "audit.jsonl"),
		}, extra...)
		code, stdout, stderr := execute(t, args...)
		if code != exitUsage {
			t.Errorf("%q: exit %d, want %d\n%s%s", extra, code, exitUsage, stdout, stderr)
		}
		for _, want := range []string{
			"Error: " + out + " (not written): 1 problem:\n",
			"  users.bob.access (" + bob + `): unknown mount "docs"` + "\n",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%q: stderr lacks %q:\n%s", extra, want, stderr)
			}
		}
		if after := initRead(t, out); !bytes.Equal(after, before) {
			t.Errorf("%q: the file changed:\n%s", extra, after)
		}
		if !bytes.Equal(initRead(t, bob), bobBefore) {
			t.Errorf("%q: %s changed", extra, bob)
		}
		if tmp := initLeftovers(t, dir); len(tmp) > 0 {
			t.Errorf("%q: temporary files left: %q", extra, tmp)
		}
		if fileExists(logs) {
			t.Errorf("%q: %s is left after a refused init", extra, logs)
		}
	}

	// Once bob loses the folder, the same command works.
	if code, _, stderr := execute(t, "user", "remove", "bob", "--config", out); code != exitOK {
		t.Fatalf("user remove: exit %d: %s", code, stderr)
	}
	runInitOK(t, "--force", "--out", out, "--state-dir", state, "--dir", "inbox="+filepath.Join(dir, "inbox"), "--no-user")
}

// TestInitForceKeeps: --force replaces the file, and keeps users.d/ and the
// host key.
func TestInitForceKeeps(t *testing.T) {
	dir, keys := initSetup(t)
	out := filepath.Join(dir, "gosftpd.toml")
	state := filepath.Join(dir, "state")
	runInitOK(t, "--out", out, "--state-dir", state, "--user", "alice", "--authorized-keys", keys, "--dir", "inbox="+filepath.Join(dir, "inbox"))
	if code, _, stderr := execute(t, "user", "add", "bob", "--key", authorizedKey(newSigner(t)), "--access", "inbox=upload", "--write", "--config", out); code != exitOK {
		t.Fatalf("user add: exit %d: %s", code, stderr)
	}
	usersDir := filepath.Join(dir, "users.d")
	bob := filepath.Join(usersDir, "bob.toml")
	key := filepath.Join(state, hostkey.DefaultFile)
	keyBefore, pubBefore, bobBefore := initRead(t, key), initRead(t, key+".pub"), initRead(t, bob)
	dirBefore, err := os.Stat(usersDir)
	if err != nil {
		t.Fatal(err)
	}

	stdout, _ := runInitOK(t, "--force", "--out", out, "--state-dir", state, "--no-user", "--password-logins",
		"--listen", "127.0.0.1:2222", "--dir", "inbox="+filepath.Join(dir, "inbox"), "--dir", "docs="+filepath.Join(dir, "docs"))
	if !strings.Contains(stdout, "Host key (existing): "+key) || strings.Contains(stdout, "users.d") {
		t.Errorf("output:\n%s", stdout)
	}
	if !bytes.Equal(initRead(t, key), keyBefore) || !bytes.Equal(initRead(t, key+".pub"), pubBefore) {
		t.Error("the host key changed")
	}
	if !bytes.Equal(initRead(t, bob), bobBefore) {
		t.Errorf("%s changed", bob)
	}
	if fi, err := os.Stat(usersDir); err != nil || fi.Mode() != dirBefore.Mode() {
		t.Errorf("users.d: %v, %v; before %v", fi, err, dirBefore.Mode())
	}
	c := initLoad(t, out)
	if len(c.Users) != 1 || c.Users["bob"] == nil || len(c.Mounts) != 2 || !slices.Equal(c.Server.Listen, []string{"127.0.0.1:2222"}) {
		t.Errorf("users %v, mounts %v, listen %q", c.Users, c.Mounts, c.Server.Listen)
	}
	if fi, err := os.Stat(out); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("config file: %v, %v", fi, err)
	}
	if tmp := initLeftovers(t, dir); len(tmp) > 0 {
		t.Errorf("temporary files left: %q", tmp)
	}
	initValid(t, out)
}

// TestInitForceSymlink: --force replaces by rename, which would replace a
// link instead of the file it points to.
func TestInitForceSymlink(t *testing.T) {
	dir, keys := initSetup(t)
	target := filepath.Join(dir, "target.toml")
	writeFile(t, target, "# mine\n")
	out := filepath.Join(dir, "gosftpd.toml")
	if err := os.Symlink(target, out); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	code, _, stderr := execute(t, "init", "--force", "--out", out, "--state-dir", filepath.Join(dir, "state"), "--user", "alice", "--authorized-keys", keys, "--dir", filepath.Join(dir, "inbox"))
	if code != exitUsage || !strings.Contains(stderr, "is a symbolic link, which --force would replace with a file") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if fi, err := os.Lstat(out); err != nil || fi.Mode()&os.ModeSymlink == 0 || string(initRead(t, target)) != "# mine\n" {
		t.Errorf("the link or its file changed: %v, %v", fi, err)
	}
}
