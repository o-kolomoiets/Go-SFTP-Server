// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// newConfig returns a configuration loaded from file (a slash path) with
// the include patterns, a writable mount inbox at /srv/sftp/inbox and the
// audit log on stdout.
func newConfig(file string, include ...string) *config.Config {
	c := config.Default()
	if file != "" {
		c.File = native(file)
		c.Files = []string{c.File}
	}
	c.Include = include
	c.AddMount("inbox", native("/srv/sftp/inbox"))
	return c
}

// loaded records include files as config.Load does.
func loaded(c *config.Config, files ...string) {
	for _, f := range files {
		c.Files = append(c.Files, native(f))
	}
}

func addUser(c *config.Config, name, keysFile string) {
	c.Users[name] = &config.User{AuthorizedKeysFile: native(keysFile), Access: map[string]string{"inbox": "full"}}
}

// input opens every mount of c in m, as Start gets them.
func input(t *testing.T, m *memFS, c *config.Config) Input {
	t.Helper()
	in := Input{Config: c, FS: m, ProcSelfFD: -1, Mounts: []MountDir{}}
	for _, name := range sortedKeys(c.Mounts) {
		dir := filepath.Clean(c.Mounts[name].Path)
		if filepath.Base(dir) == "{user}" {
			dir = filepath.Dir(dir)
		}
		info, err := m.Stat(dir)
		if err != nil {
			t.Fatalf("mount %s: %v", name, err)
		}
		in.Mounts = append(in.Mounts, MountDir{Name: name, FD: -1, Dev: info.Dev, Ino: info.Ino})
	}
	return in
}

func compute(t *testing.T, in Input) Plan {
	t.Helper()
	p, err := Compute(in)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return p
}

// describe lists rules as "dir /etc/gosftpd read_file,read_dir" or
// "file /etc/x read_file", with slash paths.
func describe(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		kind := "file"
		if r.Dir {
			kind = "dir"
		}
		out = append(out, kind+" "+slash(r.Path)+" "+r.Rights.String())
	}
	return out
}

// checkPlan compares the rules and the warnings; a warning matches when
// it contains want's text with native paths.
func checkPlan(t *testing.T, p Plan, rules []string, warnings ...string) {
	t.Helper()
	got := describe(p.Rules)
	slices.Sort(rules)
	slices.Sort(got)
	if !slices.Equal(got, rules) {
		t.Errorf("rules:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(rules, "\n  "))
	}
	if len(p.Warnings) != len(warnings) {
		t.Errorf("warnings:\n  %s\nwant %d", strings.Join(p.Warnings, "\n  "), len(warnings))
		return
	}
	for i, w := range warnings {
		if got := slashText(p.Warnings[i]); !strings.Contains(got, w) {
			t.Errorf("warning %d:\n  %s\nwant it to contain:\n  %s", i, got, w)
		}
	}
}

// slashText writes the native paths in a message with slashes.
func slashText(s string) string {
	if runtime.GOOS == "windows" {
		return strings.ReplaceAll(strings.ReplaceAll(s, `C:\`, "/"), `\`, "/")
	}
	return s
}

const (
	rw      = "read_file,read_dir,write_file,truncate,make_reg,make_dir,remove_file,remove_dir,refer"
	ro      = "read_file,read_dir"
	rfile   = "read_file"
	waudit  = "write_file,make_reg"
	wfile   = "write_file"
	rdir    = "read_dir"
	inbox   = "dir /srv/sftp/inbox " + rw
	shared  = "; replaced by rename, it cannot be read until a restart"
	rotWarn = "rotation by rename (logrotate's create, as in docs/audit-log.md) makes the audit log unwritable until a restart; with on_error = fail-closed every new connection is refused; use copytruncate or a directory of its own"
)

// TestPackagedLayout: the files of packaging/ as installed. /etc/gosftpd
// with users.d and ca.pub, /var/lib/gosftpd with a host key, its .pub and
// a stale temporary file, and /var/log/gosftpd are dedicated.
func TestPackagedLayout(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).
		files("/etc/gosftpd/config.toml", "/etc/gosftpd/ca.pub", "/etc/gosftpd/users.d/alice.toml").
		files("/var/lib/gosftpd/ssh_host_ed25519_key", "/var/lib/gosftpd/ssh_host_ed25519_key.pub", "/var/lib/gosftpd/.ssh_host_ed25519_key.tmp-1").
		files("/var/log/gosftpd/audit.jsonl").
		dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
	loaded(c, "/etc/gosftpd/users.d/alice.toml")
	c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
	c.Server.HostKeys = []string{native("/var/lib/gosftpd/ssh_host_ed25519_key")}
	c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
	in := input(t, m, c)
	in.Home = native("/") // the packaged user's home
	checkPlan(t, compute(t, in), []string{
		"dir /etc/gosftpd " + ro,
		"dir /var/lib/gosftpd " + rfile,
		"dir /var/log/gosftpd " + waudit,
		inbox,
	})
}

func TestDedication(t *testing.T) {
	t.Parallel()
	t.Run("reference layout", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).
			files("/etc/gosftpd/config.toml", "/etc/gosftpd/users.d/bob.toml", "/etc/gosftpd/keys/alice.pub").
			dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
		loaded(c, "/etc/gosftpd/users.d/bob.toml")
		addUser(c, "alice", "/etc/gosftpd/keys/alice.pub")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})
	})
	t.Run("users.d holds an unnamed file", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).
			files("/etc/gosftpd/config.toml", "/etc/gosftpd/ca.pub", "/etc/gosftpd/users.d/bob.toml", "/etc/gosftpd/users.d/README").
			dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
		loaded(c, "/etc/gosftpd/users.d/bob.toml")
		c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
		checkPlan(t, compute(t, input(t, m, c)), []string{
			"file /etc/gosftpd/config.toml " + rfile,
			"file /etc/gosftpd/ca.pub " + rfile,
			"dir /etc/gosftpd/users.d " + rdir,
			"file /etc/gosftpd/users.d/bob.toml " + rfile,
			inbox,
		},
			"configuration: Landlock covers only the file config.toml in /etc/gosftpd, which holds users.d"+shared,
			"include: Landlock covers only the include files found at start in /etc/gosftpd/users.d, which holds README; a new or renamed include file needs a restart",
			"auth.trusted_user_ca_keys_file: Landlock covers only the file ca.pub in /etc/gosftpd, which holds users.d"+shared,
		)
	})
	t.Run("a subdirectory holding no named entry", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/archive/old.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"file /etc/gosftpd/config.toml " + rfile, inbox},
			"configuration: Landlock covers only the file config.toml in /etc/gosftpd, which holds archive"+shared)
	})
	t.Run("zero-configuration ~/.ssh", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).
			files("/home/u/.ssh/authorized_keys", "/home/u/.ssh/id_ed25519", "/home/u/.ssh/id_ed25519.pub").
			files("/home/u/.config/gosftpd/ssh_host_ed25519_key", "/home/u/.config/gosftpd/ssh_host_ed25519_key.pub").
			dirs("/home/u/share")
		c := config.Default()
		c.AddMount("share", native("/home/u/share"))
		c.AnyUser = &config.ZeroConfigUser{AuthorizedKeysFile: native("/home/u/.ssh/authorized_keys")}
		c.Server.HostKeys = []string{native("/home/u/.config/gosftpd/ssh_host_ed25519_key")}
		in := input(t, m, c)
		in.Home = native("/home/u")
		checkPlan(t, compute(t, in), []string{
			"file /home/u/.ssh/authorized_keys " + rfile,
			"dir /home/u/.config/gosftpd " + rfile,
			"dir /home/u/share " + rw,
		}, "--authorized-keys: Landlock covers only the file authorized_keys in /home/u/.ssh, which is a .ssh directory"+shared)
	})
	t.Run("configuration in the home directory", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/home/u/gosftpd.toml", "/home/u/users.d/a.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/home/u/gosftpd.toml", "users.d/*.toml")
		loaded(c, "/home/u/users.d/a.toml")
		in := input(t, m, c)
		in.Home = native("/home/u")
		checkPlan(t, compute(t, in), []string{"file /home/u/gosftpd.toml " + rfile, "dir /home/u/users.d " + ro, inbox},
			"configuration: Landlock covers only the file gosftpd.toml in /home/u, which is the home directory of the user running gosftpd"+shared)
	})
	t.Run("home directory found by identity", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/usr/home/u/gosftpd.toml").symlink("/home", "/usr/home").dirs("/srv/sftp/inbox")
		c := newConfig("/usr/home/u/gosftpd.toml")
		in := input(t, m, c)
		in.Home = native("/home/u")
		checkPlan(t, compute(t, in), []string{"file /usr/home/u/gosftpd.toml " + rfile, inbox},
			"which is the home directory of the user running gosftpd")
	})
	t.Run("a directory that cannot be listed", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml").noList("/etc/gosftpd").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"file /etc/gosftpd/config.toml " + rfile, inbox},
			"configuration: Landlock covers only the file config.toml in /etc/gosftpd, which cannot be listed"+shared)
	})
	t.Run("a configuration at the root", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/gosftpd.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/gosftpd.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"file /gosftpd.toml " + rfile, inbox},
			"which is the root directory"+shared)
	})
	t.Run("Kubernetes ConfigMap volume", func(t *testing.T) {
		t.Parallel()
		const ts = "..2026_10_12_10_00_00.123456789"
		m := newMemFS(t).
			files("/etc/gosftpd/"+ts+"/config.toml", "/etc/gosftpd/"+ts+"/ca.pub", "/etc/gosftpd/..2026_10_11_09_00_00.42/config.toml").
			symlink("/etc/gosftpd/..data", ts).symlink("/etc/gosftpd/..data_tmp", ts).
			symlink("/etc/gosftpd/config.toml", "..data/config.toml").symlink("/etc/gosftpd/ca.pub", "..data/ca.pub").
			dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml")
		c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})
	})
	t.Run("editor and user add temporary files", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).
			files("/etc/gosftpd/config.toml", "/etc/gosftpd/config.toml~", "/etc/gosftpd/.config.toml.swp", "/etc/gosftpd/.config.toml.swx",
				"/etc/gosftpd/#config.toml#", "/etc/gosftpd/.#config.toml", "/etc/gosftpd/config.toml.bak").
			files("/etc/gosftpd/users.d/alice.toml", "/etc/gosftpd/users.d/.alice.toml.3f2a9c.tmp", "/etc/gosftpd/users.d/alice.toml.orig",
				"/etc/gosftpd/users.d/.alice.toml.swp").
			dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
		loaded(c, "/etc/gosftpd/users.d/alice.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})

		// gosftpd's own writes of a host key, its .pub and certificate.
		const k = "/etc/gosftpd/ssh_host_ed25519_key"
		m.files(k, k+".pub", "/etc/gosftpd/.ssh_host_ed25519_key.tmp-1", "/etc/gosftpd/.ssh_host_ed25519_key.pub.tmp-2",
			"/etc/gosftpd/.ssh_host_ed25519_key-cert.pub.tmp-3", "/etc/gosftpd/.ssh_host_ed25519_key.next-cert.pub.tmp-4")
		c.Server.HostKeys = []string{native(k)}
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})

		// Not derived: another name, a swap file of another length, a
		// temporary file of a file that is not named.
		for _, f := range []string{"/etc/gosftpd/notes.txt", "/etc/gosftpd/.config.toml.swpx", "/etc/gosftpd/users.d/.carol.toml.1.tmp", "/etc/gosftpd/.other.tmp-1"} {
			m2 := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/users.d/alice.toml", f).dirs("/srv/sftp/inbox")
			p := compute(t, input(t, m2, c))
			if slices.Contains(describe(p.Rules), "dir /etc/gosftpd "+ro) {
				t.Errorf("%s: /etc/gosftpd is dedicated", f)
			}
		}
	})
	t.Run("lost+found at the root of a file system", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).
			volume("/var/lib/gosftpd").dirs("/var/lib/gosftpd/lost+found").files("/var/lib/gosftpd/ssh_host_ed25519_key").
			volume("/var/log/gosftpd").dirs("/var/log/gosftpd/lost+found").files("/var/log/gosftpd/audit.jsonl").
			files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml")
		c.Server.HostKeys = []string{native("/var/lib/gosftpd/ssh_host_ed25519_key")}
		c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
		checkPlan(t, compute(t, input(t, m, c)), []string{
			"dir /etc/gosftpd " + ro, "dir /var/lib/gosftpd " + rfile, "dir /var/log/gosftpd " + waudit, inbox,
		})

		// Elsewhere lost+found is an entry like any other.
		m = newMemFS(t).dirs("/var/lib/gosftpd/lost+found").files("/var/lib/gosftpd/ssh_host_ed25519_key", "/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
		checkPlan(t, compute(t, input(t, m, c)), []string{
			"dir /etc/gosftpd " + ro, "file /var/lib/gosftpd/ssh_host_ed25519_key " + rfile, inbox,
		}, "server.host_keys: Landlock covers only the file ssh_host_ed25519_key in /var/lib/gosftpd, which holds lost+found", "audit.output")
	})
	t.Run("up to three entries are named", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd.toml", "/etc/group", "/etc/hosts", "/etc/passwd", "/etc/shadow", "/etc/sudoers").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"file /etc/gosftpd.toml " + rfile, inbox},
			"configuration: Landlock covers only the file gosftpd.toml in /etc, which holds group, hosts, passwd and 2 more"+shared)
	})
	t.Run("symlink loop", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/keys/a.pub").symlink("/etc/gosftpd/keys/self", "/etc/gosftpd/keys").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml")
		addUser(c, "a", "/etc/gosftpd/keys/a.pub")
		p := compute(t, input(t, m, c))
		if slices.Contains(describe(p.Rules), "dir /etc/gosftpd "+ro) {
			t.Errorf("a directory holding a loop is dedicated: %v", describe(p.Rules))
		}
	})
}

func TestIncludes(t *testing.T) {
	t.Parallel()
	t.Run("absolute pattern with a wildcard directory", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml", "/srv/teams/a/users.toml", "/srv/teams/b/users.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", native("/srv/teams/*/users.toml"))
		loaded(c, "/srv/teams/a/users.toml", "/srv/teams/b/users.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, "dir /srv/teams " + ro, inbox})
	})
	t.Run("a team directory holds an unnamed file", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml", "/srv/teams/a/users.toml", "/srv/teams/b/users.toml", "/srv/teams/b/notes.txt").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", native("/srv/teams/*/users.toml"))
		loaded(c, "/srv/teams/a/users.toml", "/srv/teams/b/users.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{
			"dir /etc/gosftpd " + ro,
			"dir /srv/teams " + rdir,
			"file /srv/teams/a/users.toml " + rfile,
			"file /srv/teams/b/users.toml " + rfile,
			inbox,
		}, "include: Landlock covers only the include files found at start in /srv/teams, which holds b; a new or renamed include file needs a restart")
	})
	t.Run("the main file's directory as the leading directory", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/alice.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", "*.toml")
		loaded(c, "/etc/gosftpd/alice.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})
	})
	t.Run("a directory missing at start", func(t *testing.T) {
		t.Parallel()
		// Covered by the dedicated directory of the main file: no warning.
		m := newMemFS(t).files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})

		m.files("/etc/gosftpd/notes.txt")
		checkPlan(t, compute(t, input(t, m, c)), []string{"file /etc/gosftpd/config.toml " + rfile, inbox},
			"configuration: Landlock covers only the file config.toml in /etc/gosftpd, which holds notes.txt",
			"include: /etc/gosftpd/users.d does not exist: the first file added there needs a restart")
	})
	t.Run("a leading directory at the root", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
		c := newConfig("/etc/gosftpd/config.toml", native("/*.toml"))
		if _, err := Compute(input(t, m, c)); !rootError(err, "include") {
			t.Errorf("Compute = %v, want a rule on / for include", err)
		}
	})
}

func rootError(err error, key string) bool {
	re, ok := errors.AsType[*RootError](err)
	return ok && re.Key == key
}

// TestSymlinksIntoAnotherTree: a named entry that is a symlink resolving
// outside its dedicated directory gets a rule on its target, and a start
// warning.
func TestSymlinksIntoAnotherTree(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).
		files("/nix/store/abc-gosftpd/config.toml", "/nix/store/def-ca/ca.pub", "/srv/conf/users.d/bob.toml").
		symlink("/etc/gosftpd/config.toml", "/nix/store/abc-gosftpd/config.toml").
		symlink("/etc/gosftpd/ca.pub", "/nix/store/def-ca/ca.pub").
		symlink("/etc/gosftpd/users.d", "/srv/conf/users.d").
		files("/etc/gosftpd/keys/alice.pub").symlink("/etc/gosftpd/keys/carol.pub", "alice.pub").
		dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
	loaded(c, "/etc/gosftpd/users.d/bob.toml")
	c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
	addUser(c, "alice", "/etc/gosftpd/keys/alice.pub")
	addUser(c, "carol", "/etc/gosftpd/keys/carol.pub") // inside its directory: no warning
	checkPlan(t, compute(t, input(t, m, c)), []string{
		"dir /etc/gosftpd " + ro,
		"file /nix/store/abc-gosftpd/config.toml " + rfile,
		"file /nix/store/def-ca/ca.pub " + rfile,
		"dir /srv/conf/users.d " + ro,
		inbox,
	},
		"configuration: /etc/gosftpd/config.toml is a link to /nix/store/abc-gosftpd/config.toml, outside /etc/gosftpd, so Landlock covers only that target; re-pointed, the link cannot be read until a restart",
		"include: /etc/gosftpd/users.d is a link to /srv/conf/users.d, outside /etc/gosftpd",
		"auth.trusted_user_ca_keys_file: /etc/gosftpd/ca.pub is a link to /nix/store/def-ca/ca.pub, outside /etc/gosftpd",
	)
}

// TestHostKeySiblings: in a shared directory each existing sibling gets a
// file rule; one warning names them.
func TestHostKeySiblings(t *testing.T) {
	t.Parallel()
	const k = "/etc/ssh/ssh_host_ed25519_key"
	m := newMemFS(t).
		files(k, k+".pub", k+".next", k+".next.pub", k+"-cert.pub", k+".next-cert.pub", "/etc/ssh/moduli", "/etc/ssh/ssh_config", "/etc/ssh/sshd_config").
		files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Server.HostKeys = []string{native(k)}
	checkPlan(t, compute(t, input(t, m, c)), []string{
		"dir /etc/gosftpd " + ro,
		"file " + k + " " + rfile,
		"file " + k + ".next " + rfile,
		"file " + k + "-cert.pub " + rfile,
		"file " + k + ".next-cert.pub " + rfile,
		inbox,
	}, "server.host_keys: Landlock covers only the files ssh_host_ed25519_key, ssh_host_ed25519_key.next, ssh_host_ed25519_key-cert.pub and ssh_host_ed25519_key.next-cert.pub in /etc/ssh, which holds moduli, ssh_config and sshd_config; replaced by rename, such a file cannot be read until a restart")
}

func TestAuditRow(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) (*memFS, *config.Config) {
		t.Helper()
		m := newMemFS(t).files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
		return m, newConfig("/etc/gosftpd/config.toml")
	}
	t.Run("in a shared directory", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		m.files("/var/log/gosftpd.jsonl", "/var/log/syslog", "/var/log/auth.log")
		c.Audit.Output = native("/var/log/gosftpd.jsonl")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, "file /var/log/gosftpd.jsonl " + wfile, inbox},
			"audit.output: Landlock covers only the file gosftpd.jsonl in /var/log, which holds auth.log and syslog: "+rotWarn)
	})
	t.Run("logrotate's extension and olddir", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		m.files("/var/log/gosftpd/audit.jsonl", "/var/log/gosftpd/audit-20261011.jsonl", "/var/log/gosftpd/audit.jsonl.1.gz",
			"/var/log/gosftpd/old/audit.jsonl.2.gz", "/var/log/gosftpd/old/audit-20261001.jsonl").dirs("/var/log/gosftpd/empty")
		c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, "dir /var/log/gosftpd " + waudit, inbox})

		m.files("/var/log/gosftpd/old/notes.txt")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, "file /var/log/gosftpd/audit.jsonl " + wfile, inbox},
			"audit.output: Landlock covers only the file audit.jsonl in /var/log/gosftpd, which holds old: ")
	})
	t.Run("next to the configuration", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		m.files("/etc/gosftpd/audit.jsonl", "/etc/gosftpd/users.d/a.toml", "/etc/gosftpd/ssh_host_ed25519_key")
		c.Include = []string{"users.d/*.toml"}
		loaded(c, "/etc/gosftpd/users.d/a.toml")
		c.Server.HostKeys = []string{native("/etc/gosftpd/ssh_host_ed25519_key")}
		c.Audit.Output = native("/etc/gosftpd/audit.jsonl")
		// Write rights on the audit file only: neither the configuration
		// nor a host key can be written, nothing created in users.d.
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, "file /etc/gosftpd/audit.jsonl " + wfile, inbox},
			"audit.output: Landlock covers only the file audit.jsonl in /etc/gosftpd, which holds config.toml, ssh_host_ed25519_key and users.d: "+rotWarn)
	})
	t.Run("not created yet (config validate)", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		m.files("/var/log/syslog")
		c.Audit.Output = native("/var/log/gosftpd.jsonl")
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox}, "audit.output: Landlock covers only the file gosftpd.jsonl in /var/log, which holds syslog")
	})
	t.Run("a symlink out of its directory", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		m.files("/srv/audit/audit.jsonl").symlink("/var/log/gosftpd/audit.jsonl", "/srv/audit/audit.jsonl")
		c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
		checkPlan(t, compute(t, input(t, m, c)), []string{
			"dir /etc/gosftpd " + ro, "dir /var/log/gosftpd " + waudit, "file /srv/audit/audit.jsonl " + wfile, inbox,
		}, "audit.output: /var/log/gosftpd/audit.jsonl is a link to /srv/audit/audit.jsonl, outside /var/log/gosftpd")
	})
	t.Run("stdout", func(t *testing.T) {
		t.Parallel()
		m, c := base(t)
		checkPlan(t, compute(t, input(t, m, c)), []string{"dir /etc/gosftpd " + ro, inbox})
	})
}

func TestMountRules(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).dirs("/srv/ro", "/srv/home", "/srv/rohome", "/srv/created")
	c := config.Default()
	c.AddMount("ro", native("/srv/ro")).ReadOnly = true
	c.AddMount("home", native("/srv/home/{user}"))
	h := c.AddMount("rohome", native("/srv/rohome/{user}"))
	h.ReadOnly, h.Create = true, true
	c.AddMount("my docs", native("/srv/created")).Create = true
	in := input(t, m, c)
	for i := range in.Mounts {
		if in.Mounts[i].Name == "my docs" {
			in.Mounts[i].FD = 7
		}
	}
	p := compute(t, in)
	checkPlan(t, p, []string{
		"dir /srv/created " + rw,
		"dir /srv/home " + rw,
		"dir /srv/ro " + ro,
		"dir /srv/rohome read_file,read_dir,make_dir",
	})
	for _, r := range p.Rules {
		want := r.Path
		if slash(r.Path) == "/srv/created" {
			want = "/proc/self/fd/7"
		}
		if r.Open != want {
			t.Errorf("%s: Open = %q, want %q", slash(r.Path), r.Open, want)
		}
		if slash(r.Path) == "/srv/created" && r.For[0] != `mounts."my docs".path` {
			t.Errorf("For = %v", r.For)
		}
	}

	t.Run("swapped after it was opened", func(t *testing.T) {
		t.Parallel()
		in := input(t, m, c)
		in.Mounts[1].Ino++
		if _, err := Compute(in); err == nil || !strings.Contains(err.Error(), "no longer the directory the mount opened") {
			t.Errorf("Compute = %v", err)
		}
	})
	t.Run("not open", func(t *testing.T) {
		t.Parallel()
		in := input(t, m, c)
		in.Mounts = in.Mounts[1:]
		if _, err := Compute(in); err == nil || !strings.Contains(err.Error(), "not open") {
			t.Errorf("Compute = %v", err)
		}
	})
	t.Run("config validate", func(t *testing.T) {
		t.Parallel()
		m := newMemFS(t).dirs("/srv/ro")
		in := Input{Config: c, FS: m, ProcSelfFD: -1}
		checkPlan(t, compute(t, in), []string{"dir /srv/ro " + ro})
	})
	t.Run("at the root", func(t *testing.T) {
		t.Parallel()
		for _, path := range []string{"/", "/{user}"} {
			c := config.Default()
			c.AddMount("root", native(path))
			_, err := Compute(input(t, newMemFS(t), c))
			if !rootError(err, "mounts.root.path") || err.Error() != "mounts.root.path: a rule would be placed on /" {
				t.Errorf("%s: Compute = %v", path, err)
			}
		}
		m := newMemFS(t).symlink("/srv/all", "/")
		c := config.Default()
		c.AddMount("all", native("/srv/all"))
		c.AnyUser = &config.ZeroConfigUser{}
		if _, err := Compute(input(t, m, c)); !rootError(err, "--dir all") {
			t.Errorf("a symlink to /: Compute = %v", err)
		}
		// config validate finds it by the path as well.
		in := input(t, m, c)
		in.Mounts = nil
		if _, err := Compute(in); !rootError(err, "--dir all") {
			t.Errorf("a symlink to / without open mounts: Compute = %v", err)
		}
	})
}

// TestDedupe: one rule per path, with the rights of all; rules below a
// directory rule that gives all their rights are left out.
func TestDedupe(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/notes.txt", "/etc/gosftpd/keys.pub", "/etc/gosftpd/ca.pub").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	addUser(c, "alice", "/etc/gosftpd/keys.pub")
	addUser(c, "bob", "/etc/gosftpd/keys.pub")
	c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
	c.Auth.RevokedKeysFile = native("/etc/gosftpd/ca.pub")
	p := compute(t, input(t, m, c))
	checkPlan(t, p, []string{
		"file /etc/gosftpd/config.toml " + rfile, "file /etc/gosftpd/keys.pub " + rfile, "file /etc/gosftpd/ca.pub " + rfile, inbox,
	}, "configuration:", "users.alice.authorized_keys_file:", "users.bob.authorized_keys_file:", "auth.trusted_user_ca_keys_file:", "auth.revoked_keys_file:")
	for _, r := range p.Rules {
		if slash(r.Path) == "/etc/gosftpd/keys.pub" && !slices.Equal(r.For, []string{"users.alice.authorized_keys_file", "users.bob.authorized_keys_file"}) {
			t.Errorf("For = %v", r.For)
		}
	}

	rules := dedupe([]Rule{
		{Path: "/a", Open: "/a", Rights: ReadFile, Dir: true},
		{Path: "/a", Open: "/proc/self/fd/3", Rights: ReadDir, Dir: true},
		{Path: "/a/b", Rights: ReadFile, Dir: true},
		{Path: "/a/c", Rights: WriteFile},
		{Path: "/ab", Rights: ReadFile},
	})
	if got := describe(rules); !slices.Equal(got, []string{"dir /a read_file,read_dir", "file /a/c write_file", "file /ab read_file"}) {
		t.Errorf("dedupe = %v", got)
	}
	if rules[0].Open != "/proc/self/fd/3" {
		t.Errorf("Open = %q: the descriptor does not win", rules[0].Open)
	}
}

// TestCoverageRule: only in -cover builds, by the build information.
func TestCoverageRule(t *testing.T) {
	t.Parallel()
	cover := []debug.BuildSetting{{Key: "-compiler", Value: "gc"}, {Key: "-cover", Value: "true"}}
	for _, tc := range []struct {
		settings  []debug.BuildSetting
		flag, env string
		want      string
	}{
		{cover, "/tmp/flag", "/tmp/env", "/tmp/flag"},
		{cover, "", "/tmp/env", "/tmp/env"},
		{cover[:1], "/tmp/flag", "/tmp/env", ""},
		{[]debug.BuildSetting{{Key: "-cover", Value: "false"}}, "", "/tmp/env", ""},
		{nil, "", "/tmp/env", ""},
	} {
		if got := coverDirOf(tc.settings, tc.flag, tc.env); got != tc.want {
			t.Errorf("coverDirOf(%v, %q, %q) = %q, want %q", tc.settings, tc.flag, tc.env, got, tc.want)
		}
	}

	m := newMemFS(t).files("/etc/gosftpd/config.toml", "/var/lib/gosftpd/k").dirs("/srv/sftp/inbox", "/tmp/cover")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Server.HostKeys = []string{native("/var/lib/gosftpd/k")}
	for dir, want := range map[string]bool{"/tmp/cover": true, "/": false, "/var/lib/gosftpd": false, "/tmp/missing": false, "/etc/gosftpd/config.toml": false} {
		in := input(t, m, c)
		in.CoverDir = native(dir)
		p := compute(t, in)
		has := slices.ContainsFunc(p.Rules, func(r Rule) bool { return slices.Contains(r.For, keyCoverage) })
		if has != want {
			t.Errorf("CoverDir %s: rule %v, want %v (%v)", dir, has, want, describe(p.Rules))
		}
		if has && !slices.Contains(describe(p.Rules), "dir /tmp/cover read_file,read_dir,write_file,make_reg,remove_file") {
			t.Errorf("coverage rule: %v", describe(p.Rules))
		}
	}
}

func TestRightsString(t *testing.T) {
	t.Parallel()
	for r, want := range map[Rights]string{0: "none", ReadFile | ReadDir: "read_file,read_dir", MountRW: rw, Rights(1): "0x1"} {
		if got := r.String(); got != want {
			t.Errorf("%d: %q, want %q", uint64(r), got, want)
		}
	}
}
