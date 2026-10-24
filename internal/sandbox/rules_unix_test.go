// SPDX-License-Identifier: Apache-2.0

//go:build unix

package sandbox

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// linuxFS is the part of a Linux system that every Linux plan reads.
func linuxFS(t *testing.T) *memFS {
	t.Helper()
	return newMemFS(t).dirs("/proc/self", "/srv/sftp/inbox").files("/etc/gosftpd/config.toml")
}

// TestLinuxRows: /proc/self through its descriptor, the name-resolution
// files (resolv.conf's directory too when it lies under /run), and paths
// under /dev and /proc that never get a rule.
func TestLinuxRows(t *testing.T) {
	t.Parallel()
	m := linuxFS(t).
		files("/etc/hosts", "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf").
		symlink("/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
	c := newConfig("/etc/gosftpd/config.toml")
	in := input(t, m, c)
	in.Linux, in.ProcSelfFD = true, 9
	p := compute(t, in)
	checkPlan(t, p, []string{
		"dir /etc/gosftpd " + ro,
		"dir /proc/self " + ro,
		"file /etc/hosts " + rfile,
		"dir /run/systemd/resolve " + rfile, // which covers the stub's own rule
		inbox,
	})
	for _, r := range p.Rules {
		if r.Path == "/proc/self" && r.Open != "/proc/self/fd/9" {
			t.Errorf("/proc/self is added through %q", r.Open)
		}
	}

	// A resolv.conf of its own: a file rule, no directory.
	m = linuxFS(t).files("/etc/resolv.conf", "/etc/nsswitch.conf")
	in = input(t, m, c)
	in.Linux = true
	checkPlan(t, compute(t, in), []string{
		"dir /etc/gosftpd " + ro, "dir /proc/self " + ro, "file /etc/resolv.conf " + rfile, "file /etc/nsswitch.conf " + rfile, inbox,
	})

	// Directly in /run, it does not open /run.
	m = linuxFS(t).files("/run/resolv.conf").symlink("/etc/resolv.conf", "/run/resolv.conf")
	in = input(t, m, c)
	in.Linux = true
	checkPlan(t, compute(t, in), []string{"dir /etc/gosftpd " + ro, "dir /proc/self " + ro, "file /run/resolv.conf " + rfile, inbox})
}

// TestDevTrustedFiles: an authorized_keys file that is /dev/null, a link
// to it, a pipe of --authorized-keys <(...), and the audit log on stderr
// get no rule; neither does a mount under /dev.
func TestDevTrustedFiles(t *testing.T) {
	t.Parallel()
	m := linuxFS(t).device("/dev/null").symlink("/dev/fd", "/proc/self/fd").symlink("/dev/stderr", "/proc/self/fd/2").
		symlink("/etc/gosftpd/keys/bob.pub", "/dev/null").files("/etc/gosftpd/keys/carol.pub").dirs("/dev/shm/drop")
	c := newConfig("/etc/gosftpd/config.toml")
	addUser(c, "alice", "/dev/null")
	addUser(c, "bob", "/etc/gosftpd/keys/bob.pub")
	addUser(c, "carol", "/etc/gosftpd/keys/carol.pub")
	c.Audit.Output = "/dev/stderr"
	c.AddMount("shm", "/dev/shm/drop")
	in := input(t, m, c)
	in.Linux = true
	checkPlan(t, compute(t, in), []string{"dir /etc/gosftpd " + ro, "dir /proc/self " + ro, inbox},
		`mounts.shm.path: /dev/shm/drop is under /dev or /proc, which never get a Landlock rule: the mount cannot be used`)

	z := config.Default()
	z.AddMount("inbox", "/srv/sftp/inbox")
	z.AnyUser = &config.ZeroConfigUser{AuthorizedKeysFile: "/dev/fd/63"}
	in = input(t, m, z)
	in.Linux = true
	checkPlan(t, compute(t, in), []string{"dir /proc/self " + ro, inbox})

	// The same paths elsewhere than on Linux are files like any other.
	in.Linux = false
	m.files("/proc/self/fd/63")
	if p := compute(t, in); !slices.Contains(describe(p.Rules), "dir /proc/self/fd "+rfile) {
		t.Errorf("without Linux: %v", describe(p.Rules))
	}
}

// TestAtmozUnderDev: an atmoz directory that is a link into /dev gets no
// rule, and the warning names it by its path.
func TestAtmozUnderDev(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).dirs("/proc/self", "/home/foo/upload", "/dev/shm").symlink("/home/foo/dev", "/dev/shm")
	c := config.Default()
	c.Atmoz = true
	c.AddMount("atmoz1", "/home/foo/upload").Display = "upload"
	c.AddMount("atmoz2", "/home/foo/dev").Display = "dev"
	in := input(t, m, c)
	in.Linux = true
	checkPlan(t, compute(t, in), []string{"dir /proc/self " + ro, "dir /home/foo/upload " + rw},
		"atmoz directory /home/foo/dev: /home/foo/dev resolves to /dev/shm under /dev or /proc, which never get a Landlock rule: the mount cannot be used; make it a directory, or mount one there")
}

// TestEphemeralUnderDev: with $TMPDIR under /dev, or a link there, serve
// --ephemeral's directory gets no rule, and under Landlock gosftpd could
// neither remove its client key nor serve its data there: the start fails
// and says to set TMPDIR elsewhere, also with --dir serving another
// directory.
func TestEphemeralUnderDev(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).dirs("/proc/self", "/dev/shm/gosftpd-ephemeral-1/data", "/srv/share").symlink("/tmp/shm", "/dev/shm")
	const why = " under /dev or /proc, which never get a Landlock rule; set TMPDIR to another directory"
	for _, tt := range []struct{ dir, mount, want string }{
		{"/dev/shm/gosftpd-ephemeral-1", "/dev/shm/gosftpd-ephemeral-1/data", "--ephemeral: /dev/shm/gosftpd-ephemeral-1 is" + why},
		{"/dev/shm/gosftpd-ephemeral-1", "/srv/share", "--ephemeral: /dev/shm/gosftpd-ephemeral-1 is" + why},
		{"/tmp/shm/gosftpd-ephemeral-1", "/tmp/shm/gosftpd-ephemeral-1/data", "--ephemeral: /tmp/shm/gosftpd-ephemeral-1 resolves to /dev/shm/gosftpd-ephemeral-1" + why},
		{"/tmp/shm/gosftpd-ephemeral-1", "/srv/share", "--ephemeral: /tmp/shm/gosftpd-ephemeral-1 resolves to /dev/shm/gosftpd-ephemeral-1" + why},
	} {
		c := config.Default()
		c.EphemeralDir = tt.dir
		c.AddMount(filepath.Base(tt.mount), tt.mount)
		in := input(t, m, c)
		in.Linux = true
		if p, err := Compute(in); err == nil || err.Error() != tt.want {
			t.Errorf("%s, mount %s: Compute = %v, %v\nwant %s", tt.dir, tt.mount, describe(p.Rules), err, tt.want)
		}
	}
}

// TestResolverWarnings: a name-resolution file replaced after start is
// reported; a systemd-resolved stub replaced inside its /run directory
// stays covered.
func TestResolverWarnings(t *testing.T) {
	t.Parallel()
	m := linuxFS(t).files("/etc/hosts", "/run/systemd/resolve/stub-resolv.conf").
		symlink("/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
	c := newConfig("/etc/gosftpd/config.toml")
	in := input(t, m, c)
	in.Linux = true
	rs := applied(t, in)
	if w := rs.ResolverWarnings(); len(w) != 0 {
		t.Errorf("at start: %v", w)
	}
	m.replace("/run/systemd/resolve/stub-resolv.conf")
	if w := rs.ResolverWarnings(); len(w) != 0 {
		t.Errorf("the stub replaced in /run: %v", w)
	}
	m.replace("/etc/hosts").remove("/etc/resolv.conf").files("/etc/resolv.conf", "/etc/nsswitch.conf")
	want := []string{
		"/etc/hosts was replaced after start; webhooks resolve names again after a restart",
		"/etc/resolv.conf was replaced after start; webhooks resolve names again after a restart",
	}
	if w := rs.ResolverWarnings(); !slices.Equal(w, want) {
		t.Errorf("ResolverWarnings = %q", w)
	}
}

// TestCheckSkipsDev: uses under /dev and /proc never had rules.
func TestCheckSkipsDev(t *testing.T) {
	t.Parallel()
	m := linuxFS(t).device("/dev/null").symlink("/etc/gosftpd/keys/bob.pub", "/dev/null")
	c := newConfig("/etc/gosftpd/config.toml")
	in := input(t, m, c)
	in.Linux = true
	rs := applied(t, in)
	addUser(c, "alice", "/dev/null")
	addUser(c, "bob", "/etc/gosftpd/keys/bob.pub")
	c.Audit.Output = "/dev/stderr"
	checkFindings(t, rs.Check(Uses(c)))
	if !rs.Covers("/dev/fd/63", ReadFile) {
		t.Error("a pipe is not covered")
	}
	if !rs.KeepsOpen("/dev/stderr") || rs.KeepsOpen("/var/log/gosftpd/audit.jsonl") || (*Ruleset)(nil).KeepsOpen("/dev/stderr") {
		t.Error("KeepsOpen")
	}
}

// TestKeepsOpenAuditLink: an audit file that is a link to stderr, when
// stderr is a pipe, gets no rule and is kept open at reloads, as one that
// resolves under /dev does (/dev/null, a terminal behind /dev/stdout); one
// that got a rule is opened again.
func TestKeepsOpenAuditLink(t *testing.T) {
	t.Parallel()
	m := linuxFS(t).symlink("/dev/stderr", "/proc/self/fd/2").symlink("/proc/self/fd/2", "pipe:[4242]").
		symlink("/var/log/gosftpd/audit.jsonl", "/dev/stderr").files("/var/log/other/audit.jsonl").
		device("/dev/null").symlink("/var/log/null/audit.jsonl", "/dev/null").
		device("/dev/pts/3").symlink("/dev/stdout", "/dev/pts/3").symlink("/var/log/tty/audit.jsonl", "/dev/stdout")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Audit.Output = "/var/log/gosftpd/audit.jsonl"
	in := input(t, m, c)
	in.Linux = true
	rs := applied(t, in)
	if !rs.KeepsOpen("/var/log/gosftpd/audit.jsonl") || rs.KeepsOpen("/var/log/other/audit.jsonl") {
		t.Error("KeepsOpen")
	}
	for _, out := range []string{"/var/log/null/audit.jsonl", "/var/log/tty/audit.jsonl"} {
		c.Audit.Output = out
		if rs := applied(t, in); !rs.KeepsOpen(out) {
			t.Errorf("%s, which resolves under /dev, is opened again", out)
		}
	}
	c.Audit.Output = "/var/log/other/audit.jsonl"
	if rs := applied(t, input(t, m, c)); rs.KeepsOpen("/var/log/other/audit.jsonl") {
		t.Error("an audit file with a rule is kept open")
	}
}
