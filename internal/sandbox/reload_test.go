// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// applied computes the plan of in and keeps it as Start does.
func applied(t *testing.T, in Input) *Ruleset {
	t.Helper()
	return newRuleset(compute(t, in).Rules, in)
}

// describeFindings lists findings as "KEY CHECKED have=RIGHTS".
func describeFindings(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key+" "+slash(f.Checked)+" have="+f.Have.String())
	}
	return out
}

func checkFindings(t *testing.T, got []Finding, want ...string) {
	t.Helper()
	if d := describeFindings(got); !slices.Equal(d, want) {
		t.Errorf("findings:\n  %s\nwant:\n  %s", strings.Join(d, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestUses(t *testing.T) {
	t.Parallel()
	c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
	loaded(c, "/etc/gosftpd/users.d/a.toml")
	addUser(c, "alice", "/etc/gosftpd/keys/alice.pub")
	c.Auth.RevokedKeysFile = native("/etc/gosftpd/revoked")
	c.Server.HostKeys = []string{native("/var/lib/gosftpd/k")}
	c.Hooks = []*config.Hook{{Webhook: &config.HookWebhook{SecretFile: native("/etc/gosftpd/hook.secret")}}}
	c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
	c.Server.HostCertificates = true
	h := c.AddMount("homes", native("/srv/homes/{user}"))
	h.ReadOnly, h.Create = true, true
	uses := func() []string {
		var got []string
		for _, u := range Uses(c) {
			got = append(got, u.Key+" "+slash(u.Path)+" "+u.Need.String())
		}
		return got
	}
	got := uses()
	want := []string{
		"include /etc/gosftpd/users.d/a.toml read_file",
		"include /etc/gosftpd/users.d read_dir",
		"users.alice.authorized_keys_file /etc/gosftpd/keys/alice.pub read_file",
		"auth.revoked_keys_file /etc/gosftpd/revoked read_file",
		"server.host_keys /var/lib/gosftpd/k read_file",
		"server.host_keys /var/lib/gosftpd/k.next read_file",
		"server.host_keys /var/lib/gosftpd/k.old read_file",
		"server.host_keys /var/lib/gosftpd/k-cert.pub read_file",
		"server.host_keys /var/lib/gosftpd/k.next-cert.pub read_file",
		"hooks[0].webhook.secret_file /etc/gosftpd/hook.secret read_file",
		"audit.output /var/log/gosftpd/audit.jsonl write_file",
		"mounts.homes.path /srv/homes read_file,read_dir,make_dir",
		"mounts.inbox.path /srv/sftp/inbox " + rw,
	}
	if !slices.Equal(got, want) {
		t.Errorf("Uses:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	// Files the configuration does not read are not uses: key files
	// without "publickey", certificates without host_certificates.
	c.Auth.Methods = []string{"password"}
	c.Server.HostCertificates = false
	want = slices.DeleteFunc(want, func(u string) bool {
		return strings.Contains(u, "alice.pub") || strings.Contains(u, "revoked") || strings.Contains(u, "cert.pub")
	})
	if got := uses(); !slices.Equal(got, want) {
		t.Errorf("Uses without publickey and certificates:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// TestCheckCovered: a reload of the configuration in use, of new users in
// a dedicated users.d and of a rotated audit log in a directory of its
// own finds nothing; uses that do not exist are skipped.
func TestCheckCovered(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).
		files("/etc/gosftpd/config.toml", "/etc/gosftpd/users.d/a.toml", "/var/lib/gosftpd/k", "/var/log/gosftpd/audit.jsonl").
		dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
	loaded(c, "/etc/gosftpd/users.d/a.toml")
	c.Server.HostKeys = []string{native("/var/lib/gosftpd/k")}
	c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
	rs := applied(t, input(t, m, c))
	checkFindings(t, rs.Check(Uses(c)))

	// user add --write, sed -i on the main file, logrotate, hostkey rotate.
	m.files("/etc/gosftpd/users.d/b.toml", "/var/lib/gosftpd/k.next").replace("/etc/gosftpd/config.toml").
		rename("/var/log/gosftpd/audit.jsonl", "/var/log/gosftpd/audit.jsonl.1")
	loaded(c, "/etc/gosftpd/users.d/b.toml")
	checkFindings(t, rs.Check(Uses(c)))
	if !rs.Covers(native("/etc/gosftpd/config.toml"), ReadFile) {
		t.Error("the main file replaced in a dedicated directory is not covered")
	}

	// Uses that do not exist are skipped.
	addUser(c, "zed", "/etc/elsewhere/zed.pub")
	c.Auth.TrustedUserCAKeysFile = native("/srv/ca/ca.pub")
	checkFindings(t, rs.Check(Uses(c)))
}

// TestCheckMounts: new, moved, recreated and remounted mounts, a symlink
// out of a covered directory, and rights the start did not give.
func TestCheckMounts(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox", "/srv/ro", "/srv/homes", "/srv/other")
	c := newConfig("/etc/gosftpd/config.toml")
	c.AddMount("ro", native("/srv/ro")).ReadOnly = true
	h := c.AddMount("homes", native("/srv/homes/{user}"))
	h.ReadOnly = true
	rs := applied(t, input(t, m, c))
	checkFindings(t, rs.Check(Uses(c)))

	n := newConfig("/etc/gosftpd/config.toml")
	n.Mounts["ro"] = &config.Mount{Path: native("/srv/ro")}                                            // read_only turned off
	n.Mounts["homes"] = &config.Mount{Path: native("/srv/homes/{user}"), ReadOnly: true, Create: true} // create added
	n.Mounts["new"] = &config.Mount{Path: native("/srv/other")}
	n.Mounts["created"] = &config.Mount{Path: native("/srv/new/deep"), Create: true}
	checkFindings(t, rs.Check(Uses(n)),
		"mounts.created.path /srv have=none",
		"mounts.homes.path /srv/homes have=read_file,read_dir",
		"mounts.new.path /srv/other have=none",
		"mounts.ro.path /srv/ro have=read_file,read_dir",
	)

	// A link out of the covered inbox, a recreated inbox, a remount.
	m.symlink("/srv/sftp/inbox/out", "/srv/other")
	n = newConfig("/etc/gosftpd/config.toml")
	n.Mounts["inbox"].Path = native("/srv/sftp/inbox/out")
	checkFindings(t, rs.Check(Uses(n)), "mounts.inbox.path /srv/sftp/inbox/out have=none")

	m.remove("/srv/sftp/inbox").dirs("/srv/sftp/inbox")
	checkFindings(t, rs.Check(Uses(c)), "mounts.inbox.path /srv/sftp/inbox have=none")
	m.remove("/srv/ro").volume("/srv/ro")
	checkFindings(t, rs.Check(Uses(c)), "mounts.inbox.path /srv/sftp/inbox have=none", "mounts.ro.path /srv/ro have=none")
}

// TestCheckAudit: a new audit directory, and an audit file next to the
// configuration rotated by rename while it has a rule of its own.
func TestCheckAudit(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/audit.jsonl").dirs("/srv/sftp/inbox", "/var/log/new")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Audit.Output = native("/etc/gosftpd/audit.jsonl")
	rs := applied(t, input(t, m, c))
	checkFindings(t, rs.Check(Uses(c)))

	m.rename("/etc/gosftpd/audit.jsonl", "/etc/gosftpd/audit.jsonl.1")
	checkFindings(t, rs.Check(Uses(c)), "audit.output /etc/gosftpd have=read_file,read_dir")
	m.files("/etc/gosftpd/audit.jsonl")
	checkFindings(t, rs.Check(Uses(c)), "audit.output /etc/gosftpd/audit.jsonl have=read_file,read_dir")

	n := newConfig("/etc/gosftpd/config.toml")
	n.Audit.Output = native("/var/log/new/audit.jsonl")
	checkFindings(t, rs.Check(Uses(n)), "audit.output /var/log/new have=none")
}

// TestCheckHostKeyRotation: host keys in a shared directory after hostkey
// rotate --finish. The key and its .old keep their inodes' rules; only the
// certificate rewritten by rename is reported.
func TestCheckHostKeyRotation(t *testing.T) {
	t.Parallel()
	const k = "/etc/ssh/ssh_host_ed25519_key"
	m := newMemFS(t).files(k, k+".pub", k+".next", k+"-cert.pub", k+".next-cert.pub", "/etc/ssh/sshd_config").
		files("/etc/gosftpd/config.toml").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Server.HostKeys = []string{native(k)}
	c.Server.HostCertificates = true
	rs := applied(t, input(t, m, c))
	checkFindings(t, rs.Check(Uses(c)))

	// FinishRotation: P.old links P, P.next replaces P; SyncFiles
	// rewrites the certificate by rename and drops the next one's.
	m.hardlink(k+".old", k).rename(k+".next", k).replace(k + "-cert.pub").remove(k + ".next-cert.pub")
	checkFindings(t, rs.Check(Uses(c)), "server.host_keys "+k+"-cert.pub have=none")
}

// TestCheckDedicatedLater: a directory that was shared at start stays as
// the start found it: a new file there is not covered, even once the
// directory holds named files only.
func TestCheckDedicatedLater(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/notes.txt", "/etc/gosftpd/ca.pub").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	c.Auth.TrustedUserCAKeysFile = native("/etc/gosftpd/ca.pub")
	rs := applied(t, input(t, m, c))
	checkFindings(t, rs.Check(Uses(c)))

	m.remove("/etc/gosftpd/notes.txt").files("/etc/gosftpd/bob.pub")
	addUser(c, "bob", "/etc/gosftpd/bob.pub")
	checkFindings(t, rs.Check(Uses(c)), "users.bob.authorized_keys_file /etc/gosftpd/bob.pub have=none")
}

// TestCheckUnresolvable: a path that exists but cannot be resolved is not
// covered.
func TestCheckUnresolvable(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/etc/gosftpd/config.toml", "/etc/gosftpd/keys/a.pub").dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml")
	addUser(c, "a", "/etc/gosftpd/keys/a.pub")
	rs := applied(t, input(t, m, c))

	// A dangling symlink is left to what reads it: a restart would not
	// help.
	m.symlink("/etc/gosftpd/keys/b.pub", "gone.pub")
	addUser(c, "b", "/etc/gosftpd/keys/b.pub")
	checkFindings(t, rs.Check(Uses(c)))

	m.noSearch("/etc/gosftpd/keys")
	checkFindings(t, rs.Check(Uses(c)),
		"users.a.authorized_keys_file /etc/gosftpd/keys/a.pub have=none",
		"users.b.authorized_keys_file /etc/gosftpd/keys/b.pub have=none")
	if rs.Covers(native("/etc/gosftpd/keys/a.pub"), ReadFile) {
		t.Error("Covers is true for a path that cannot be resolved")
	}
}

func TestNilRuleset(t *testing.T) {
	t.Parallel()
	var rs *Ruleset
	denied := &fs.PathError{Op: "open", Path: native("/etc/passwd"), Err: fs.ErrPermission}
	if !rs.Covers(native("/etc/passwd"), ReadFile) || rs.Check([]Use{{Path: native("/x"), Need: ReadFile}}) != nil ||
		rs.ResolverWarnings() != nil || rs.Rules() != nil || rs.Explain(denied, ReadFile).Error() != denied.Error() {
		t.Error("a nil ruleset does not cover everything")
	}
}

// TestExplain: a permission error carries the hint only where the ruleset
// does not cover the path with what its use needs.
func TestExplain(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).
		files("/etc/gosftpd/config.toml", "/etc/gosftpd/users.d/a.toml", "/var/log/gosftpd/audit.jsonl", "/etc/shared/keys", "/etc/shared/notes").
		dirs("/srv/sftp/inbox")
	c := newConfig("/etc/gosftpd/config.toml", "users.d/*.toml")
	loaded(c, "/etc/gosftpd/users.d/a.toml")
	addUser(c, "alice", "/etc/shared/keys")
	c.Audit.Output = native("/var/log/gosftpd/audit.jsonl")
	rs := applied(t, input(t, m, c))
	m.replace("/etc/shared/keys").files("/etc/elsewhere/x.toml")

	denied := func(p string) error {
		return fmt.Errorf("users.alice: %w", &fs.PathError{Op: "open", Path: native(p), Err: fs.ErrPermission})
	}
	for _, tc := range []struct {
		name string
		err  error
		need Rights
		hint bool
	}{
		{"a covered file", denied("/etc/gosftpd/users.d/a.toml"), ReadFile, false},
		{"a file replaced by rename", denied("/etc/shared/keys"), ReadFile, true},
		{"a file outside", denied("/etc/elsewhere/x.toml"), ReadFile, true},
		{"writing a covered file the rule does not let write", denied("/etc/gosftpd/config.toml"), WriteFile, true},
		{"a directory that can be listed", denied("/etc/gosftpd/users.d"), ReadFile, false},
		{"a directory outside", denied("/etc/elsewhere"), ReadFile, true},
		{"a file to create in the audit directory", denied("/var/log/gosftpd/audit.jsonl.new"), WriteFile, false},
		{"a file to create in the configuration directory", denied("/etc/gosftpd/audit.jsonl"), WriteFile, true},
		{"another error", fmt.Errorf("x: %w", &fs.PathError{Op: "open", Path: native("/etc/elsewhere/x.toml"), Err: fs.ErrNotExist}), ReadFile, false},
		{"a relative path", &fs.PathError{Op: "openat", Path: "a/b", Err: fs.ErrPermission}, ReadFile, false},
		{"joined, the second outside", errors.Join(denied("/etc/gosftpd/users.d/a.toml"), denied("/etc/elsewhere/x.toml")), ReadFile, true},
		{"no path", fs.ErrPermission, ReadFile, false},
	} {
		got := rs.Explain(tc.err, tc.need)
		if hinted := strings.HasSuffix(got.Error(), " ("+Hint+")"); hinted != tc.hint {
			t.Errorf("%s: %v", tc.name, got)
		}
		if !errors.Is(got, tc.err) {
			t.Errorf("%s: the error does not wrap %v", tc.name, tc.err)
		}
	}
}

// TestMountUse: a mount's use, as Uses lists it.
func TestMountUse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		m    config.Mount
		want string
	}{
		{config.Mount{Path: native("/srv/a")}, "mounts.x.path /srv/a " + rw + " create=false"},
		{config.Mount{Path: native("/srv/a"), ReadOnly: true, Create: true}, "mounts.x.path /srv/a " + ro + " create=true"},
		{config.Mount{Path: native("/srv/h/{user}"), ReadOnly: true}, "mounts.x.path /srv/h " + ro + " create=false"},
		{config.Mount{Path: native("/srv/h/{user}"), ReadOnly: true, Create: true}, "mounts.x.path /srv/h read_file,read_dir,make_dir create=true"},
	} {
		u := MountUse("x", &tc.m)
		if got := fmt.Sprintf("%s %s %s create=%v", u.Key, slash(u.Path), u.Need, u.Create == CreateDir); got != tc.want {
			t.Errorf("MountUse(%+v) = %s, want %s", tc.m, got, tc.want)
		}
	}
}
