// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// replaceFile writes data to path through a new file renamed over it, as
// editors, sed -i and user add --write do: the file gets a new inode.
func replaceFile(t *testing.T, path, data string) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// relink points the symlink link at target, as ln -sfn does.
func relink(t *testing.T, link, target string) {
	t.Helper()
	tmp := link + ".new"
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
}

// hinted reports whether the log names path with the Landlock hint.
func hinted(log, path string) bool {
	for line := range strings.SplitSeq(log, "\n") {
		if strings.Contains(line, path) && strings.Contains(line, "outside the Landlock ruleset applied at start; restart gosftpd") {
			return true
		}
	}
	return false
}

// TestLandlockReloadMounts: a reload cannot widen the ruleset applied at
// start. A new mount, a mount moved to a link out of a covered directory
// and a recreated mount are left out as unavailable; read_only turned off
// and create added keep their running values; a new audit directory keeps
// the running audit output. Each is named in restart_required, and a
// mount back at its first directory is served again.
func TestLandlockReloadMounts(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	files(t, base, map[string]string{
		"srv/data/": "", "srv/ro/": "", "srv/again/": "", "srv/homes/": "",
		"other/new/": "", "other/linked/": "", "log/": "", "newlog/": "", "state/": "",
	})
	if err := os.Symlink(p("other/linked"), p("srv/data/out")); err != nil {
		t.Fatal(err)
	}
	type step struct {
		dataPath, audit string
		roWritable      bool
		homesCreate     bool
		newMount        bool
	}
	write := func(s step) {
		t.Helper()
		cfg := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + p("state/host_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.data]
path = "` + s.dataPath + `"
[mounts.ro]
path = "` + p("srv/ro") + `"
read_only = ` + map[bool]string{true: "false", false: "true"}[s.roWritable] + `
[mounts.again]
path = "` + p("srv/again") + `"
[mounts.homes]
path = "` + p("srv/homes") + `/{user}"
read_only = true
create = ` + map[bool]string{true: "true", false: "false"}[s.homesCreate] + `
`
		access := `data = "full", ro = "full", again = "full", homes = "full"`
		if s.newMount {
			cfg += "[mounts.new]\npath = \"" + p("other/new") + "\"\n"
			access += `, new = "full"`
		}
		cfg += "[users.alice]\nauthorized_keys = [\"" + authorizedKey(alice) + "\"]\naccess = { " + access + " }\n[audit]\noutput = \"" + s.audit + "\"\n"
		files(t, base, map[string]string{"etc/config.toml": cfg})
	}
	start := step{dataPath: p("srv/data"), audit: p("log/audit.jsonl")}
	write(start)
	audit := func() string { b, _ := os.ReadFile(p("log/audit.jsonl")); return string(b) }
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})

	write(step{dataPath: p("srv/data/out"), audit: p("newlog/audit.jsonl"), roWritable: true, homesCreate: true, newMount: true})
	ev := sb.reload(t, audit)
	if want := "mounts.data.path,mounts.homes.create,mounts.new.path,mounts.ro.read_only,audit.output"; ev["result"] != "ok" || ev["restart_required"] != want {
		t.Errorf("server.reload = %v, want restart_required %s\n%s", ev, want, sb.logs())
	}
	for _, path := range []string{p("srv/data/out"), p("other/new"), p("srv/ro"), p("srv/homes"), p("newlog")} {
		if !hinted(sb.logs(), path) {
			t.Errorf("no hint for %s:\n%s", path, sb.logs())
		}
	}
	c := sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/ro/x", "x"); err == nil {
		t.Error("ro is writable without a restart")
	}
	for _, m := range []string{"/new/x", "/data/x"} {
		if err := putFile(c, m, "x"); err == nil {
			t.Errorf("%s: an upload to a mount the rules do not cover", m)
		}
	}
	if _, err := c.ReadDir("/homes"); err == nil {
		t.Error("homes: a home was created without a restart")
	}
	if _, err := os.Stat(p("srv/homes/alice")); err == nil {
		t.Error("the home of alice exists")
	}
	if _, err := os.Stat(p("newlog/audit.jsonl")); err == nil {
		t.Error("the new audit output was created")
	}
	c.Close()

	// Back to the first directories, but one mount recreated.
	if err := os.Rename(p("srv/again"), p("srv/again.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p("srv/again"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(start)
	if ev := sb.reload(t, audit); ev["result"] != "ok" || ev["restart_required"] != "mounts.again.path" {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	c = sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/data/x", "x"); err != nil {
		t.Errorf("data is not served again: %v", err)
	}
	if err := putFile(c, "/again/x", "x"); err == nil {
		t.Error("an upload to the recreated mount")
	}
	if _, err := os.Stat(p("srv/again/x")); err == nil {
		t.Error("a file in the recreated mount")
	}
	c.Close()
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockSharedFiles: files in directories that hold other files get
// rules of their own. Nothing else in such a directory can be read: an
// unnamed file next to the include files, in a subdirectory of users.d or
// in a team directory under a wildcard include, a file next to the key
// files. Replaced by rename, an authorized_keys file is left out, the host
// key keeps the running host keys, a webhook keeps its running secret and
// a new webhook whose secret the rules do not cover is left out, each with
// the hint and its key in restart_required; a new team directory and a
// replaced revocation list fail the reload with the hint, without
// restart_required.
func TestLandlockSharedFiles(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice, bob, carol, dave := newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	user := func(name, key string) string {
		return "[users." + name + "]\nauthorized_keys = [\"" + key + "\"]\naccess = { inbox = \"read\" }\n"
	}
	hook := func(name string) string {
		return "[[hooks]]\nname = \"" + name + "\"\non = [\"fs.upload\"]\nwebhook = { url = \"http://127.0.0.1:9/hook\", secret_file = \"../keys/" + name + ".secret\" }\n"
	}
	conf := `config_version = 1
include = ["users.d/*.toml", "teams/*/users.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["../keys/host_key"]
shutdown_timeout = "1s"
[auth]
revoked_keys_file = "../keys/revoked"
[mounts.inbox]
path = "` + p("srv/inbox") + `"
[users.alice]
authorized_keys_file = "../keys/alice.keys"
access = { inbox = "full" }
` + hook("notify")
	const secret = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	files(t, base, map[string]string{
		"etc/config.toml":         conf,
		"etc/users.d/bob.toml":    user("bob", authorizedKey(bob)),
		"etc/users.d/notes.txt":   "notes",
		"etc/users.d/archive/x":   "archived",
		"etc/teams/t1/users.toml": user("carol", authorizedKey(carol)),
		"etc/teams/t1/notes.txt":  "notes",
		"keys/alice.keys":         authorizedKey(alice) + "\n",
		"keys/readme.txt":         "readme",
		"keys/revoked":            "# nothing revoked\n",
		"keys/notify.secret":      secret,
		"srv/inbox/":              "",
	})
	if code, out, errOut := execute(t, "hostkey", "generate", "--out", p("keys/host_key")); code != exitOK {
		t.Fatalf("hostkey generate: exit %d\n%s%s", code, out, errOut)
	}
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
	for _, w := range []string{
		"include: Landlock covers only the include files found at start in " + p("etc/users.d") + ", which holds archive and notes.txt",
		"include: Landlock covers only the include files found at start in " + p("etc/teams"),
		"users.alice.authorized_keys_file: Landlock covers only the file alice.keys in " + p("keys") + ", which holds readme.txt",
		"server.host_keys: Landlock covers only the file host_key in " + p("keys") + ", which holds readme.txt",
	} {
		waitLog(t, sb.logs, w)
	}
	sb.denied(t, "read "+p("etc/users.d/archive/x"))
	sb.denied(t, "read "+p("etc/users.d/notes.txt"))
	sb.denied(t, "read "+p("etc/teams/t1/notes.txt"))
	sb.denied(t, "read "+p("keys/readme.txt"))
	sb.denied(t, "create "+p("etc/users.d/new.toml"))
	sb.allowed(t, "read "+p("etc/users.d/bob.toml"))
	sb.allowed(t, "read "+p("etc/teams/t1/users.toml"))
	sb.allowed(t, "list "+p("etc/teams"))

	// Files replaced by rename, and a new secret file: they are left out
	// or keep their running values.
	hostKey, err := os.ReadFile(p("keys/host_key"))
	if err != nil {
		t.Fatal(err)
	}
	replaceFile(t, p("keys/alice.keys"), authorizedKey(alice)+"\n")
	replaceFile(t, p("keys/host_key"), string(hostKey))
	replaceFile(t, p("keys/notify.secret"), secret)
	files(t, base, map[string]string{"keys/late.secret": secret})
	writeFile(t, p("etc/config.toml"), conf+hook("late"))
	ev := sb.reload(t, sb.audit)
	if want := "users.alice.authorized_keys_file,server.host_keys,hooks[0].webhook.secret_file,hooks[1].webhook.secret_file"; ev["result"] != "ok" || ev["restart_required"] != want {
		t.Errorf("server.reload = %v, want restart_required %s\n%s", ev, want, sb.logs())
	}
	for _, what := range []string{"its keys are not used", "the running host keys stay", `hook \"notify\" keeps its running secret`, `hook \"late\" is left out until its secret is fixed`} {
		if !strings.Contains(sb.logs(), what) {
			t.Errorf("no %q in the log:\n%s", what, sb.logs())
		}
	}
	for _, f := range []string{"keys/alice.keys", "keys/host_key", "keys/notify.secret", "keys/late.secret"} {
		if !hinted(sb.logs(), p(f)) {
			t.Errorf("no hint for %s:\n%s", f, sb.logs())
		}
	}
	if canLogIn(sb.addr, "alice", alice) {
		t.Error("alice logs in with a key file the rules do not cover")
	}
	if !canLogIn(sb.addr, "bob", bob) {
		t.Error("bob cannot log in with the running host keys")
	}

	// A new team directory: its include file cannot be read.
	files(t, base, map[string]string{"etc/teams/t2/users.toml": user("dave", authorizedKey(dave))})
	ev = sb.reload(t, sb.audit)
	if ev["result"] != "error" || ev["reason"] != "config" || ev["restart_required"] != nil {
		t.Errorf("server.reload with a new team = %v\n%s", ev, sb.logs())
	}
	if !hinted(sb.logs(), p("etc/teams/t2/users.toml")) {
		t.Errorf("no hint for the new team:\n%s", sb.logs())
	}
	if err := os.RemoveAll(p("etc/teams/t2")); err != nil {
		t.Fatal(err)
	}

	// The revocation list replaced by rename: the reload fails closed.
	replaceFile(t, p("keys/revoked"), "# still nothing\n")
	ev = sb.reload(t, sb.audit)
	if ev["result"] != "error" || ev["reason"] != "config" || ev["restart_required"] != nil {
		t.Errorf("server.reload with a replaced revocation list = %v\n%s", ev, sb.logs())
	}
	if !hinted(sb.logs(), p("keys/revoked")) {
		t.Errorf("no hint for the revocation list:\n%s", sb.logs())
	}
	if !canLogIn(sb.addr, "bob", bob) || !canLogIn(sb.addr, "carol", carol) || canLogIn(sb.addr, "dave", dave) {
		t.Error("the failed reloads changed the users")
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockWildcardInclude: a wildcard include whose leading directory
// the rules do not cover fails the reload with the hint, instead of
// matching nothing: a new pattern outside the ruleset, a leading directory
// missing at start and created later, one replaced by rename. The running
// users stay.
func TestLandlockWildcardInclude(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice, bob, carol, dave, erin := newSigner(t), newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	user := func(name string, key ssh.Signer) string {
		return "[users." + name + "]\nauthorized_keys = [\"" + authorizedKey(key) + "\"]\naccess = { inbox = \"read\" }\n"
	}
	conf := func(include string) string {
		return `include = ["users.d/*.toml", "teams/*/users.toml", "groups/*/users.toml"` + include + "]\n" + minimalConfig(base, alice, "")
	}
	files(t, base, map[string]string{
		"etc/config.toml":            conf(""),
		"etc/README":                 "the configuration directory is shared",
		"etc/users.d/bob.toml":       user("bob", bob),
		"etc/teams/t1/users.toml":    user("carol", carol),
		"partners/p1/users.toml":     user("dave", dave),
		"teams.new/t1/users.toml":    user("carol", carol),
		"teams.new/t2/users.toml":    user("erin", erin),
		"groups.later/g1/users.toml": user("erin", erin),
		"srv/inbox/":                 "", "state/": "",
	})
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
	waitLog(t, sb.logs, "include: "+p("etc/groups")+" does not exist: the first file added there needs a restart")
	failed := func(what, dir string) {
		t.Helper()
		ev := sb.reload(t, sb.audit)
		if ev["result"] != "error" || ev["reason"] != "config" || ev["restart_required"] != nil {
			t.Errorf("%s: server.reload = %v\n%s", what, ev, sb.logs())
		}
		if !hinted(sb.logs(), dir) {
			t.Errorf("%s: no hint for %s:\n%s", what, dir, sb.logs())
		}
		if !canLogIn(sb.addr, "bob", bob) || !canLogIn(sb.addr, "carol", carol) || canLogIn(sb.addr, "dave", dave) || canLogIn(sb.addr, "erin", erin) {
			t.Errorf("%s: the failed reload changed the users", what)
		}
	}

	writeFile(t, p("etc/config.toml"), conf(`, "`+p("partners")+`/*/users.toml"`))
	failed("a new pattern", p("partners"))
	writeFile(t, p("etc/config.toml"), conf(""))
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}

	if err := os.Rename(p("groups.later"), p("etc/groups")); err != nil {
		t.Fatal(err)
	}
	failed("a leading directory created after the start", p("etc/groups"))
	if err := os.RemoveAll(p("etc/groups")); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(p("etc/teams"), p("teams.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p("teams.new"), p("etc/teams")); err != nil {
		t.Fatal(err)
	}
	failed("a leading directory replaced by rename", p("etc/teams"))
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockLinkedTeam: a team directory of a wildcard include that is
// a link into another tree gets a rule on its target, with a warning that
// names the link: a reload still lists it and loads its users, whether
// the leading directory is dedicated or holds another file.
func TestLandlockLinkedTeam(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	for _, shared := range []bool{false, true} {
		base := t.TempDir()
		bob, carol := newSigner(t), newSigner(t)
		p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
		user := func(name string, key ssh.Signer) string {
			return "[users." + name + "]\nauthorized_keys = [\"" + authorizedKey(key) + "\"]\naccess = { inbox = \"read\" }\n"
		}
		tree := map[string]string{
			"etc/config.toml":             `include = ["teams/*/users.toml"]` + "\n" + minimalConfig(base, newSigner(t), ""),
			"etc/teams/b/users.toml":      user("carol", carol),
			"elsewhere/team-a/users.toml": user("bob", bob),
			"srv/inbox/":                  "", "state/": "",
		}
		if shared {
			tree["etc/teams/README"] = "readme"
		}
		files(t, base, tree)
		if err := os.Symlink(p("elsewhere/team-a"), p("etc/teams/a")); err != nil {
			t.Fatal(err)
		}
		sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
		waitLog(t, sb.logs, "include: "+p("etc/teams/a")+" is a link to "+p("elsewhere/team-a")+", outside "+p("etc/teams"))
		if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
			t.Errorf("shared = %v: server.reload = %v\n%s", shared, ev, sb.logs())
		}
		if !canLogIn(sb.addr, "bob", bob) || !canLogIn(sb.addr, "carol", carol) {
			t.Errorf("shared = %v: a team's user cannot log in after the reload:\n%s", shared, sb.logs())
		}
		if code := sb.stop(t); code != exitOK {
			t.Errorf("exit %d", code)
		}
	}
}
