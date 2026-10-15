// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// landlockStatus is what server.start records under Landlock here:
// min(ABI, 5).
func landlockStatus(t *testing.T) string {
	t.Helper()
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		t.Fatal(errno)
	}
	return "v" + strconv.Itoa(min(int(v), 5))
}

// TestLandlockServe: under the real ruleset every vfs operation works
// (uploads, atomic and resumed ones, every conflict policy with versions,
// rename, remove, mkdir, setstat, statvfs, home creation), and nothing
// outside is reachable: /etc/passwd through a planted symlink or
// /proc/self/root, a file outside through an os.Root opened before,
// writing the configuration or a host key. /proc/self stays readable. A
// hard link inside a mount reaches its file: the documented gap. Every
// audit line of the run, with a reload, matches the audit schema.
func TestLandlockServe(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice, bob := newSigner(t), newSigner(t)
	srv := func(m string) string { return filepath.Join(base, "srv", m) }
	files(t, base, map[string]string{
		"etc/users.d/bob.toml": "[users.bob]\nauthorized_keys = [\"" + authorizedKey(bob) + "\"]\naccess = { rename = \"read\" }\n",
		"etc/config.toml": `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["../state/ssh_host_ed25519_key"]
host_key_auto_generate = true
landlock = "required"
[mounts.rename]
path = "` + srv("rename") + `"
[mounts.reject]
path = "` + srv("reject") + `"
on_conflict = "reject"
[mounts.overwrite]
path = "` + srv("overwrite") + `"
on_conflict = "overwrite"
[mounts.version]
path = "` + srv("version") + `"
on_conflict = "version"
versions = { keep = 1 }
[mounts.atomic]
path = "` + srv("atomic") + `"
atomic_uploads = true
on_conflict = "version"
[mounts.homes]
path = "` + srv("homes") + `/{user}"
create = true
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { rename = "full", reject = "full", overwrite = "full", version = "full", atomic = "full", homes = "full" }
[audit]
output = "../log/audit.jsonl"
`,
		"srv/rename/kept.txt":  "kept",
		"srv/reject/":          "",
		"srv/overwrite/":       "",
		"srv/version/":         "",
		"srv/atomic/":          "",
		"log/":                 "",
		"state/":               "",
		"outside/secret.txt":   "secret",
		"outside/elsewhere/x":  "x",
		"home/.ssh/id_ed25519": "private",
	})
	if err := os.Symlink("/etc/passwd", filepath.Join(srv("rename"), "passwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(base, "outside", "secret.txt"), filepath.Join(srv("rename"), "linked.txt")); err != nil {
		t.Fatal(err)
	}
	auditFile := filepath.Join(base, "log", "audit.jsonl")
	audit := func() string { b, _ := os.ReadFile(auditFile); return string(b) }
	sb := startSandboxed(t, sandboxOpts{
		args: []string{"--config", filepath.Join(base, "etc", "config.toml")},
		home: filepath.Join(base, "home"),
		env:  []string{rootEnv + "=" + filepath.Join(base, "outside")},
	})
	waitLog(t, sb.logs, "msg=\"landlock: ABI "+landlockStatus(t)+" applied\"")

	c := sftpClient(t, sb.addr, "alice", alice)
	// rename: a second upload gets a numbered name; a resumed upload
	// continues the file; rename across directories, setstat, remove.
	for _, data := range []string{"1", "2"} {
		if err := putFile(c, "/rename/a.txt", data); err != nil {
			t.Fatalf("upload: %v", err)
		}
	}
	data := strings.Repeat("0123456789", 1000)
	if err := putFile(c, "/rename/part.bin", data[:5000]); err != nil {
		t.Fatal(err)
	}
	f, err := c.OpenFile("/rename/part.bin", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(data[5000:]), 5000); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, step := range []error{
		c.Mkdir("/rename/sub"),
		c.Rename("/rename/a.txt", "/rename/sub/a.txt"),
		c.Chtimes("/rename/sub/a.txt", time.Now(), time.Unix(1_000_000_000, 0)),
		c.Remove("/rename/a (1).txt"),
		c.Remove("/rename/sub/a.txt"),
		c.RemoveDirectory("/rename/sub"),
	} {
		if step != nil {
			t.Errorf("rename mount: %v", step)
		}
	}
	if st, err := c.StatVFS("/rename"); err != nil || st.Blocks == 0 {
		t.Errorf("statvfs = %+v, %v", st, err)
	}
	// reject, overwrite, version (one kept), atomic with versions.
	if err := putFile(c, "/reject/a.txt", "1"); err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/reject/a.txt", "2"); err == nil {
		t.Error("reject: the second upload succeeded")
	}
	for _, m := range []string{"overwrite", "version", "atomic"} {
		for _, v := range []string{"1", "2", "3"} {
			if err := putFile(c, "/"+m+"/a.txt", v); err != nil {
				t.Fatalf("%s: %v", m, err)
			}
		}
	}
	// A home is created at the first login.
	if err := putFile(c, "/homes/h.txt", "home"); err != nil {
		t.Fatal(err)
	}
	// The hard link inside a mount reaches its file outside: Landlock
	// checks paths, and this path is inside the mount.
	if got := readRemote(t, c, "/rename/linked.txt"); got != "secret" {
		t.Errorf("linked.txt = %q", got)
	}
	if _, err := c.Stat("/rename/passwd"); err == nil {
		t.Error("the planted symlink to /etc/passwd can be followed")
	}

	for name, want := range map[string]string{
		"srv/rename/part.bin":   data,
		"srv/reject/a.txt":      "1",
		"srv/overwrite/a.txt":   "3",
		"srv/version/a.txt":     "3",
		"srv/atomic/a.txt":      "3",
		"srv/homes/alice/h.txt": "home",
		"srv/rename/kept.txt":   "kept",
		"srv/rename/linked.txt": "secret",
		"outside/elsewhere/x":   "x",
		"home/.ssh/id_ed25519":  "private",
	} {
		if got, err := os.ReadFile(filepath.Join(base, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	// versions.keep = 1 removes the older one; atomic keeps both.
	for m, n := range map[string]int{"version": 1, "atomic": 2} {
		if versions, err := filepath.Glob(filepath.Join(srv(m), ".versions", "a.txt", "a.*.txt")); err != nil || len(versions) != n {
			t.Errorf("%s: versions %q, %v; want %d", m, versions, err, n)
		}
	}

	// From inside the ruleset.
	sb.denied(t, "read /etc/passwd")
	sb.denied(t, "read "+filepath.Join(srv("rename"), "passwd"))
	sb.denied(t, "read /proc/self/root/etc/passwd")
	sb.denied(t, "rootread secret.txt")
	sb.denied(t, "read "+filepath.Join(base, "outside", "secret.txt"))
	sb.denied(t, "read "+filepath.Join(base, "home", ".ssh", "id_ed25519"))
	sb.denied(t, "write "+filepath.Join(base, "etc", "config.toml"))
	sb.denied(t, "create "+filepath.Join(base, "etc", "users.d", "x.toml"))
	sb.denied(t, "write "+filepath.Join(base, "state", "ssh_host_ed25519_key"))
	sb.denied(t, "list "+filepath.Join(base, "state"))
	sb.denied(t, "read "+auditFile)
	sb.allowed(t, "read "+filepath.Join(base, "etc", "users.d", "bob.toml"))
	sb.allowed(t, "read "+filepath.Join(base, "state", "ssh_host_ed25519_key"))
	sb.allowed(t, "read "+filepath.Join(srv("rename"), "linked.txt")) // the documented gap
	sb.allowed(t, "create "+filepath.Join(srv("rename"), "new.txt"))
	sb.allowed(t, "read /proc/self/statm")
	sb.allowed(t, "read /proc/self/mountinfo")
	sb.allowed(t, "list /proc/self/fd")

	if ev := sb.reload(t, audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	if !canLogIn(sb.addr, "bob", bob) {
		t.Error("bob cannot log in")
	}
	c.Close()
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
	if evs := events(t, audit(), "server.start"); len(evs) != 1 || evs[0]["landlock"] != landlockStatus(t) {
		t.Errorf("server.start = %v", evs)
	}
	if len(events(t, audit(), "server.stop")) != 1 {
		t.Errorf("no server.stop:\n%s", audit())
	}
	checkAuditSchema(t, audit())
}

// readRemote downloads path.
func readRemote(t *testing.T, c *sftpConn, path string) string {
	t.Helper()
	f, err := c.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
