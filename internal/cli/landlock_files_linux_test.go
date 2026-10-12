// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// userCert certifies key for the principal name with ca.
func userCert(t *testing.T, ca, key ssh.Signer, name string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key: key.PublicKey(), CertType: ssh.UserCert, KeyId: name, ValidPrincipals: []string{name},
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestLandlockLinks: a configuration file and a CA file that are links
// into another tree, as a NixOS generation or an ln -sfn deployment makes
// them, reload; a re-pointed configuration link fails the reload with the
// hint, and a re-pointed CA link is left out with restart_required.
func TestLandlockLinks(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	ca, ca2, key := newSigner(t), newSigner(t), newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	conf := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + p("state/host_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[auth]
trusted_user_ca_keys_file = "ca.pub"
[mounts.inbox]
path = "` + p("srv/inbox") + `"
[users.alice]
access = { inbox = "full" }
`
	files(t, base, map[string]string{
		"tree/v1/config.toml": conf,
		"tree/v1/ca.pub":      authorizedKey(ca) + "\n",
		"tree/v2/config.toml": conf + "# the next generation\n",
		"tree/v2/ca.pub":      authorizedKey(ca2) + "\n",
		"conf/":               "", "srv/inbox/": "", "state/": "",
	})
	for name, target := range map[string]string{"conf/config.toml": "../tree/v1/config.toml", "conf/ca.pub": "../tree/v1/ca.pub"} {
		if err := os.Symlink(target, p(name)); err != nil {
			t.Fatal(err)
		}
	}
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("conf/config.toml")}})
	waitLog(t, sb.logs, "configuration: "+p("conf/config.toml")+" is a link to "+p("tree/v1/config.toml")+", outside "+p("conf"))
	waitLog(t, sb.logs, "auth.trusted_user_ca_keys_file: "+p("conf/ca.pub")+" is a link to "+p("tree/v1/ca.pub"))
	cert := userCert(t, ca, key, "alice")
	if !canLogIn(sb.addr, "alice", cert) {
		t.Fatal("a certificate of the CA does not log in")
	}
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}

	relink(t, p("conf/config.toml"), "../tree/v2/config.toml")
	if ev := sb.reload(t, sb.audit); ev["result"] != "error" || ev["reason"] != "config" {
		t.Errorf("server.reload with a re-pointed configuration link = %v\n%s", ev, sb.logs())
	}
	if !hinted(sb.logs(), p("conf/config.toml")) {
		t.Errorf("no hint for the configuration:\n%s", sb.logs())
	}

	relink(t, p("conf/config.toml"), "../tree/v1/config.toml")
	relink(t, p("conf/ca.pub"), "../tree/v2/ca.pub")
	ev := sb.reload(t, sb.audit)
	if ev["result"] != "ok" || ev["restart_required"] != "auth.trusted_user_ca_keys_file" {
		t.Errorf("server.reload with a re-pointed CA link = %v\n%s", ev, sb.logs())
	}
	if !hinted(sb.logs(), p("conf/ca.pub")) || !strings.Contains(sb.logs(), "its CAs are not trusted") {
		t.Errorf("no hint for the CA file:\n%s", sb.logs())
	}
	if canLogIn(sb.addr, "alice", cert) || canLogIn(sb.addr, "alice", userCert(t, ca2, key, "alice")) {
		t.Error("a CA logs in although its file is left out")
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockReference: the reference layout, /etc/gosftpd with users.d
// and keys, is dedicated. sed -i on the main file, a users.d file and a
// key file replaced by rename, and user add --write reload without a
// restart.
func TestLandlockReference(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice, alice2, bob, bob2, carol := newSigner(t), newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	user := func(name string, key ssh.Signer) string {
		return "[users." + name + "]\nauthorized_keys = [\"" + authorizedKey(key) + "\"]\naccess = { inbox = \"read\" }\n"
	}
	conf := `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + p("var/lib/gosftpd/ssh_host_ed25519_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.inbox]
path = "` + p("srv/sftp/inbox") + `"
[users.alice]
authorized_keys_file = "keys/alice.pub"
access = { inbox = "full" }
`
	files(t, base, map[string]string{
		"etc/gosftpd/config.toml":      conf,
		"etc/gosftpd/users.d/bob.toml": user("bob", bob),
		"etc/gosftpd/keys/alice.pub":   authorizedKey(alice) + "\n",
		"var/lib/gosftpd/":             "", "srv/sftp/inbox/": "",
	})
	file := p("etc/gosftpd/config.toml")
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", file}})
	waitLog(t, sb.logs, "landlock: ABI v")
	if strings.Contains(sb.logs(), "msg=landlock ") {
		t.Errorf("start warnings for the reference layout:\n%s", sb.logs())
	}

	replaceFile(t, file, "# edited with sed -i\n"+conf)
	replaceFile(t, p("etc/gosftpd/users.d/bob.toml"), user("bob", bob2))
	replaceFile(t, p("etc/gosftpd/keys/alice.pub"), authorizedKey(alice2)+"\n")
	writeFile(t, p("carol.pub"), authorizedKey(carol)+"\n")
	if code, out, errOut := execute(t, "user", "add", "carol", "--key", p("carol.pub"), "--access", "inbox=upload", "--write", "--config", file); code != exitOK {
		t.Fatalf("user add: exit %d\n%s%s", code, out, errOut)
	}
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	for _, tc := range []struct {
		user string
		key  ssh.Signer
		ok   bool
	}{{"alice", alice, false}, {"alice", alice2, true}, {"bob", bob, false}, {"bob", bob2, true}, {"carol", carol, true}} {
		if canLogIn(sb.addr, tc.user, tc.key) != tc.ok {
			t.Errorf("%s logs in: %v, want %v", tc.user, !tc.ok, tc.ok)
		}
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockAuditShared: an audit file next to the configuration, in a
// directory that holds another file, gets a rule on the file only: nothing
// else there can be written or read, the configuration and the host key
// cannot be opened for writing, and nothing can be created in users.d.
// Rotated as docs/audit-log.md does, it cannot be created again: the
// reload names audit.output in restart_required and the log gives the
// hint; fail-closed then refuses new connections.
func TestLandlockAuditShared(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	files(t, base, map[string]string{
		"etc/config.toml": `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["ssh_host_ed25519_key"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.inbox]
path = "` + p("srv/inbox") + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { inbox = "full" }
[audit]
output = "audit.jsonl"
`,
		"etc/users.d/": "", "etc/notes.txt": "notes", "srv/inbox/": "",
	})
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
	waitLog(t, sb.logs, "audit.output: Landlock covers only the file audit.jsonl in "+p("etc")+", which holds config.toml, notes.txt, ssh_host_ed25519_key and 2 more: rotation by rename")
	sb.denied(t, "read "+p("etc/notes.txt"))
	sb.denied(t, "write "+p("etc/notes.txt"))
	sb.denied(t, "write "+p("etc/config.toml"))
	sb.denied(t, "write "+p("etc/ssh_host_ed25519_key"))
	sb.denied(t, "create "+p("etc/users.d/x.toml"))
	sb.denied(t, "create "+p("etc/new"))
	sb.denied(t, "read "+p("etc/audit.jsonl"))
	sb.allowed(t, "write "+p("etc/audit.jsonl"))
	sb.allowed(t, "read "+p("etc/config.toml"))
	if !canLogIn(sb.addr, "alice", alice) {
		t.Fatal("alice cannot log in")
	}

	// Rotation by rename; the server.reload event cannot be written to
	// the audit log any more and goes to the operational log.
	if err := os.Rename(p("etc/audit.jsonl"), p("etc/audit.jsonl.1")); err != nil {
		t.Fatal(err)
	}
	sb.do(t, "reload")
	waitLog(t, sb.logs, "event=server.reload result=ok restart_required=audit.output")
	if !hinted(sb.logs(), p("etc/audit.jsonl")) || !strings.Contains(sb.logs(), "cannot reopen the audit log") {
		t.Errorf("no hint for the audit file:\n%s", sb.logs())
	}
	if _, err := os.Stat(p("etc/audit.jsonl")); err == nil {
		t.Error("the audit file was created again")
	}
	if canLogIn(sb.addr, "alice", alice) {
		t.Error("a new connection is accepted while the audit log cannot be written")
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockAuditKeys: a key directory next to the audit file whose name
// looks like a rotated copy's (audit-keys) is no olddir: the audit file
// gets a rule of its own, and the key file cannot be written nor a new one
// created.
func TestLandlockAuditKeys(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	files(t, base, map[string]string{
		"etc/config.toml": minimalConfig(base, alice, "[audit]\noutput = \""+p("log/audit.jsonl")+"\"\n") +
			"[users.bob]\nauthorized_keys_file = \"" + p("log/audit-keys/bob.pub") + "\"\naccess = { inbox = \"read\" }\n",
		"log/audit-keys/bob.pub": authorizedKey(newSigner(t)) + "\n",
		"srv/inbox/":             "", "state/": "",
	})
	audit := func() string { b, _ := os.ReadFile(p("log/audit.jsonl")); return string(b) }
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
	waitLog(t, sb.logs, "audit.output: Landlock covers only the file audit.jsonl in "+p("log")+", which holds audit-keys: rotation by rename")
	sb.denied(t, "write "+p("log/audit-keys/bob.pub"))
	sb.denied(t, "create "+p("log/audit-keys/carol.pub"))
	sb.denied(t, "create "+p("log/audit.jsonl.1"))
	sb.allowed(t, "write "+p("log/audit.jsonl"))
	sb.allowed(t, "read "+p("log/audit-keys/bob.pub"))
	if !canLogIn(sb.addr, "alice", alice) {
		t.Errorf("alice cannot log in:\n%s", sb.logs())
	}
	waitLog(t, audit, `"event":"auth.success"`)
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockAuditStderr: audit.output = "/dev/stderr" gets no rule; a
// reload does not open it again, and the audit log is still written, with
// stderr a regular file or a FIFO.
func TestLandlockAuditStderr(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	files(t, base, map[string]string{
		"etc/config.toml": `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + p("state/host_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.inbox]
path = "` + p("srv/inbox") + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { inbox = "full" }
[audit]
output = "/dev/stderr"
`,
		"srv/inbox/": "", "state/": "",
	})
	for _, kind := range []string{"file", "fifo"} {
		var (
			stderr *os.File
			logs   func() string
		)
		path := p("stderr." + kind)
		if kind == "file" {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			stderr, logs = f, func() string { b, _ := os.ReadFile(path); return string(b) }
		} else {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			// Opened for reading and writing, so that neither end waits.
			r, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			w, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			var buf lockedBuffer
			copied := make(chan struct{})
			go func() { defer close(copied); _, _ = io.Copy(&buf, r) }()
			t.Cleanup(func() { r.Close(); <-copied })
			stderr, logs = w, buf.String
		}
		sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}, stderr: stderr, logs: logs})
		_ = stderr.Close() // the child has it
		if !canLogIn(sb.addr, "alice", alice) {
			t.Fatalf("%s: alice cannot log in", kind)
		}
		ev := sb.reload(t, logs)
		if ev["result"] != "ok" {
			t.Errorf("%s: server.reload = %v", kind, ev)
		}
		if !canLogIn(sb.addr, "alice", alice) {
			t.Errorf("%s: alice cannot log in after the reload", kind)
		}
		if code := sb.stop(t); code != exitOK {
			t.Errorf("%s: exit %d", kind, code)
		}
		waitLog(t, logs, `"event":"server.stop"`) // the FIFO is read meanwhile
		out := logs()
		if strings.Contains(out, "cannot reopen the audit log") || len(events(t, out, "conn.close")) != 2 {
			t.Errorf("%s: stderr:\n%s", kind, out)
		}
	}
}

// TestLandlockAuditDevNull: an audit file that is a link into /dev (to
// /dev/null, as a container image may link it to /dev/stdout) gets no
// rule; a reload does not open it again, and fail-closed keeps accepting
// connections.
func TestLandlockAuditDevNull(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	files(t, base, map[string]string{
		"etc/config.toml": minimalConfig(base, alice, "[audit]\noutput = \""+p("log/audit.jsonl")+"\"\n"),
		"srv/inbox/":      "", "state/": "", "log/": "",
	})
	if err := os.Symlink("/dev/null", p("log/audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("etc/config.toml")}})
	if !canLogIn(sb.addr, "alice", alice) {
		t.Fatal("alice cannot log in")
	}
	// The server.reload event goes to /dev/null: the log says when the
	// reload ended.
	n := reloaded(sb.logs())
	sb.do(t, "reload")
	for deadline := time.Now().Add(time.Minute); reloaded(sb.logs()) == n; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the reload did not end:\n%s", sb.logs())
		}
	}
	if !strings.Contains(sb.logs(), `msg="configuration reloaded"`) || strings.Contains(sb.logs(), "cannot reopen the audit log") {
		t.Errorf("the reload opened the audit file again:\n%s", sb.logs())
	}
	if !canLogIn(sb.addr, "alice", alice) {
		t.Errorf("alice cannot log in after the reload:\n%s", sb.logs())
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockExecHooks: with exec hooks Landlock is not applied; a
// reload that adds one under Landlock leaves it out, warns and names hooks
// in restart_required.
func TestLandlockExecHooks(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	p := func(rel string) string { return filepath.Join(base, filepath.FromSlash(rel)) }
	conf := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + p("state/host_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.inbox]
path = "` + p("srv/inbox") + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { inbox = "full" }
`
	hook := `[[hooks]]
name = "record"
on = ["fs.upload"]
exec = { argv = ["/bin/sh", "-c", "echo ran >> ` + p("runs") + `"] }
`
	files(t, base, map[string]string{"with/config.toml": conf + hook, "without/config.toml": conf, "srv/inbox/": "", "state/": ""})

	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", p("with/config.toml")}})
	waitLog(t, sb.logs, `msg="landlock: not applied" reason="exec hooks configured"`)
	sb.allowed(t, "read /etc/passwd")
	c := sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/a.txt", "a"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(10 * time.Millisecond) {
		if b, _ := os.ReadFile(p("runs")); string(b) == "ran\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hook did not run:\n%s", sb.logs())
		}
	}
	sb.stop(t)
	if evs := events(t, sb.audit(), "server.start"); len(evs) != 1 || evs[0]["landlock"] != "not_applied" {
		t.Errorf("server.start = %v", evs)
	}

	sb = startSandboxed(t, sandboxOpts{args: []string{"--config", p("without/config.toml")}})
	files(t, base, map[string]string{"without/config.toml": conf + hook})
	ev := sb.reload(t, sb.audit)
	if ev["result"] != "ok" || ev["restart_required"] != "hooks" {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	waitLog(t, sb.logs, `hook \"record\" is left out until a restart: Landlock was applied at start`)
	c = sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/b.txt", "b"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
	if b, _ := os.ReadFile(p("runs")); string(b) != "ran\n" {
		t.Errorf("runs = %q: the hook left out ran", b)
	}
}
