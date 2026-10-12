// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// minimalConfig is a configuration below base with one mount, inbox, for
// alice's key, and extra appended.
func minimalConfig(base string, alice ssh.Signer, extra string) string {
	return `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + filepath.Join(base, "state", "host_key") + `"]
host_key_auto_generate = true
shutdown_timeout = "1s"
[mounts.inbox]
path = "` + filepath.Join(base, "srv", "inbox") + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { inbox = "full" }
` + extra
}

// TestLandlockNotApplied: a rule that would be placed on / skips Landlock
// in "auto", with the reason in the log and not_applied in server.start;
// in "required" the start fails with exit status 2.
func TestLandlockNotApplied(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	conf := `include = ["/*.toml"]` + "\n" + minimalConfig(base, newSigner(t), "")
	files(t, base, map[string]string{
		"auto/config.toml":     conf,
		"required/config.toml": strings.Replace(conf, "[server]\n", "[server]\nlandlock = \"required\"\n", 1),
		"srv/inbox/":           "", "state/": "",
	})

	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", filepath.Join(base, "auto", "config.toml")}})
	waitLog(t, sb.logs, `level=INFO msg="landlock: not applied" reason="a rule would be placed on /" key=include`)
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
	if evs := events(t, sb.audit(), "server.start"); len(evs) != 1 || evs[0]["landlock"] != "not_applied" {
		t.Errorf("server.start = %v", evs)
	}

	sb = startSandboxed(t, sandboxOpts{args: []string{"--config", filepath.Join(base, "required", "config.toml")}, failing: true})
	if sb.code != exitUsage || !strings.Contains(sb.logs(), `Error: landlock: not applied: a rule would be placed on / (include); server.landlock is "required"`) {
		t.Errorf("exit %d:\n%s", sb.code, sb.logs())
	}
	if strings.Contains(sb.audit(), "server.start") {
		t.Errorf("server.start before a failed start:\n%s", sb.audit())
	}
}

// TestLandlockSwappedMount: a mount directory swapped for a link after it
// was opened, before the rules are added, cannot redirect its rule: the
// start fails with exit status 1.
func TestLandlockSwappedMount(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	files(t, base, map[string]string{
		"etc/config.toml": minimalConfig(base, newSigner(t), ""),
		"srv/inbox/":      "", "state/": "", "outside/secret.txt": "secret",
	})
	inbox := filepath.Join(base, "srv", "inbox")
	sb := startSandboxed(t, sandboxOpts{
		args:    []string{"--config", filepath.Join(base, "etc", "config.toml")},
		env:     []string{swapEnv + "=" + inbox + "=" + filepath.Join(base, "outside")},
		failing: true,
	})
	if sb.code != exitFailure || !strings.Contains(sb.logs(), `level=ERROR msg="landlock: failed" err="mounts.inbox.path: `+inbox+` is no longer the directory the mount opened"`) {
		t.Errorf("exit %d:\n%s", sb.code, sb.logs())
	}
}

// TestLandlockZeroConfig: in zero-configuration mode ~/.ssh is never
// dedicated: the authorized_keys file gets a rule of its own, with a
// warning, and the private keys next to it stay unreadable, also one
// created after the start.
func TestLandlockZeroConfig(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	home := filepath.Join(base, "home")
	files(t, base, map[string]string{
		"home/.ssh/authorized_keys": authorizedKey(alice) + "\n",
		"home/.ssh/id_ed25519":      "private",
		"share/":                    "",
	})
	sb := startSandboxed(t, sandboxOpts{args: []string{"--dir", filepath.Join(base, "share"), "--listen", "127.0.0.1:0"}, home: home})
	waitLog(t, sb.logs, "--authorized-keys: Landlock covers only the file authorized_keys in "+filepath.Join(home, ".ssh")+", which is a .ssh directory")
	files(t, base, map[string]string{"home/.ssh/id_new": "private"})
	sb.denied(t, "read "+filepath.Join(home, ".ssh", "id_ed25519"))
	sb.denied(t, "read "+filepath.Join(home, ".ssh", "id_new"))
	sb.denied(t, "list "+filepath.Join(home, ".ssh"))
	sb.allowed(t, "read "+filepath.Join(home, ".ssh", "authorized_keys"))
	c := sftpClient(t, sb.addr, "anyone", alice)
	if err := putFile(c, "/a.txt", "a"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockBindMount: after the kernel reclaimed its dentries
// (drop_caches), /proc/self stays readable through the descriptor held
// open, so that a reload still refuses a trusted file reached through a
// bind mount of a mount: mountinfo shows where it lies. It runs as root in
// a mount namespace of its own.
func TestLandlockBindMount(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	conf := minimalConfig(base, alice, "[metrics]\nlisten = \"127.0.0.1:0\"\n")
	files(t, base, map[string]string{"etc/config.toml": conf, "srv/inbox/": "", "state/": "", "bind/": ""})
	sb := startSandboxed(t, sandboxOpts{
		args: []string{"--config", filepath.Join(base, "etc", "config.toml")},
		bind: []string{filepath.Join(base, "srv", "inbox"), filepath.Join(base, "bind")},
	})
	if !dropCaches(t) {
		return
	}
	sb.allowed(t, "read /proc/self/statm")
	sb.allowed(t, "list /proc/self/fd")
	sb.allowed(t, "read /proc/self/mountinfo")
	// The process metrics read /proc/self.
	m := regexp.MustCompile(`metrics: (http://\S+/metrics)`).FindStringSubmatch(sb.logs())
	if m == nil {
		t.Fatalf("no metrics address:\n%s", sb.logs())
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, m[1], nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, metric := range []string{"\nprocess_resident_memory_bytes ", "\nprocess_open_fds "} {
		if !strings.Contains(string(body), metric) {
			t.Errorf("no%s in /metrics:\n%s", strings.TrimSuffix(metric, " "), body)
		}
	}

	// The key file of a new user, written into the mount and named
	// through the bind mount: clients could change it.
	writeFile(t, filepath.Join(base, "srv", "inbox", "bob.keys"), authorizedKey(newSigner(t))+"\n")
	writeFile(t, filepath.Join(base, "etc", "config.toml"), conf+"[users.bob]\nauthorized_keys_file = \""+
		filepath.Join(base, "bind", "bob.keys")+"\"\naccess = { inbox = \"read\" }\n")
	if ev := sb.reload(t, sb.audit); ev["result"] != "error" || ev["reason"] != "config" {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	if !strings.Contains(sb.logs(), "covers the authorized_keys file of bob ("+filepath.Join(base, "bind", "bob.keys")+"): clients could change it") {
		t.Errorf("the reload does not say why:\n%s", sb.logs())
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockResolverWarnings: a name-resolution file replaced by rename
// after the start gives a warning at every reload; a systemd-resolved stub
// replaced inside its /run directory gives none. The child runs in a mount
// namespace of its own with directories of the test in place of /etc and
// /run, so that the test can replace those files.
func TestLandlockResolverWarnings(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	tree := map[string]string{
		"etc/config.toml":            minimalConfig(base, newSigner(t), ""),
		"fake/etc/hosts":             "127.0.0.1 localhost\n",
		"fake/etc/nsswitch.conf":     "hosts: files dns\n",
		"fake/run/resolve/stub.conf": "nameserver 127.0.0.53\n",
		"srv/inbox/":                 "", "state/": "",
	}
	files(t, base, tree)
	// The loader of setpriv and env, and of a test binary built with cgo.
	if cache, err := os.ReadFile("/etc/ld.so.cache"); err == nil {
		files(t, base, map[string]string{"fake/etc/ld.so.cache": string(cache)})
	}
	if err := os.Symlink("/run/resolve/stub.conf", filepath.Join(base, "fake/etc/resolv.conf")); err != nil {
		t.Fatal(err)
	}
	sb := startSandboxed(t, sandboxOpts{
		args: []string{"--config", filepath.Join(base, "etc", "config.toml")},
		bind: []string{filepath.Join(base, "fake/etc"), "/etc", filepath.Join(base, "fake/run"), "/run"},
	})
	sb.denied(t, "read /etc/ld.so.cache")
	sb.allowed(t, "read /etc/hosts")
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || strings.Contains(sb.logs(), "was replaced after start") {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}

	replaceFile(t, filepath.Join(base, "fake/run/resolve/stub.conf"), "nameserver 127.0.0.53\n# replaced\n")
	replaceFile(t, filepath.Join(base, "fake/etc/hosts"), "127.0.0.1 localhost\n# replaced\n")
	for range 2 { // at every reload
		sb.reload(t, sb.audit)
	}
	if n := strings.Count(sb.logs(), `level=WARN msg=landlock detail="/etc/hosts was replaced after start; webhooks resolve names again after a restart"`); n != 2 {
		t.Errorf("%d warnings for /etc/hosts, want 2:\n%s", n, sb.logs())
	}
	if strings.Contains(sb.logs(), "/etc/resolv.conf was replaced") {
		t.Errorf("a warning for the stub replaced inside /run:\n%s", sb.logs())
	}
	sb.allowed(t, "read /etc/resolv.conf")
	sb.denied(t, "read /etc/hosts")
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockReadme: the README flow under Landlock, in both orders: init,
// user add --write, serve, reload; and init, serve, user add --write,
// reload. init creates users.d, so that the first user file needs no
// restart. Not parallel: init works in the current directory.
func TestLandlockReadme(t *testing.T) {
	if serveChild(t) {
		return
	}
	for _, before := range []bool{true, false} {
		home := isolate(t)
		dir := t.TempDir()
		t.Chdir(dir)
		alice, partner, partner2 := newSigner(t), newSigner(t), newSigner(t)
		files(t, home, map[string]string{".ssh/authorized_keys": authorizedKey(alice) + "\n"})
		files(t, dir, map[string]string{"partner.pub": authorizedKey(partner) + "\n", "partner2.pub": authorizedKey(partner2) + "\n"})
		if code, out, errOut := execute(t, "init", "--user", "alice"); code != exitOK || !strings.Contains(out, "users.d") {
			t.Fatalf("init: exit %d\n%s%s", code, out, errOut)
		}
		add := func(name string) {
			t.Helper()
			if code, out, errOut := execute(t, "user", "add", name, "--key", name+".pub", "--access", "share=upload", "--write"); code != exitOK {
				t.Fatalf("user add: exit %d\n%s%s", code, out, errOut)
			}
		}
		if before {
			add("partner")
		}
		sb := startSandboxed(t, sandboxOpts{args: []string{"--listen", "127.0.0.1:0"}, dir: dir, home: home})
		waitLog(t, sb.logs, "landlock: ABI v")
		if before && !canLogIn(sb.addr, "partner", partner) {
			t.Errorf("partner cannot log in:\n%s", sb.logs())
		}
		add("partner2")
		if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
			t.Errorf("before = %v: server.reload = %v\n%s", before, ev, sb.logs())
		}
		c := sftpClient(t, sb.addr, "partner2", partner2)
		if err := putFile(c, "/report.pdf", "%PDF"); err != nil {
			t.Errorf("before = %v: upload: %v", before, err)
		}
		c.Close()
		if !canLogIn(sb.addr, "alice", alice) {
			t.Errorf("alice cannot log in")
		}
		if code := sb.stop(t); code != exitOK {
			t.Errorf("exit %d", code)
		}
		if got, err := os.ReadFile(filepath.Join(dir, "share", "report.pdf")); err != nil || string(got) != "%PDF" {
			t.Errorf("report.pdf = %q, %v", got, err)
		}
	}
}

// packagedConfig is the packaged layout's configuration below base:
// /etc/gosftpd/config.toml, the host key in /var/lib/gosftpd, the inbox
// under /srv/sftp, the audit log in /var/log/gosftpd.
func packagedConfig(base, extra string) string {
	return `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + filepath.Join(base, "var/lib/gosftpd/ssh_host_ed25519_key") + `"]
shutdown_timeout = "1s"
` + extra + `
[mounts.inbox]
path = "` + filepath.Join(base, "srv/sftp/inbox") + `"
create = true
[audit]
output = "` + filepath.Join(base, "var/log/gosftpd/audit.jsonl") + `"
`
}

// TestLandlockPackaged: the packaged layout, started before users.d
// exists, then restarted with it; each time a user added with user add
// --write logs in after a reload, without a restart.
func TestLandlockPackaged(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	file := filepath.Join(base, "etc/gosftpd/config.toml")
	files(t, base, map[string]string{
		"etc/gosftpd/config.toml": packagedConfig(base, "host_key_auto_generate = true"),
		"var/lib/gosftpd/":        "", "var/log/gosftpd/": "",
	})
	audit := func() string {
		b, _ := os.ReadFile(filepath.Join(base, "var/log/gosftpd/audit.jsonl"))
		return string(b)
	}
	for _, name := range []string{"alice", "bob"} {
		key := newSigner(t)
		writeFile(t, filepath.Join(base, name+".pub"), authorizedKey(key)+"\n")
		sb := startSandboxed(t, sandboxOpts{args: []string{"--config", file}, home: "/"})
		waitLog(t, sb.logs, "landlock: ABI v")
		if strings.Contains(sb.logs(), "msg=landlock ") {
			t.Errorf("start warnings for the packaged layout:\n%s", sb.logs())
		}
		if code, out, errOut := execute(t, "user", "add", name, "--key", filepath.Join(base, name+".pub"), "--access", "inbox=upload", "--write", "--config", file); code != exitOK {
			t.Fatalf("user add: exit %d\n%s%s", code, out, errOut)
		}
		if ev := sb.reload(t, audit); ev["result"] != "ok" || ev["restart_required"] != nil {
			t.Errorf("server.reload = %v\n%s", ev, sb.logs())
		}
		if !canLogIn(sb.addr, name, key) {
			t.Errorf("%s cannot log in:\n%s", name, sb.logs())
		}
		if code := sb.stop(t); code != exitOK {
			t.Errorf("exit %d", code)
		}
	}
}

// TestLandlockPackagedHostCerts: in the packaged layout a host key
// rotation with host certificates (rotate, reload, rotate --finish,
// reload) needs no restart, and the certificate of the new key is served.
func TestLandlockPackagedHostCerts(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	file := filepath.Join(base, "etc/gosftpd/config.toml")
	key := filepath.Join(base, "var/lib/gosftpd/ssh_host_ed25519_key")
	files(t, base, map[string]string{
		"etc/gosftpd/config.toml":        packagedConfig(base, "host_certificates = true"),
		"etc/gosftpd/users.d/alice.toml": "[users.alice]\nauthorized_keys = [\"" + authorizedKey(alice) + "\"]\naccess = { inbox = \"read\" }\n",
		"var/lib/gosftpd/":               "", "var/log/gosftpd/": "",
	})
	if code, out, errOut := execute(t, "hostkey", "generate", "--out", key); code != exitOK {
		t.Fatalf("hostkey generate: exit %d\n%s%s", code, out, errOut)
	}
	ca := newSigner(t)
	signHostCert(t, ca, key)
	audit := func() string {
		b, _ := os.ReadFile(filepath.Join(base, "var/log/gosftpd/audit.jsonl"))
		return string(b)
	}
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", file}, home: "/"})
	ts := &testServer{addr: sb.addr, stderr: sb.err}
	served := func() *ssh.Certificate {
		t.Helper()
		used, _ := ts.hostKeyOf(t, "alice", alice, ssh.CertAlgoED25519v01)
		cert, ok := used.(*ssh.Certificate)
		if !ok {
			t.Fatalf("no certificate served: %T", used)
		}
		return cert
	}
	first := served()

	if code, out, errOut := execute(t, "hostkey", "rotate", "--config", file); code != exitOK {
		t.Fatalf("rotate: exit %d\n%s%s", code, out, errOut)
	}
	signHostCert(t, ca, hostkey.Next(key))
	if ev := sb.reload(t, audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload after rotate = %v\n%s", ev, sb.logs())
	}
	if code, out, errOut := execute(t, "hostkey", "rotate", "--finish", "--config", file); code != exitOK {
		t.Fatalf("rotate --finish: exit %d\n%s%s", code, out, errOut)
	}
	if ev := sb.reload(t, audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload after rotate --finish = %v\n%s", ev, sb.logs())
	}
	next, err := hostkey.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	if cert := served(); !sameKeys(cert.Key, next.PublicKey()) || sameKeys(cert.Key, first.Key) {
		t.Errorf("the certificate served after rotate --finish is not the new key's")
	}
	if strings.Contains(sb.logs(), "outside the Landlock ruleset") {
		t.Errorf("a hint during the rotation:\n%s", sb.logs())
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestServeClearsAmbient: with CAP_NET_BIND_SERVICE in the ambient set, as
// systemd's AmbientCapabilities= gives it for port 22, serve clears the
// set before any hook can run: an exec hook's process has none.
func TestServeClearsAmbient(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	base := t.TempDir()
	alice := newSigner(t)
	out := filepath.Join(base, "capamb")
	files(t, base, map[string]string{
		"etc/config.toml": minimalConfig(base, alice, `[[hooks]]
name = "caps"
on = ["fs.upload"]
exec = { argv = ["/bin/sh", "-c", "grep CapAmb /proc/self/status > `+out+`"] }
`),
		"srv/inbox/": "", "state/": "",
	})
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", filepath.Join(base, "etc", "config.toml")}, ambient: true})
	waitLog(t, sb.logs, `msg="ambient capabilities cleared" set=0x400`)
	c := sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/a.txt", "a"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(time.Minute)
	for {
		if b, err := os.ReadFile(out); err == nil && strings.HasSuffix(string(b), "\n") {
			if got := strings.Fields(string(b)); len(got) != 2 || got[1] != "0000000000000000" {
				t.Errorf("the hook runs with %q", b)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hook did not run:\n%s", sb.logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestConfigValidateLandlock: config validate --check-fs prints the
// warnings serve gives when it applies Landlock; a rule that would be
// placed on / is a warning in "auto" and an error in "required".
func TestConfigValidateLandlock(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	alice := newSigner(t)
	files(t, base, map[string]string{
		"audit/config.toml":    minimalConfig(base, alice, "[audit]\noutput = \"audit.jsonl\"\n"),
		"auto/config.toml":     `include = ["/*.toml"]` + "\n" + minimalConfig(base, alice, ""),
		"required/config.toml": `include = ["/*.toml"]` + "\n" + strings.Replace(minimalConfig(base, alice, ""), "[server]\n", "[server]\nlandlock = \"required\"\n", 1),
		"off/config.toml":      strings.Replace(minimalConfig(base, alice, "[audit]\noutput = \"audit.jsonl\"\n"), "[server]\n", "[server]\nlandlock = \"off\"\n", 1),
		"srv/inbox/":           "",
	})
	validate := func(name string) (int, string) {
		code, _, errOut := execute(t, "config", "validate", "--check-fs", "--config", filepath.Join(base, name, "config.toml"))
		return code, errOut
	}
	code, out := validate("audit")
	if code != exitOK || !strings.Contains(out, "warning: landlock: audit.output: Landlock covers only the file audit.jsonl in "+filepath.Join(base, "audit")+", which holds config.toml: rotation by rename") {
		t.Errorf("audit: exit %d\n%s", code, out)
	}
	if code, out := validate("auto"); code != exitOK || !strings.Contains(out, "warning: landlock: not applied: a rule would be placed on / (include)") {
		t.Errorf("auto: exit %d\n%s", code, out)
	}
	if code, out := validate("required"); code != exitUsage || !strings.Contains(out, `Error: landlock: not applied: a rule would be placed on / (include); server.landlock is "required"`) {
		t.Errorf("required: exit %d\n%s", code, out)
	}
	if code, out := validate("off"); code != exitOK || strings.Contains(out, "landlock") {
		t.Errorf("off: exit %d\n%s", code, out)
	}
	// Without --check-fs nothing is looked at.
	if code, _, errOut := execute(t, "config", "validate", "--config", filepath.Join(base, "audit", "config.toml")); code != exitOK || strings.Contains(errOut, "landlock") {
		t.Errorf("without --check-fs: exit %d\n%s", code, errOut)
	}
}
