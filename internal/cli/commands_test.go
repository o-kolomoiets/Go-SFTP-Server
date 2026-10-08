// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch (run go test -update if intended)\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authorizedKey(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// isolate points HOME and the user config directory into a temporary
// directory, so that commands never touch the real ones.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))
	t.Setenv(config.EnvConfig, "")
	t.Setenv(config.EnvListen, "")
	t.Setenv(config.EnvLogLevel, "")
	t.Setenv(config.EnvLogFormat, "")
	return home
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUserAddGolden(t *testing.T) {
	t.Parallel()

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl partner@laptop"
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "partner.pub")
	writeFile(t, keyFile, "# partner's keys\n"+key+"\n\n")
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	got, err := userBlock("partner-acme", userAddOptions{
		keys:      []string{keyFile, `from="10.0.0.0/8" ` + key},
		access:    []string{"inbox=upload", "My Docs=read", "public=list,read"},
		expires:   "72h",
		allowFrom: []string{"192.0.2.0/24"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "user-add.golden", got)

	// The block is valid TOML and decodes into a user.
	var parsed struct {
		Users map[string]config.User `toml:"users"`
	}
	if _, err := toml.Decode(got, &parsed); err != nil {
		t.Fatalf("output is not TOML: %v", err)
	}
	u := parsed.Users["partner-acme"]
	if len(u.AuthorizedKeys) != 2 || u.Access["My Docs"] != "read" || !u.Expires.Equal(now.Add(72*time.Hour)) {
		t.Errorf("decoded user = %+v", u)
	}
}

func TestUserAddErrors(t *testing.T) {
	t.Parallel()

	key := authorizedKey(newSigner(t))
	for _, args := range [][]string{
		{"user", "add", "Alice", "--key", key, "--access", "a=read"},
		{"user", "add", "alice", "--access", "a=read"},
		{"user", "add", "alice", "--key", key},
		{"user", "add", "alice", "--key", key, "--access", "a=admin"},
		{"user", "add", "alice", "--key", key, "--access", "noequals"},
		{"user", "add", "alice", "--key", key, "--access", "a=read", "--access", "a=full"},
		{"user", "add", "alice", "--key", "/no/such/file", "--access", "a=read"},
		{"user", "add", "alice", "--key", `command="sh" ` + key, "--access", "a=read"},
		{"user", "add", "alice", "--key", key, "--access", "a=read", "--expires", "-1h"},
		{"user", "add", "alice", "--key", key, "--access", "a=read", "--allow-from", "example.org"},
		{"user", "add"},
	} {
		if code, _, errOut := execute(t, args...); code != exitUsage {
			t.Errorf("%q: exit %d, want %d; stderr %s", args, code, exitUsage, errOut)
		}
	}
}

func TestInit(t *testing.T) {
	home := isolate(t)
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n")
	out := filepath.Join(dir, "gosftpd.toml")

	code, stdout, stderr := execute(t, "init", "--out", out, "--user", "alice",
		"--authorized-keys", keys, "--dir", "inbox="+filepath.Join(dir, "inbox"))
	if code != exitOK {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"Created " + out, "mount inbox -> ", "Host key (generated)", "gosftpd config validate --check-fs"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	if fi, err := os.Stat(out); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("config file: %v, %v", fi, err)
	}
	keyPath := filepath.Join(home, ".config", "gosftpd", "ssh_host_ed25519_key")
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("host key not generated: %v", err)
		}
	}

	// The result is valid, including the filesystem checks.
	if code, stdout, stderr := execute(t, "config", "validate", "--check-fs", "--config", out); code != exitOK || !strings.Contains(stdout, "OK (1 mounts, 1 users)") {
		t.Errorf("validate: exit %d\n%s%s", code, stdout, stderr)
	}
	// Never overwritten without --force.
	if code, _, stderr := execute(t, "init", "--out", out); code != exitUsage || !strings.Contains(stderr, "already exists") {
		t.Errorf("second init: exit %d: %s", code, stderr)
	}
	if code, _, stderr := execute(t, "init", "--out", out, "--force", "--authorized-keys", keys); code != exitOK {
		t.Errorf("init --force: exit %d: %s", code, stderr)
	}
}

func TestInitPlaceholderWithoutKeys(t *testing.T) {
	isolate(t)
	out := filepath.Join(t.TempDir(), "gosftpd.toml")
	code, stdout, stderr := execute(t, "init", "--out", out, "--user", "bob")
	if code != exitOK {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "paste your public key") {
		t.Errorf("no hint about the missing key:\n%s", stdout)
	}
	code, _, stderr = execute(t, "config", "validate", "--config", out)
	if code != exitUsage || !strings.Contains(stderr, "users.bob.authorized_keys: entry 1 is a placeholder") {
		t.Errorf("validate: exit %d: %s", code, stderr)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gosftpd.toml")

	// DoD M2: a typo in a key gives exit 2 and names the key.
	writeFile(t, path, "config_version = 1\n[server]\nhost_keys = [\"/k\"]\n[mounts.m]\npath = \"/srv\"\nreadonly = true\n")
	code, _, stderr := execute(t, "config", "validate", "--config", path)
	if code != exitUsage || !strings.Contains(stderr, "unknown key mounts.m.readonly") {
		t.Errorf("typo: exit %d: %s", code, stderr)
	}

	writeFile(t, path, "config_version = 1\n[server]\nlisten = [\"nope\"]\n[mounts.m]\npath = \"rel\"\n[users.a]\naccess = { x = \"read\" }\n")
	code, _, stderr = execute(t, "config", "validate", "--config", path)
	if code != exitUsage {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{"4 problems:", "server.listen", "server.host_keys", "mounts.m.path", `users.a.access: unknown mount "x"`, "warning: users.a: no authorized_keys"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}

	// No configuration at all.
	t.Chdir(dir)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := execute(t, "config", "validate"); code != exitUsage || !strings.Contains(stderr, "gosftpd init") {
		t.Errorf("no config: exit %d: %s", code, stderr)
	}
}

func TestConfigShowAndExample(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, "config_version = 1\n[server]\nhost_keys = [\"/k\"]\n[mounts.m]\npath = \"/srv/m\"\n")
	t.Setenv(config.EnvListen, "127.0.0.1:2222")

	code, stdout, stderr := execute(t, "config", "show", "--config", path)
	if code != exitOK {
		t.Fatalf("show: exit %d: %s", code, stderr)
	}
	for _, want := range []string{`listen = ["127.0.0.1:2222"]`, `on_conflict = "rename"`, `umask = "0027"`, "[mounts.m]"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("show lacks %q:\n%s", want, stdout)
		}
	}

	for _, args := range [][]string{{"config", "example"}, {"config", "example", "--full"}} {
		code, stdout, _ := execute(t, args...)
		full := len(args) == 3
		if code != exitOK || stdout != string(config.Example(full)) {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestUserList(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	keys := filepath.Join(dir, "bob.pub")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n"+authorizedKey(newSigner(t))+"\n")
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "/srv/m"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { m = "full" }
[users.bob]
authorized_keys_file = "bob.pub"
expires = 2001-01-01T00:00:00Z
access = { m = "upload" }
[users.carol]
disabled = true
access = { m = "read" }
`)
	code, stdout, stderr := execute(t, "user", "list", "--config", path)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	space := regexp.MustCompile(`\s+`)
	got := make([]string, len(lines))
	for i, l := range lines {
		got[i] = space.ReplaceAllString(strings.TrimSpace(l), " ")
	}
	want := []string{
		"USER ACCESS KEYS EXPIRES STATUS",
		"alice m=full 1 - active",
		"bob m=upload 2 2001-01-01T00:00:00Z expired",
		"carol m=read 0 - disabled",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("user list:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestHostkeyGenerate(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "key")
	code, stdout, stderr := execute(t, "hostkey", "generate", "--type", "ecdsa", "--out", out)
	if code != exitOK || !strings.HasPrefix(stdout, "SHA256:") {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	if code, _, stderr := execute(t, "hostkey", "generate", "--out", out); code != exitUsage || !strings.Contains(stderr, "already exists") {
		t.Errorf("overwrite: exit %d: %s", code, stderr)
	}
	if code, _, _ := execute(t, "hostkey", "generate", "--type", "dsa", "--out", out+"2"); code != exitUsage {
		t.Errorf("dsa: exit %d", code)
	}
}

func TestCompletion(t *testing.T) {
	t.Parallel()

	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		code, stdout, _ := execute(t, "completion", shell)
		if code != exitOK || !strings.Contains(stdout, "gosftpd") {
			t.Errorf("completion %s: exit %d", shell, code)
		}
	}
}

func TestServeFlagsNeedDir(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, "config_version = 1\n")
	for _, args := range [][]string{
		{"serve", "--config", path, "--user", "alice"},
		{"serve", "--config", path, "--authorized-keys", path},
		{"serve", "--config", path, "--dir", dir},
	} {
		if code, _, stderr := execute(t, args...); code != exitUsage {
			t.Errorf("%q: exit %d: %s", args, code, stderr)
		}
	}
}

// lockedBuffer is a bytes.Buffer safe for concurrent use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// TestServeMinimalExample runs the minimal example configuration end to end,
// with the key placeholder and paths filled in as a user would.
func TestServeMinimalExample(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	user := newSigner(t)
	data := string(config.Example(false))
	data = strings.Replace(data, "<paste your public key, e.g. ~/.ssh/id_ed25519.pub>", authorizedKey(user), 1)
	data = strings.Replace(data, "/var/lib/gosftpd/ssh_host_ed25519_key", filepath.ToSlash(filepath.Join(dir, "state", "host_key")), 1)
	data = strings.Replace(data, `path = "/srv/sftp"`, `path = "`+filepath.ToSlash(filepath.Join(dir, "data"))+`"`, 1)
	data = strings.Replace(data, `[":2022"]`, `["127.0.0.1:0"]`, 1)
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, data)

	ctx, cancel := context.WithCancel(t.Context())
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve", "--config", path}, &stdout, &stderr) }()

	addrRE := regexp.MustCompile(`listen:\s+(127\.0\.0\.1:\d+)`)
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for addr == "" {
		if m := addrRE.FindStringSubmatch(stderr.String()); m != nil {
			addr = m[1]
		}
		select {
		case code := <-done:
			t.Fatalf("serve exited with %d:\n%s", code, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("no listen address in:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(user)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Create("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	conn.Close()

	if got, err := os.ReadFile(filepath.Join(dir, "data", "hello.txt")); err != nil || string(got) != "hello" {
		t.Errorf("uploaded file = %q, %v", got, err)
	}
	cancel()
	if code := <-done; code != exitOK {
		t.Errorf("serve exit code %d:\n%s", code, stderr.String())
	}
	for _, event := range []string{`"event":"server.start"`, `"event":"fs.upload"`, `"user":"alice"`, `"event":"server.stop"`} {
		if !strings.Contains(stdout.String(), event) {
			t.Errorf("audit log lacks %s:\n%s", event, stdout.String())
		}
	}
}
