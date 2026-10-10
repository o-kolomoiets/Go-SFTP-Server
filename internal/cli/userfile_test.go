// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// userConfig writes a configuration that includes users.d/*.toml, with one
// user in the main file, and returns its path.
func userConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "inbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := hostkey.Generate(filepath.Join(dir, "state", "host_key")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:2222"]
host_keys = ["state/host_key"]
[mounts.inbox]
path = "`+filepath.ToSlash(filepath.Join(dir, "inbox"))+`"
[users.admin]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { inbox = "full" }
`)
	return path
}

func TestUserAddWrite(t *testing.T) {
	t.Parallel()

	path := userConfig(t)
	key := authorizedKey(newSigner(t))
	code, out, errOut := execute(t, "user", "add", "partner", "--key", key, "--access", "inbox=upload",
		"--expires", "720h", "--write", "--config", path, "--host", "sftp.example.org")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	file := filepath.Join(filepath.Dir(path), "users.d", "partner.toml")
	for _, want := range []string{
		"Wrote " + file, "host:    sftp.example.org", "port:    2222", "user:    partner",
		"host key: ED25519 SHA256:", "known_hosts: [sftp.example.org]:2222 ssh-ed25519 ", "connect: sftp -P 2222 partner@sftp.example.org",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want that of the configuration (0600)", fi.Mode().Perm())
	}
	if di, err := os.Stat(filepath.Dir(file)); err != nil || runtime.GOOS != "windows" && di.Mode().Perm() != 0o700 {
		t.Errorf("users.d mode: %v, %v; want 0700 for a 0600 configuration, whatever the umask", di.Mode().Perm(), err)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CheckFS(); err != nil {
		t.Errorf("CheckFS refuses the written file: %v", err)
	}
	u := c.Users["partner"]
	if u == nil || u.From != file || u.Expires == nil || u.Access["inbox"] != "upload" {
		t.Errorf("partner = %+v", u)
	}

	for _, args := range [][]string{
		{"user", "add", "partner", "--key", key, "--access", "inbox=read", "--write", "--config", path}, // exists
		{"user", "add", "admin", "--key", key, "--access", "inbox=read", "--write", "--config", path},   // in the main file
		{"user", "add", "other", "--key", key, "--access", "outbox=read", "--write", "--config", path},  // unknown mount
	} {
		if code, _, _ := execute(t, args...); code == exitOK {
			t.Errorf("%q succeeded", args)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(file), "other.toml")); err == nil {
		t.Error("an invalid user was written")
	}
	des, _ := os.ReadDir(filepath.Dir(file))
	if len(des) != 1 {
		t.Errorf("users.d holds %d entries, want 1 (no temporary files)", len(des))
	}
}

func TestUserAddWriteNeedsInclude(t *testing.T) {
	t.Parallel()

	path := userConfig(t)
	data, _ := os.ReadFile(path)
	writeFile(t, path, strings.Replace(string(data), `include = ["users.d/*.toml"]`, "", 1))
	code, _, errOut := execute(t, "user", "add", "partner", "--key", authorizedKey(newSigner(t)), "--access", "inbox=upload", "--write", "--config", path)
	if code != exitUsage || !strings.Contains(errOut, `include = ["users.d/*.toml"]`) {
		t.Errorf("exit %d: %s", code, errOut)
	}
}

func TestUserDisableEnableRemove(t *testing.T) {
	t.Parallel()

	path := userConfig(t)
	key := authorizedKey(newSigner(t))
	for _, u := range []string{"bob", "carol"} {
		if code, _, errOut := execute(t, "user", "add", u, "--key", key, "--access", "inbox=read", "--write", "--config", path); code != exitOK {
			t.Fatalf("add %s: %s", u, errOut)
		}
	}
	file := filepath.Join(filepath.Dir(path), "users.d", "bob.toml")
	status := func() string {
		t.Helper()
		_, out, _ := execute(t, "user", "list", "--config", path)
		for line := range strings.SplitSeq(out, "\n") {
			if strings.HasPrefix(line, "bob ") {
				return strings.Fields(line)[len(strings.Fields(line))-1]
			}
		}
		return "missing"
	}

	code, out, errOut := execute(t, "user", "disable", "bob", "--config", path)
	if code != exitOK || !strings.Contains(out, "Disabled bob in "+file) || !strings.Contains(out, "disconnect_removed_users") {
		t.Fatalf("disable: exit %d: %s%s", code, out, errOut)
	}
	if s := status(); s != "disabled" {
		t.Errorf("status after disable = %s", s)
	}
	if data, _ := os.ReadFile(file); !strings.HasPrefix(string(data), "# Written by gosftpd user add") {
		t.Errorf("the comment was lost:\n%s", data)
	}
	if _, out, _ := execute(t, "user", "disable", "bob", "--config", path); !strings.Contains(out, "disabled already") {
		t.Errorf("disable twice: %s", out)
	}
	if code, _, _ := execute(t, "user", "enable", "bob", "--config", path); code != exitOK || status() != "active" {
		t.Errorf("enable: exit %d, status %s", code, status())
	}
	if code, out, _ := execute(t, "user", "remove", "bob", "--config", path); code != exitOK || !strings.Contains(out, "and its file") {
		t.Errorf("remove: exit %d: %s", code, out)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("the file of a removed user is left")
	}
	if s := status(); s != "missing" {
		t.Errorf("status after remove = %s", s)
	}

	for _, args := range [][]string{
		{"user", "remove", "admin", "--config", path},   // in the main file
		{"user", "disable", "nobody", "--config", path}, // unknown
	} {
		if code, _, errOut := execute(t, args...); code != exitUsage {
			t.Errorf("%q: exit %d: %s", args, code, errOut)
		}
	}
	if _, _, errOut := execute(t, "user", "remove", "admin", "--config", path); !strings.Contains(errOut, "does not rewrite") {
		t.Errorf("removing a user of the main file: %s", errOut)
	}
}

// A user that could not log in is refused unless --force; the warnings say
// why.
func TestUserAddWriteUnusable(t *testing.T) {
	t.Parallel()

	path := userConfig(t)
	hash := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI"
	args := []string{"user", "add", "pat", "--password-hash", hash, "--access", "inbox=upload", "--write", "--config", path}
	code, _, errOut := execute(t, args...)
	if code != exitUsage || !strings.Contains(errOut, "could not log in") || !strings.Contains(errOut, `auth.methods does not include "password"`) {
		t.Errorf("password user with publickey only: exit %d: %s", code, errOut)
	}
	if code, _, errOut := execute(t, append(args, "--force")...); code != exitOK {
		t.Errorf("--force: exit %d: %s", code, errOut)
	}
}

func TestPartnerInstructionsIPv6(t *testing.T) {
	t.Parallel()

	c := &config.Config{}
	c.Server.Listen = []string{"[2001:db8::1]:2022"}
	out := partnerInstructions(c, "bob", "")
	if !strings.Contains(out, "connect: sftp -P 2022 bob@[2001:db8::1]") {
		t.Errorf("instructions:\n%s", out)
	}
}

// A configuration that trusts CAs takes users without keys: they log in
// with a certificate for their name or principals.
func TestUserAddCertificate(t *testing.T) {
	t.Parallel()

	path := userConfig(t)
	ca := authorizedKey(newSigner(t))
	if code, _, errOut := execute(t, "user", "add", "dave", "--access", "inbox=upload", "--write", "--config", path); code != exitUsage || !strings.Contains(errOut, "could not log in") {
		t.Errorf("a user without keys and no trusted CA: exit %d: %s", code, errOut)
	}
	if code, _, errOut := execute(t, "user", "add", "dave", "--access", "inbox=upload"); code != exitUsage || !strings.Contains(errOut, "--key") {
		t.Errorf("a printed block without keys: exit %d: %s", code, errOut)
	}
	data, _ := os.ReadFile(path)
	writeFile(t, path, strings.Replace(string(data), "[mounts.inbox]", "[auth]\ntrusted_user_ca_keys = [\""+ca+"\"]\n[mounts.inbox]", 1))

	code, out, errOut := execute(t, "user", "add", "carol", "--principal", "carol@corp", "--access", "inbox=upload", "--write", "--config", path)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"for the principal carol@corp", "ssh-keygen -s CA_KEY -I carol -n carol@corp -V +52w"} {
		if !strings.Contains(out, want) {
			t.Errorf("instructions lack %q:\n%s", want, out)
		}
	}
	_, out, _ = execute(t, "user", "list", "--config", path)
	if !strings.Contains(strings.Join(strings.Fields(out), " "), "carol inbox=upload 0 carol@corp - - active") {
		t.Errorf("user list:\n%s", out)
	}

	code, out, errOut = execute(t, "user", "add", "erin", "--key", `cert-authority,principals="erin" `+ca, "--access", "inbox=read")
	if code != exitOK || !strings.Contains(out, "cert-authority,principals=") {
		t.Errorf("--key with a cert-authority line: exit %d: %s%s", code, out, errOut)
	}
}
