// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
)

// hookConfig loads a configuration with one mount "Inbox" and the given
// [[hooks]] tables.
func hookConfig(t *testing.T, hooksTOML string) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	inbox := filepath.Join(dir, "inbox")
	if err := os.Mkdir(inbox, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	data := `config_version = 1
[server]
host_keys = ["hk"]
host_key_auto_generate = true
[mounts.Inbox]
path = "` + filepath.ToSlash(inbox) + `"
[users.alice]
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
access = { Inbox = "upload" }
` + hooksTOML
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func TestValidateHooks(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"name required":      "[[hooks]]\non = [\"fs.upload\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"unknown event":      "[[hooks]]\nname = \"a\"\non = [\"auth.success\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"unknown mount":      "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nmounts = [\"outbox\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"bad pattern":        "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nglob = [\"[\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"pattern with slash": "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexclude = [\"in/*.pdf\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"both":               "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"/bin/true\"] }\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n",
		"neither":            "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\n",
		"relative program":   "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"archive.sh\"] }\n",
		"user info":          "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nwebhook = { url = \"https://u:p@x\", secret_file = \"s\" }\n",
		"scheme":             "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nwebhook = { url = \"ftp://x\", secret_file = \"s\" }\n",
		"no secret":          "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nwebhook = { url = \"https://x\" }\n",
		"duplicate name":     "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"/bin/true\"] }\n[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"/bin/true\"] }\n",
		"delay too long":     "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\ndelay = \"2h\"\nexec = { argv = [\"/bin/true\"] }\n",
		"queue too long":     "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nqueue = 100000\nexec = { argv = [\"/bin/true\"] }\n",
		"too many workers":   "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nconcurrency = 17\nexec = { argv = [\"/bin/true\"] }\n",
		"exec timeout":       "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"/bin/true\"], timeout = \"2h\" }\n",
		"webhook timeout":    "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nwebhook = { url = \"https://x\", secret_file = \"s\", timeout = \"5m\" }\n",
	}
	for name, h := range cases {
		c, _ := hookConfig(t, h)
		if _, err := c.Validate(); err == nil || !strings.Contains(err.Error(), "hooks[") {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	c, _ := hookConfig(t, "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nwebhook = { url = \"http://example.org/x\", secret_file = \"s\" }\n")
	if warns, err := c.Validate(); err != nil || len(warns) != 1 || !strings.Contains(warns[0], "in the clear") {
		t.Errorf("http to a remote host: %v, %v", warns, err)
	}
	if _, err := Load(writeTemp(t, "config_version = 1\n[[hooks]]\nName = \"a\"\n")); err == nil {
		t.Error("a key in the wrong case inside [[hooks]] was accepted")
	}
}

func writeTemp(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHookSpec(t *testing.T) {
	t.Parallel()
	prog := "/bin/true" // Validate needs only an absolute path
	if runtime.GOOS == "windows" {
		prog = "C:/Windows/System32/whoami.exe"
	}
	c, _ := hookConfig(t, `[[hooks]]
name = "a"
on = ["fs.upload"]
mounts = ["inbox"]
delay = "2m"
exec = { argv = ["`+prog+`"] }
[[hooks]]
name = "b"
on = ["fs.upload"]
webhook = { url = "https://x", secret_file = "s" }
`)
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	a := c.HookSpec(c.Hooks[0], nil)
	if a.Mounts[0] != "Inbox" || a.Concurrency != 1 || a.Queue != hooks.MaxQueue || a.Exec.Timeout != hooks.DefaultExecTime || a.Delay != 2*time.Minute {
		t.Errorf("spec a = %+v", a)
	}
	b := c.HookSpec(c.Hooks[1], []byte("k"))
	if b.Queue != hooks.DefaultQueue || b.Webhook.Timeout != hooks.DefaultHookTime || string(b.Webhook.Secret) != "k" {
		t.Errorf("spec b = %+v", b)
	}
	if !filepath.IsAbs(c.Hooks[1].Webhook.SecretFile) {
		t.Errorf("secret_file not resolved against the configuration: %s", c.Hooks[1].Webhook.SecretFile)
	}
}

func TestHookFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := t.TempDir()
	write := func(name, data string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := strings.Repeat("ab", 16)
	prog := write("prog", "#!/bin/sh\n", 0o755)
	script := write("script.sh", "echo\n", 0o644)
	cases := []struct {
		name           string
		hook           Hook
		argvOK, secrOK bool
		secretWant     string
	}{
		{"program", Hook{Exec: &HookExec{Argv: []string{prog}}}, true, true, ""},
		{"interpreter and script, devices, new files", Hook{Exec: &HookExec{Argv: []string{"/bin/sh", script, "/dev/null", filepath.Join(dir, "new.log"), dir}}}, true, true, ""},
		{"missing program", Hook{Exec: &HookExec{Argv: []string{filepath.Join(dir, "nope")}}}, false, true, ""},
		{"not executable", Hook{Exec: &HookExec{Argv: []string{script}}}, false, true, ""},
		{"script others may write", Hook{Exec: &HookExec{Argv: []string{"/bin/sh", write("w.sh", "", 0o666)}}}, false, true, ""},
		{"secret 0640", Hook{Webhook: &HookWebhook{SecretFile: write("s1", " "+good+"\n", 0o640)}}, true, true, good},
		{"secret 0400", Hook{Webhook: &HookWebhook{SecretFile: write("s2", good, 0o400)}}, true, true, good},
		{"secret 0644", Hook{Webhook: &HookWebhook{SecretFile: write("s3", good, 0o644)}}, true, false, ""},
		{"secret 0660", Hook{Webhook: &HookWebhook{SecretFile: write("s4", good, 0o660)}}, true, false, ""},
		{"short secret", Hook{Webhook: &HookWebhook{SecretFile: write("s5", "short", 0o600)}}, true, false, ""},
		{"BOM", Hook{Webhook: &HookWebhook{SecretFile: write("s6", "\xef\xbb\xbf"+good, 0o600)}}, true, false, ""},
		{"UTF-16", Hook{Webhook: &HookWebhook{SecretFile: write("s7", "\xff\xfea\x00b\x00"+strings.Repeat("c\x00", 40), 0o600)}}, true, false, ""},
		{"missing secret", Hook{Webhook: &HookWebhook{SecretFile: filepath.Join(dir, "none")}}, true, false, ""},
	}
	for _, c := range cases {
		secret, argvErr, secretErr := HookFiles(&c.hook)
		if (argvErr == nil) != c.argvOK || (secretErr == nil) != c.secrOK {
			t.Errorf("%s: argv %v, secret %v", c.name, argvErr, secretErr)
		}
		if string(secret) != c.secretWant {
			t.Errorf("%s: secret %q", c.name, secret)
		}
	}
}

// Hook files inside a mount are refused, whether or not they exist.
func TestHookFilesInsideMount(t *testing.T) {
	t.Parallel()
	_, dir := hookConfig(t, "")
	inbox := filepath.Join(dir, "inbox")
	for _, h := range []string{
		"exec = { argv = [\"/bin/sh\", \"" + filepath.ToSlash(filepath.Join(inbox, "x.sh")) + "\"] }",
		"webhook = { url = \"https://x\", secret_file = \"" + filepath.ToSlash(filepath.Join(inbox, "s")) + "\" }",
	} {
		c2, err := Load(writeConfigWith(t, "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\n"+h+"\n", inbox))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c2.CheckFS(); err == nil || !strings.Contains(err.Error(), "a file of a hook") {
			t.Errorf("%s: CheckFS = %v", h, err)
		}
	}
	// A directory argument inside a mount is fine.
	c2, err := Load(writeConfigWith(t, "[[hooks]]\nname = \"a\"\non = [\"fs.upload\"]\nexec = { argv = [\"/usr/bin/find\", \""+filepath.ToSlash(inbox)+"\"] }\n", inbox))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.CheckFS(); err != nil && strings.Contains(err.Error(), "a file of a hook") {
		t.Errorf("a directory argument was refused: %v", err)
	}
}

// writeConfigWith writes a configuration whose mount is inbox, with hooks.
func writeConfigWith(t *testing.T, hooksTOML, inbox string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gosftpd.toml")
	data := `config_version = 1
[server]
host_keys = ["hk"]
host_key_auto_generate = true
[mounts.inbox]
path = "` + filepath.ToSlash(inbox) + `"
[users.alice]
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
access = { inbox = "upload" }
` + hooksTOML
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
