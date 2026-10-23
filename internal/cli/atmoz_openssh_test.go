// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/atmoz"
)

// TestAtmozOpenSSH runs the atmoz README's examples end to end with
// OpenSSH's sftp, in the image's mode, from the three sources at once: the
// spec of docker run IMAGE foo:pass:::upload (a second upload of the same
// name overwrites the first) and foo again (skipped); the users file
// /etc/sftp/users.conf with a user without directories and a user who logs
// in with a key from /home/kim/.ssh/keys/; $SFTP_USERS with a bcrypt hash
// (:e) and a user whose directory is an existing volume. The client
// checks the host key against the banner's known_hosts line.
func TestAtmozOpenSSH(t *testing.T) {
	sftpPath, err := exec.LookPath("sftp")
	if err != nil {
		t.Skip("OpenSSH's sftp is not installed")
	}
	home := atmozEnv(t, true)
	work := t.TempDir()
	key := writeClientKey(t, filepath.Join(work, "id_ed25519"))
	writeAll(t, filepath.Join(home, "kim", ".ssh", "keys", "id_ed25519.pub"), authorizedKey(key)+"\n")
	writeAll(t, atmozUsersFile, "baz:xyz:1003:100\nkim::1005\n")
	writeAll(t, filepath.Join(home, "vol", "share", "old.txt"), "on the volume\n")
	t.Setenv(atmoz.EnvUsers, "qux:"+bcryptOf(t, "bcrypt-pw")+":e:1004::inbox vol:vol-pw:1006")
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::upload", "foo:dup")

	m := regexp.MustCompile(`known_hosts: (\[127\.0\.0\.1\]:(\d+) .+)`).FindStringSubmatch(ts.stderr.String())
	if m == nil {
		t.Fatalf("no known_hosts line in the banner:\n%s", ts.stderr.String())
	}
	knownHosts := filepath.Join(work, "known_hosts")
	writeAll(t, knownHosts, m[1]+"\n")
	port := m[2]
	writeAll(t, filepath.Join(work, "a.txt"), "the first upload, which is longer\n")
	writeAll(t, filepath.Join(work, "b.txt"), "the second\n")

	// sftp runs a batch as user, with password or, without one, the key.
	sftp := func(user, password, batch string) (string, error) {
		t.Helper()
		batchFile := filepath.Join(work, "batch")
		writeAll(t, batchFile, batch)
		// -F: the user's ssh_config, which OpenSSH reads from the account's
		// home whatever $HOME says, must not change the logins.
		args := []string{"-F", os.DevNull, "-P", port, "-o", "UserKnownHostsFile=" + knownHosts, "-o", "StrictHostKeyChecking=yes", "-b", batchFile}
		var env []string
		if password != "" {
			askpass := filepath.Join(work, "askpass")
			if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho '"+password+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			args = append([]string{"-o", "BatchMode=no", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"}, args...)
			env = []string{"SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:0"}
		} else {
			args = append([]string{"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", filepath.Join(work, "id_ed25519")}, args...)
		}
		cmd := exec.CommandContext(t.Context(), sftpPath, append(args, user+"@127.0.0.1")...)
		cmd.Env = append(os.Environ(), env...)
		cmd.Stdin = nil
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	mustSFTP := func(user, password, batch string) string {
		t.Helper()
		out, err := sftp(user, password, batch)
		if err != nil {
			t.Fatalf("sftp as %s: %v\n%s\nserver:\n%s", user, err, out, ts.stderr.String())
		}
		return out
	}

	// docker run IMAGE foo:pass:::upload
	out := mustSFTP("foo", pw, "ls -1 /\nput "+filepath.Join(work, "a.txt")+" upload/a.txt\nput "+filepath.Join(work, "b.txt")+" upload/a.txt\n-put "+filepath.Join(work, "a.txt")+" /root.txt\n-mkdir /dir\n")
	if !strings.Contains(out, "upload") {
		t.Errorf("foo: ls / does not show upload:\n%s", out)
	}
	if got := readHost(t, filepath.Join(home, "foo", "upload", "a.txt")); got != "the second\n" {
		t.Errorf("foo: a.txt = %q, want the second upload", got)
	}
	for _, p := range []string{filepath.Join(home, "foo", "root.txt"), filepath.Join(home, "foo", "dir"), filepath.Join(home, "foo", "upload", "a (1).txt")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("foo: %s exists", p)
		}
	}
	if out, err := sftp("foo", "dup", "ls\n"); err == nil {
		t.Errorf("the second definition of foo logs in:\n%s", out)
	}

	// The users file: baz without directories, kim with a key.
	out = mustSFTP("baz", "xyz", "ls -1 /\n-put "+filepath.Join(work, "a.txt")+" /a.txt\n")
	if strings.Contains(out, "upload") || fileExists(filepath.Join(home, "baz", "a.txt")) {
		t.Errorf("baz: not an empty read-only root:\n%s", out)
	}
	mustSFTP("kim", "", "ls -1 /\n")
	if out, err := sftp("kim", "anything", "ls\n"); err == nil {
		t.Errorf("kim logs in with a password:\n%s", out)
	}

	// $SFTP_USERS: a bcrypt hash, and an existing volume directory.
	mustSFTP("qux", "bcrypt-pw", "put "+filepath.Join(work, "a.txt")+" inbox/a.txt\n")
	if got := readHost(t, filepath.Join(home, "qux", "inbox", "a.txt")); got != "the first upload, which is longer\n" {
		t.Errorf("qux: a.txt = %q", got)
	}
	got := filepath.Join(work, "old.txt")
	mustSFTP("vol", "vol-pw", "get share/old.txt "+got+"\n")
	if s := readHost(t, got); s != "on the volume\n" {
		t.Errorf("vol: old.txt = %q", s)
	}

	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
	for _, want := range []string{
		`msg="atmoz mode" users_file=2 arguments=1 sftp_users=2`,
		"argument 2: user foo is already defined by argument 1; skipped, as atmoz skips it",
	} {
		if !strings.Contains(ts.stderr.String(), want) {
			t.Errorf("no %q in the log:\n%s", want, ts.stderr.String())
		}
	}
	noSecret(t, ts)
}

// writeClientKey writes a new ed25519 key to path, 0600 in OpenSSH's
// format, and returns it.
func writeClientKey(t *testing.T, path string) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
