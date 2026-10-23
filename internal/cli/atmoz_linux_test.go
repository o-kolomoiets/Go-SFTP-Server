// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestLandlockAtmoz: under Landlock, atmoz mode serves each user's
// directory through a rule of its own, while the users file and the key
// files, read once at start, are outside every rule; the inlined keys and
// the hashed passwords still log in (ADR 0012).
func TestLandlockAtmoz(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	home := t.TempDir()
	etc := t.TempDir()
	users := filepath.Join(etc, "users.conf")
	writeAll(t, users, "foo:"+pw+":::upload\nbar::::inbox\n")
	key := newSigner(t)
	keyFile := filepath.Join(home, "bar", ".ssh", "keys", "id.pub")
	writeAll(t, keyFile, authorizedKey(key)+"\n")
	sb := startSandboxed(t, sandboxOpts{
		args: []string{"--users-conf", users, "--listen", "127.0.0.1:0", "--state-dir", t.TempDir()},
		env:  []string{homeEnv + "=" + home, "SFTP_USERS=", "GOSFTPD_ATMOZ_IMAGE="},
	})
	waitLog(t, sb.logs, "landlock: ABI v")
	sb.denied(t, "read "+users)
	sb.denied(t, "read "+keyFile)
	sb.denied(t, "list "+filepath.Dir(keyFile))
	sb.denied(t, "list "+filepath.Join(home, "foo"))
	sb.denied(t, "create "+filepath.Join(home, "foo", "new"))
	sb.allowed(t, "list "+filepath.Join(home, "foo", "upload"))
	sb.allowed(t, "create "+filepath.Join(home, "bar", "inbox", "probe"))

	foo := mustLogin(t, sb.addr, "foo", ssh.Password(pw))
	for range 2 {
		if err := putFile(foo, "/upload/a.txt", "data"); err != nil {
			t.Fatal(err)
		}
	}
	if got := names(t, foo, "/upload"); len(got) != 1 {
		t.Errorf("/upload lists %v", got)
	}
	bar := mustLogin(t, sb.addr, "bar", ssh.PublicKeys(key))
	if err := putFile(bar, "/inbox/b.txt", "data"); err != nil {
		t.Fatal(err)
	}
	foo.Close()
	bar.Close()
	if code := sb.stop(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, sb.logs())
	}
	if got := readHost(t, filepath.Join(home, "bar", "inbox", "b.txt")); got != "data" {
		t.Errorf("b.txt = %q", got)
	}
}
