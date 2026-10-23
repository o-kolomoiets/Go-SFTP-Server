// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestLandlockEphemeral: under Landlock, serve --ephemeral serves its data
// to the key and the password, cannot read its own client key or list its
// directory, and on SIGTERM removes the key and the data; the directory
// itself stays, empty (ADR 0012).
func TestLandlockEphemeral(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	tmp := t.TempDir()
	sb := startSandboxed(t, sandboxOpts{args: []string{"--ephemeral"}, env: []string{"TMPDIR=" + tmp}})
	waitLog(t, sb.logs, "landlock: ABI v")
	var line string
	for deadline := time.Now().Add(time.Minute); line == ""; time.Sleep(10 * time.Millisecond) {
		for l := range strings.SplitSeq(sb.out.String(), "\n") {
			if strings.HasPrefix(l, `{"host":`) {
				line = l + "\n"
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection details:\n%s\n%s", sb.out.String(), sb.logs())
		}
	}
	d := decodeDetails(t, line)
	dir := filepath.Dir(d.PrivateKeyPath)
	if filepath.Dir(dir) != tmp || d.Dir != filepath.Join(dir, "data") {
		t.Fatalf("details %+v", d)
	}
	sb.denied(t, "read "+d.PrivateKeyPath)
	sb.denied(t, "list "+dir)
	sb.denied(t, "create "+filepath.Join(dir, "new"))

	c, err := ephemeralLogin(t, d, "test", clientKey(t, d))
	if err != nil {
		t.Fatalf("key login: %v", err)
	}
	if err := c.MkdirAll("/sub/dir"); err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/sub/dir/a.txt", "a"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = ephemeralLogin(t, d, "test", ssh.Password(d.Password))
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	f, err := c.Open("/sub/dir/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(f); err != nil || string(got) != "a" {
		t.Errorf("download: %q, %v", got, err)
	}
	f.Close()
	c.Close()

	if err := sb.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := sb.stop(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, sb.logs())
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Errorf("%s holds %v after SIGTERM", dir, got)
	}
	if got := entries(t, tmp); len(got) != 1 {
		t.Errorf("%s holds %v after SIGTERM", tmp, got)
	}
	waitLog(t, sb.logs, `msg="removed the client key and the data; under Landlock the empty directory stays" dir=`+dir)
	if _, err := os.Stat(d.PrivateKeyPath); !os.IsNotExist(err) {
		t.Errorf("client key: %v", err)
	}
}
