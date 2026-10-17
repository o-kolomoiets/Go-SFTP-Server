// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The tests below mount a disk on the directory of a running server's mount
// (ROADMAP M4 DoD). The child serves in a mount namespace of its own, where
// a bind mount stands for the disk; the test itself sees the directories
// without it, so the mount's directory is the one hidden below the mount
// point.

// mountInChild bind-mounts src onto dst in the mount namespace of the
// child sb, through sudo -n nsenter.
func mountInChild(t *testing.T, sb *sandboxed, src, dst string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "sudo", "-n", "nsenter", "--target", sb.do(t, "pid"), "--mount", "--",
		"mount", "--bind", src, dst).CombinedOutput()
	if err != nil {
		t.Fatalf("mount --bind in the child's namespace: %v %s", err, out)
	}
}

// remountConfig is minimalConfig with server.landlock set to landlock.
func remountConfig(base string, alice ssh.Signer, landlock string) string {
	return strings.Replace(minimalConfig(base, alice, ""), "[server]\n", "[server]\nlandlock = \""+landlock+"\"\n", 1)
}

// TestReloadRemountedMount: without Landlock, uploads go to the hidden
// directory until a reload, which opens the disk for new logins and logs
// it; a connection from before the reload keeps the hidden directory.
func TestReloadRemountedMount(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	needSudo(t, "nsenter")
	base := t.TempDir()
	alice := newSigner(t)
	files(t, base, map[string]string{
		"etc/config.toml": remountConfig(base, alice, "off"),
		"srv/inbox/":      "", "disk/": "", "state/": "",
	})
	inbox, disk := filepath.Join(base, "srv", "inbox"), filepath.Join(base, "disk")
	sb := startSandboxed(t, sandboxOpts{args: []string{"--config", filepath.Join(base, "etc", "config.toml")}, bind: []string{}})
	old := sftpClient(t, sb.addr, "alice", alice)
	mountInChild(t, sb, disk, inbox)
	// hidden reports whether name is in the hidden directory only.
	hidden := func(name string) bool {
		return exists(filepath.Join(inbox, name)) && !exists(filepath.Join(disk, name))
	}

	c := sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/before.txt", "x"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !hidden("before.txt") {
		t.Error("before the reload, an upload did not land in the hidden directory")
	}
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	if !strings.Contains(sb.logs(), `level=INFO msg="mount reopened" mount=inbox reason=`) {
		t.Errorf("the reopened mount is not logged:\n%s", sb.logs())
	}
	c = sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/after.txt", "x"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !exists(filepath.Join(disk, "after.txt")) || exists(filepath.Join(inbox, "after.txt")) {
		t.Error("after the reload, a new login's upload did not land on the disk")
	}
	if err := putFile(old, "/old.txt", "x"); err != nil {
		t.Fatal(err)
	}
	old.Close()
	if !hidden("old.txt") {
		t.Error("a connection from before the reload did not keep the hidden directory")
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// TestLandlockRemountedMount: under Landlock the kernel denies the disk, so
// the reload leaves the mount out as unavailable, names it in
// restart_required, and uploads fail; after a restart they land on the
// disk.
func TestLandlockRemountedMount(t *testing.T) {
	t.Parallel()
	if serveChild(t) {
		return
	}
	needSudo(t, "nsenter")
	base := t.TempDir()
	alice := newSigner(t)
	files(t, base, map[string]string{
		"etc/config.toml": remountConfig(base, alice, "required"),
		"srv/inbox/":      "", "disk/": "", "state/": "",
	})
	inbox, disk := filepath.Join(base, "srv", "inbox"), filepath.Join(base, "disk")
	args := []string{"--config", filepath.Join(base, "etc", "config.toml")}
	sb := startSandboxed(t, sandboxOpts{args: args, bind: []string{}})
	mountInChild(t, sb, disk, inbox)
	sb.denied(t, "create "+filepath.Join(inbox, "probe"))
	if ev := sb.reload(t, sb.audit); ev["result"] != "ok" || ev["restart_required"] != "mounts.inbox.path" {
		t.Errorf("server.reload = %v\n%s", ev, sb.logs())
	}
	if !hinted(sb.logs(), inbox) {
		t.Errorf("no restart hint for %s:\n%s", inbox, sb.logs())
	}
	if strings.Contains(sb.logs(), `msg="mount reopened"`) {
		t.Errorf("an unavailable mount is logged as reopened:\n%s", sb.logs())
	}
	c := sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/before.txt", "x"); err == nil {
		t.Error("an upload to the remounted mount before the restart")
	}
	c.Close()
	for _, dir := range []string{inbox, disk} {
		for _, name := range []string{"before.txt", "probe"} {
			if exists(filepath.Join(dir, name)) {
				t.Errorf("%s was written before the restart", filepath.Join(dir, name))
			}
		}
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}

	// The restart: the disk is mounted before serve starts.
	sb = startSandboxed(t, sandboxOpts{args: args, bind: []string{disk, inbox}})
	c = sftpClient(t, sb.addr, "alice", alice)
	if err := putFile(c, "/after.txt", "x"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !exists(filepath.Join(disk, "after.txt")) || exists(filepath.Join(inbox, "after.txt")) {
		t.Error("after the restart, the upload did not land on the disk")
	}
	if code := sb.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}
