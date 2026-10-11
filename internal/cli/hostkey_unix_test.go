// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// As root, --finish gives a next key copied in by root the owner of the
// host key, which gosftpd must read; a file of another owner is refused.
func TestHostkeyRotateFinishOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files other owners")
	}
	isolate(t)
	key := filepath.Join(t.TempDir(), "key")
	if _, err := hostkey.Generate(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(key, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--host-key", key); code != exitOK {
		t.Fatalf("rotate: %s", errOut)
	}
	owner := func(f string) uint32 {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Uid
	}
	if owner(hostkey.Next(key)) != 4242 {
		t.Errorf("the next key belongs to uid %d, want the owner of the host key", owner(hostkey.Next(key)))
	}
	if err := os.Chown(hostkey.Next(key), 0, 0); err != nil { // copied in by root
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--finish", "--host-key", key); code != exitOK {
		t.Fatalf("finish: %s", errOut)
	}
	if owner(key) != 4242 {
		t.Errorf("the new host key belongs to uid %d, want 4242", owner(key))
	}

	// A next key that is a hard link to another root file is not chowned:
	// that file would be handed to the owner of the key.
	if code, _, errOut := execute(t, "hostkey", "rotate", "--retire", "--host-key", key); code != exitOK {
		t.Fatalf("retire: %s", errOut)
	}
	secret := filepath.Join(t.TempDir(), "secret_key")
	if _, err := hostkey.Generate(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, hostkey.Next(key)); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--finish", "--host-key", key); code != exitUsage || !strings.Contains(errOut, "other hard links") {
		t.Errorf("finish with a linked next key: exit %d, %s", code, errOut)
	}
	if owner(secret) != 0 {
		t.Errorf("the linked file now belongs to uid %d", owner(secret))
	}

	other := filepath.Join(t.TempDir(), "other")
	writeFile(t, other, "x")
	if err := sameOwner(other, key, false); err == nil || !strings.Contains(err.Error(), "belongs to uid 0") {
		t.Errorf("sameOwner() of a root file = %v", err)
	}
	if err := sameOwner(other, key, true); err != nil {
		t.Errorf("sameOwner() of a root certificate = %v", err)
	}
}
