// SPDX-License-Identifier: Apache-2.0

//go:build unix

package atmoz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildPermissions: the users file and the key files must not be
// writable by group or others (ROADMAP §6.5), as atmoz's own examples
// mount them from the host.
func TestBuildPermissions(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	file := filepath.Join(t.TempDir(), "users.conf")
	write(t, file, "foo:"+secret+"\n")
	if err := os.Chmod(file, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{UsersFile: file, Home: home}); err == nil || !strings.Contains(err.Error(), "the users file "+file+": writable by group or others (mode 0664)") {
		t.Errorf("group-writable users file: %v", err)
	}
	key := filepath.Join(home, "foo", ".ssh", "keys", "id.pub")
	write(t, key, pubKey(t)+"\n")
	if err := os.Chmod(key, 0o646); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Args: []string{"foo::"}, Home: home}); err == nil || !strings.Contains(err.Error(), "argument 1 (user foo): a key file "+key+": writable by group or others (mode 0646)") {
		t.Errorf("key file writable by others: %v", err)
	}
}
