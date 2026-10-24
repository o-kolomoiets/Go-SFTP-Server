// SPDX-License-Identifier: Apache-2.0

//go:build unix

package atmoz

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// TestBuildUnopenable: a directory that exists but that the user gosftpd
// runs as cannot open, such as a volume's host directory of another user
// with mode 0700, is unavailable to its user, with a warning that says
// how to fix it; the user's other directories work. Opening it at start
// would otherwise stop the start, naming the mount atmoz1.
func TestBuildUnopenable(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	up := filepath.Join(home, "foo", "upload")
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(up, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(up, 0o755) })
	if r, err := os.OpenRoot(up); err == nil {
		r.Close()
		t.Skip("a directory with mode 0000 opens: the test runs with CAP_DAC_OVERRIDE")
	}
	m := build(t, Options{Args: []string{"foo:" + secret + ":::upload,other"}, Home: home})
	c := m.Config
	if !slices.Equal(c.Unavailable, []string{"atmoz1"}) || c.Mounts["atmoz1"].Display != "upload" {
		t.Fatalf("unavailable %v", c.Unavailable)
	}
	if want := "argument 1 (user foo): directory upload cannot be opened (open " + up + ": permission denied), so it is unavailable to foo; let uid "; !hasWarning(m.Warnings, want) {
		t.Errorf("no warning %q in %q", want, m.Warnings)
	}
	if hasWarning(m.Warnings, "atmoz1") || hasWarning(m.Warnings, "directory other") {
		t.Errorf("warnings %q", m.Warnings)
	}
	if fi, err := os.Stat(filepath.Join(home, "foo", "other")); err != nil || !fi.IsDir() {
		t.Errorf("the other directory: %v", err)
	}
	// CheckFS leaves the unavailable mount out and passes the other.
	validate(t, c)
}

// TestBuildUsersFileReadable: the users file holds passwords or their
// hashes, so one that all users can read is warned about, as a
// configuration file is, with a fix that keeps it readable to gosftpd's
// group; the mode the migration guide gives, 0640, passes.
func TestBuildUsersFileReadable(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "users.conf")
	write(t, file, "foo:"+secret+":::up\n")
	want := "the atmoz users file " + file + ": readable by all users, and it holds passwords or their hashes; let only gosftpd's group read it: chown root:" + strconv.Itoa(os.Getegid()) + " and chmod 0640 the file"
	for mode, warned := range map[os.FileMode]bool{0o644: true, 0o640: false, 0o600: false} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		m := build(t, Options{UsersFile: file, Home: t.TempDir()})
		if warns := validate(t, m.Config); hasWarning(warns, want) != warned || hasWarning(warns, "readable") != warned {
			t.Errorf("mode %04o: warnings %q", mode, warns)
		}
	}
}
