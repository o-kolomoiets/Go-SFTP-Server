// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// A writable mount on a read-only file system is a warning at start (and
// in config validate --check-fs) and at reload (ADR 0011). Tests cannot
// mount a file system read-only, so the statfs result is injected. Not
// parallel: it replaces readOnlyFS.
func TestReadOnlyFileSystemWarning(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"ro", "rw", "homes", "ro-mount"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The read-only file system holds ro, homes, ro-mount and new/.
	readOnly := []string{filepath.Join(dir, "ro"), filepath.Join(dir, "homes"), filepath.Join(dir, "ro-mount"), dir}
	var asked []string
	orig := readOnlyFS
	readOnlyFS = func(path string) (bool, error) {
		path = filepath.Clean(path)
		asked = append(asked, path)
		return slices.Contains(readOnly, path), nil
	}
	t.Cleanup(func() { readOnlyFS = orig })

	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["{dir}/hk"]
host_key_auto_generate = true
[mounts.ro]
path = "{dir}/ro"
[mounts.rw]
path = "{dir}/rw"
[mounts.home]
path = "{dir}/homes/{user}"
[mounts.new]
path = "{dir}/new/inbox"
create = true
[mounts.readonly]
path = "{dir}/ro-mount"
read_only = true
[users.alice]
authorized_keys = ["`+pubKey(t)+`"]
access = { ro = "full", rw = "full", home = "full", new = "full", readonly = "read" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	// The warning names the mount's path as the configuration has it.
	d := filepath.ToSlash(dir)
	want := []string{
		"mounts.home.path: " + d + "/homes/{user} is on a read-only file system; uploads will fail (under systemd: add it to ReadWritePaths=, docs/install.md)",
		"mounts.new.path: " + d + "/new/inbox is on a read-only file system; uploads will fail (under systemd: add it to ReadWritePaths=, docs/install.md)",
		"mounts.ro.path: " + d + "/ro is on a read-only file system; uploads will fail (under systemd: add it to ReadWritePaths=, docs/install.md)",
	}

	warns, err := c.CheckFS()
	if err != nil {
		t.Fatalf("CheckFS: %v", err)
	}
	if got := readOnlyWarnings(warns); !slices.Equal(got, want) {
		t.Errorf("CheckFS warnings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A read-only mount is never asked about; a {user} home by its parent,
	// a mount still to be created by the nearest directory that exists.
	if slices.Contains(asked, filepath.Join(dir, "ro-mount")) {
		t.Error("asked about a read-only mount")
	}
	for _, p := range []string{filepath.Join(dir, "homes"), dir} {
		if !slices.Contains(asked, p) {
			t.Errorf("did not ask about %s: %q", p, asked)
		}
	}

	warns, unavailable, err := c.CheckFSReload(nil)
	if err != nil || len(unavailable) != 0 {
		t.Fatalf("CheckFSReload: %v, unavailable %q", err, unavailable)
	}
	if got := readOnlyWarnings(warns); !slices.Equal(got, want) {
		t.Errorf("CheckFSReload warnings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// A statfs that fails says nothing.
	readOnlyFS = func(string) (bool, error) { return true, os.ErrPermission }
	warns, err = c.CheckFS()
	if err != nil || len(readOnlyWarnings(warns)) != 0 {
		t.Errorf("CheckFS with a failing statfs = %q, %v", warns, err)
	}
}

func readOnlyWarnings(warns []string) []string {
	var ro []string
	for _, w := range warns {
		if strings.Contains(w, "read-only file system") {
			ro = append(ro, w)
		}
	}
	slices.Sort(ro)
	return ro
}

// The real statfs: a temporary directory is writable.
func TestStatfsReadOnly(t *testing.T) {
	t.Parallel()

	if ro, err := statfsReadOnly(t.TempDir()); err != nil || ro {
		t.Errorf("statfsReadOnly(temp dir) = %v, %v", ro, err)
	}
	if _, err := statfsReadOnly(filepath.Join(t.TempDir(), "missing")); err == nil && runtime.GOOS != "windows" {
		t.Error("statfsReadOnly of a missing path: no error")
	}
}
