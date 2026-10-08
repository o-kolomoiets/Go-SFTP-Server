// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// homeFixture returns a table with a home mount <base>/home/{user} and the
// base directory, which also holds outside/secret.txt.
func homeFixture(t *testing.T, create bool) (*Table, string) {
	t.Helper()
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "outside", "secret.txt"), "secret")
	if !create {
		if err := os.MkdirAll(filepath.Join(base, "home"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := spec("home", filepath.Join(base, "home", UserPlaceholder), ConflictRename)
	s.Create = create
	tbl, err := Open([]MountSpec{s}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tbl.Close() })
	return tbl, base
}

var homeGrant = []Grant{{Mount: "home", Perm: PermAll}}

func TestHomeCreated(t *testing.T) {
	t.Parallel()

	tbl, base := homeFixture(t, true)
	alice := session(t, tbl, "alice", homeGrant)
	bob := session(t, tbl, "bob", homeGrant)

	fi, err := os.Stat(filepath.Join(base, "home", "alice"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("home not created: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&^homeDirPerm != 0 {
		t.Errorf("home mode = %#o", fi.Mode().Perm())
	}
	if _, err := upload(t, alice, "/a.txt", put, "alice's"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(base, "home", "alice", "a.txt")); got != "alice's" {
		t.Errorf("a.txt = %q", got)
	}
	// Bob has his own empty home and cannot reach Alice's.
	for _, p := range []string{"/a.txt", "/../alice/a.txt", "../../alice/a.txt"} {
		if _, err := bob.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("bob Stat(%q) = %v", p, err)
		}
	}
	if !tbl.Mount("home").Home() {
		t.Error("Home() = false")
	}
}

func TestHomeMissing(t *testing.T) {
	t.Parallel()

	tbl, base := homeFixture(t, false)
	s, errs := tbl.Session("alice", homeGrant)
	defer s.Close()
	if len(errs) != 1 || !errors.Is(errs[0], ErrHomeMissing) {
		t.Fatalf("errs = %v, want ErrHomeMissing", errs)
	}
	if len(s.Mounts()) != 0 {
		t.Errorf("mounts = %v", s.Mounts())
	}
	if _, err := os.Stat(filepath.Join(base, "home", "alice")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("home created without create = true: %v", err)
	}
}

// ST-12: a home replaced by a symlink, outside or to another user's home,
// makes the mount unavailable; nothing is created or read through it.
func TestHomeSymlinkRefused(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]func(base string) string{
		"outside":  func(base string) string { return filepath.Join(base, "outside") },
		"relative": func(string) string { return filepath.Join("..", "outside") },
		"bob":      func(string) string { return "bob" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tbl, base := homeFixture(t, true)
			home := filepath.Join(base, "home")
			if err := os.MkdirAll(filepath.Join(home, "bob"), 0o755); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(home, "bob", "b.txt"), "bob's")
			symlink(t, target(base), filepath.Join(home, "alice"))

			s, errs := tbl.Session("alice", homeGrant)
			defer s.Close()
			if len(errs) != 1 || !errors.Is(errs[0], ErrHomeNotDir) {
				t.Fatalf("errs = %v, want ErrHomeNotDir", errs)
			}
			if len(s.Mounts()) != 0 {
				t.Fatalf("mount available: %v", s.Mounts())
			}
			for _, p := range []string{"/secret.txt", "/b.txt", "/home/b.txt"} {
				if _, err := s.Stat(p); err == nil {
					t.Errorf("Stat(%q) succeeded", p)
				}
			}
			if _, err := s.OpenWrite("/x.txt", put); err == nil {
				t.Error("upload succeeded")
			}
			if _, err := os.Stat(filepath.Join(base, "outside", "x.txt")); err == nil {
				t.Error("file created outside")
			}
		})
	}
}

func TestHomeFileRefused(t *testing.T) {
	t.Parallel()

	tbl, base := homeFixture(t, true)
	mustWrite(t, filepath.Join(base, "home", "alice"), "not a dir")
	s, errs := tbl.Session("alice", homeGrant)
	defer s.Close()
	if len(errs) != 1 || !errors.Is(errs[0], ErrHomeNotDir) {
		t.Fatalf("errs = %v, want ErrHomeNotDir", errs)
	}
}

func TestHomeBadUserName(t *testing.T) {
	t.Parallel()

	tbl, _ := homeFixture(t, true)
	for _, user := range []string{"", ".", "..", "a/b", `a\b`} {
		s, errs := tbl.Session(user, homeGrant)
		s.Close()
		if len(errs) != 1 {
			t.Errorf("user %q: errs = %v", user, errs)
		}
	}
}
