// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestHeldDirs: one directory per mount, sorted by name; a {user} mount
// holds the parent of {user}; a reload keeps what an unchanged mount
// holds.
func TestHeldDirs(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for _, d := range []string{"data", "homes"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	specs := []MountSpec{
		spec("homes", filepath.Join(base, "homes", UserPlaceholder), ConflictRename),
		spec("data", filepath.Join(base, "data"), ConflictRename),
	}
	tbl, err := Open(specs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	held := tbl.HeldDirs()
	if len(held) != 2 || held[0].Mount != "data" || held[1].Mount != "homes" {
		t.Fatalf("HeldDirs = %+v", held)
	}
	for i, dir := range []string{filepath.Join(base, "data"), filepath.Join(base, "homes")} {
		checkHeld(t, held[i], dir)
	}

	next, warns, err := tbl.Reload(specs[1:], Options{})
	if err != nil || len(warns) != 0 {
		t.Fatal(err, warns)
	}
	defer next.Close()
	if again := next.HeldDirs(); len(again) != 1 || again[0] != held[0] {
		t.Errorf("after a reload: %+v, want %+v", again, held[0])
	}
	if runtime.GOOS != "linux" && (held[0].FD != -1 || held[0].Dev != 0) {
		t.Errorf("a descriptor where there is no Landlock: %+v", held[0])
	}
}
