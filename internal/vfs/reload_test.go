// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reloadFixture opens a table with the mounts "keep" and "move" and returns
// it with its base directory.
func reloadFixture(t *testing.T) (*Table, string) {
	t.Helper()
	base := t.TempDir()
	for _, d := range []string{"keep", "move", "moved"} {
		mustWrite(t, filepath.Join(base, d, "f.txt"), d)
	}
	tbl, err := Open([]MountSpec{
		spec("keep", filepath.Join(base, "keep"), ConflictRename),
		spec("move", filepath.Join(base, "move"), ConflictRename),
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return tbl, base
}

func readVirtual(t *testing.T, s *Session, vp string) string {
	t.Helper()
	r, err := s.OpenRead(vp)
	if err != nil {
		t.Fatalf("OpenRead(%s): %v", vp, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A reload keeps the directories of unchanged mounts, opens changed and new
// ones, and closes a directory with the last generation that uses it.
func TestReloadGenerations(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	old := session(t, t1, "alice", t1.FullAccess())
	o := DefaultMountOptions()
	o.OnConflict = ConflictOverwrite // options may change, the directory stays
	t2, warns, err := t1.Reload([]MountSpec{
		{Name: "keep", Path: filepath.Join(base, "keep") + "/", Options: o},
		spec("move", filepath.Join(base, "moved"), ConflictRename),
	}, Options{})
	if err != nil || len(warns) > 0 {
		t.Fatal(err, warns)
	}
	if t2.Mount("keep").dir != t1.Mount("keep").dir {
		t.Error("an unchanged mount got a new directory")
	}
	if t2.Mount("move").dir == t1.Mount("move").dir {
		t.Error("a repointed mount kept its directory")
	}
	if t2.Mount("keep").Options().OnConflict != ConflictOverwrite {
		t.Error("the new options do not apply")
	}
	if t2.registry != t1.registry {
		t.Error("the generations do not share the registry")
	}
	cur := session(t, t2, "alice", t2.FullAccess())
	if got := readVirtual(t, cur, "/move/f.txt"); got != "moved" {
		t.Errorf("new generation reads %q", got)
	}
	if got := readVirtual(t, old, "/move/f.txt"); got != "move" {
		t.Errorf("a session of the old generation reads %q", got)
	}

	if err := t1.Close(); err != nil {
		t.Fatal(err)
	}
	if t1.Acquire() {
		t.Error("Acquire succeeded after the last reference was dropped")
	}
	if _, err := t1.Mount("move").root.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the old directory of a repointed mount is open: %v", err)
	}
	if got := readVirtual(t, cur, "/keep/f.txt"); got != "keep" {
		t.Errorf("a shared directory closed with the old generation: %q", got)
	}
	if !t2.Acquire() {
		t.Fatal("Acquire failed on an open table")
	}
	_ = t2.Close()
	if got := readVirtual(t, cur, "/keep/f.txt"); got != "keep" {
		t.Errorf("a table closed with references left: %q", got)
	}
	if err := t2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := t2.Mount("keep").root.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the last generation left a directory open: %v", err)
	}
}

// A directory replaced at the same path, as by a disk mounted over it, is
// opened anew; the old generation keeps the old one.
func TestReloadReplacedDirectory(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	old := session(t, t1, "alice", t1.FullAccess())
	keep := filepath.Join(base, "keep")
	if err := os.Rename(keep, filepath.Join(base, "keep.old")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(keep, "f.txt"), "replaced")
	t2, _, err := t1.Reload([]MountSpec{spec("keep", keep, ConflictRename)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	if t2.Mount("keep").dir == t1.Mount("keep").dir {
		t.Error("a replaced directory was reused")
	}
	if got := readVirtual(t, session(t, t2, "alice", t2.FullAccess()), "/keep/f.txt"); got != "replaced" {
		t.Errorf("new generation reads %q", got)
	}
	if got := readVirtual(t, old, "/keep/f.txt"); got != "keep" {
		t.Errorf("old generation reads %q", got)
	}
}

// A mount that cannot be opened is unavailable in the new generation; the
// other mounts keep their directories and their paths.
func TestReloadUnavailableMount(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	mustWrite(t, filepath.Join(base, "file"), "not a directory")
	t2, warns, err := t1.Reload([]MountSpec{
		spec("keep", filepath.Join(base, "keep"), ConflictRename),
		spec("zfile", filepath.Join(base, "file"), ConflictRename),
	}, Options{Flatten: true, Unavailable: []string{"disk"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	if len(warns) != 1 || !strings.Contains(warns[0].Error(), "zfile") {
		t.Errorf("warnings = %v", warns)
	}
	if t1.Mount("keep").dir.refs != 2 {
		t.Errorf("shared directory has %d references, want 2", t1.Mount("keep").dir.refs)
	}
	if t2.Flattened() {
		t.Error("a table with unavailable mounts is flattened")
	}
	if g := t2.FullAccess(); len(g) != 3 {
		t.Errorf("FullAccess = %v, want every configured mount", g)
	}
	// Granted keep and disk: keep stays at /keep, not "/", so that uploads
	// meant for /disk/x cannot land in keep.
	s, errs := t2.Session("alice", []Grant{{"keep", PermAll}, {"disk", PermAll}, {"disk", PermAll}})
	defer s.Close()
	if len(errs) != 1 || !errors.Is(errs[0], ErrUnavailable) {
		t.Errorf("session errors = %v", errs)
	}
	if got := readVirtual(t, s, "/keep/f.txt"); got != "keep" {
		t.Errorf("read %q", got)
	}

	t3, _, err := t1.Reload(nil, Options{Unavailable: []string{"keep"}})
	if err != nil {
		t.Fatalf("reload with every mount unavailable: %v", err)
	}
	_ = t3.Close()
	if got := readVirtual(t, session(t, t1, "alice", t1.FullAccess()), "/keep/f.txt"); got != "keep" {
		t.Errorf("after releasing a generation: %q", got)
	}
}

// Generations share the registries: one writer per file, and a redirect
// made for a directory does not apply to a mount repointed elsewhere.
func TestReloadSharesRegistry(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	t2, _, err := t1.Reload([]MountSpec{
		spec("keep", filepath.Join(base, "keep"), ConflictRename),
		spec("move", filepath.Join(base, "moved"), ConflictRename),
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	old := session(t, t1, "alice", t1.FullAccess())
	cur := session(t, t2, "alice", t2.FullAccess())

	h, err := old.OpenWrite("/keep/new.txt", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cur.OpenWrite("/keep/new.txt", OpenFlags{Write: true}); !errors.Is(err, ErrBusy) {
		t.Errorf("second writer across generations: %v", err)
	}
	if !cur.isCreated(cur.byName["keep"], "new.txt") {
		t.Error("an upload open in the old generation is not the user's in the new one")
	}
	_ = h.Close(false)

	// The rename policy on the old directory redirects f.txt to "f (1).txt".
	if h, err := upload(t, old, "/move/f.txt", put, "x"); err != nil || h.Path() != "/move/f (1).txt" {
		t.Fatalf("upload: %v, %v", h, err)
	}
	if fi, err := cur.Stat("/move/f.txt"); err != nil || fi.Size() != int64(len("moved")) {
		t.Errorf("a redirect of the old directory applied to the new one: %v, %v", fi, err)
	}
	if fi, err := old.Stat("/move/f.txt"); err != nil || fi.Size() != 1 {
		t.Errorf("the redirect is lost in its own generation: %v, %v", fi, err)
	}
}

func TestReloadValidates(t *testing.T) {
	t.Parallel()

	t1, _ := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	if _, _, err := t1.Reload(nil, Options{}); err == nil {
		t.Error("reload without mounts succeeded")
	}
	if _, _, err := t1.Reload([]MountSpec{spec("x", "relative", ConflictRename)}, Options{}); err == nil {
		t.Error("reload with a relative path succeeded")
	}
}

// A directory still used by an old generation is shared with a later one
// even when a generation in between left the mount out.
func TestReloadSharesSkippedDirectory(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	keep := spec("keep", filepath.Join(base, "keep"), ConflictRename)
	t2, _, err := t1.Reload([]MountSpec{spec("move", filepath.Join(base, "move"), ConflictRename)}, Options{Unavailable: []string{"keep"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	t3, _, err := t2.Reload([]MountSpec{keep}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t3.Close() })
	if t3.Mount("keep").dir != t1.Mount("keep").dir {
		t.Error("a directory still in use was opened a second time")
	}
}

// A home mount does not share its directory with a plain mount of the same
// directory: registry entries are relative to different roots.
func TestReloadHomeDoesNotSharePlain(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "h", "alice", "f.txt"), "home")
	t1, err := Open([]MountSpec{spec("data", filepath.Join(base, "h"), ConflictRename)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t1.Close() })
	t2, _, err := t1.Reload([]MountSpec{spec("homes", filepath.Join(base, "h", UserPlaceholder), ConflictRename)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	if t2.Mount("homes").dir == t1.Mount("data").dir {
		t.Error("a home mount shares the directory of a plain mount")
	}
}

// A reload that takes the write permission away also ends the uploader's
// right to set the times of its own uploads.
func TestReloadRevokedWriteEndsOwnSetstat(t *testing.T) {
	t.Parallel()

	t1, base := reloadFixture(t)
	t.Cleanup(func() { t1.Close() })
	up := session(t, t1, "alice", []Grant{{"keep", PermList | PermWrite}})
	if _, err := upload(t, up, "/keep/x.txt", put, "x"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	times := Attrs{Atime: now, Mtime: now, HasTimes: true}
	if err := up.Setstat("/keep/x.txt", times); err != nil {
		t.Fatalf("an uploader cannot set the times of its upload: %v", err)
	}
	t2, _, err := t1.Reload([]MountSpec{spec("keep", filepath.Join(base, "keep"), ConflictRename)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2.Close() })
	read := session(t, t2, "alice", []Grant{{"keep", PermList | PermRead}})
	if err := read.Setstat("/keep/x.txt", times); !errors.Is(err, ErrDenied) {
		t.Errorf("Setstat without write after a reload: %v", err)
	}
}
