// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// displayed returns a spec of name at path that clients see as display.
func displayed(name, display, path string, policy ConflictPolicy) MountSpec {
	s := spec(name, path, policy)
	s.Display = display
	return s
}

// rootNames lists the names in the session's root.
func rootNames(t *testing.T, s *Session) []string {
	t.Helper()
	l, err := s.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ls := make([]os.FileInfo, 10)
	n, err := l.ListAt(ls, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	names := make([]string, n)
	for i, fi := range ls[:n] {
		names[i] = fi.Name()
	}
	return names
}

// TestDisplayNamesKeptApart: two users each see /upload, on different host
// paths (atmoz mode, ADR 0012). Lookup, listing, file infos and every name
// an event reports use the visible name, never the internal one, and the
// rename policy and stat redirects of one user's upload never reach the
// other's directory.
func TestDisplayNamesKeptApart(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	alice, bob := filepath.Join(base, "alice", "upload"), filepath.Join(base, "bob", "upload")
	mustWrite(t, filepath.Join(alice, "x.txt"), "alice's")
	mustWrite(t, filepath.Join(bob, "x.txt"), "bob's file")
	tbl, err := Open([]MountSpec{
		displayed("atmoz1", "upload", alice, ConflictRename),
		displayed("atmoz2", "upload", bob, ConflictRename),
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	sa := session(t, tbl, "alice", []Grant{{Mount: "atmoz1", Perm: PermAll}})
	sb := session(t, tbl, "bob", []Grant{{Mount: "atmoz2", Perm: PermAll}})

	for _, s := range []*Session{sa, sb} {
		if got := s.Mounts(); !slices.Equal(got, []string{"upload"}) {
			t.Errorf("%s: Mounts() = %v", s.User(), got)
		}
		if got := rootNames(t, s); !slices.Equal(got, []string{"upload"}) {
			t.Errorf("%s: root lists %v", s.User(), got)
		}
		if fi, err := s.Stat("/upload"); err != nil || fi.Name() != "upload" || !fi.IsDir() {
			t.Errorf("%s: Stat(/upload) = %v, %v", s.User(), fi, err)
		}
		if _, err := s.Stat("/atmoz1"); err == nil {
			t.Errorf("%s: the internal name resolves", s.User())
		}
		if m := s.MountOf("/upload/x.txt"); m != "upload" {
			t.Errorf("%s: MountOf = %q", s.User(), m)
		}
		if w := s.Locate("/upload/x.txt"); w.Mount != "upload" || w.Info == nil {
			t.Errorf("%s: Locate = %+v", s.User(), w)
		}
	}

	h, err := upload(t, sa, "/upload/x.txt", put, "alice's upload")
	if err != nil {
		t.Fatal(err)
	}
	if h.Path() != "/upload/x (1).txt" || h.Conflict() != ConflictRenamed {
		t.Errorf("alice's upload went to %q (%s)", h.Path(), h.Conflict())
	}
	if w := h.Located(); w.Mount != "upload" || w.HostPath != filepath.Join(alice, "x (1).txt") {
		t.Errorf("Located = %+v", w)
	}
	// alice's stat redirect answers for her copy; bob's x.txt is his own.
	if fi, err := sa.Stat("/upload/x.txt"); err != nil || fi.Size() != int64(len("alice's upload")) {
		t.Errorf("alice: Stat(/upload/x.txt) = %v, %v; want her upload through the redirect", fi, err)
	}
	if fi, err := sb.Stat("/upload/x.txt"); err != nil || fi.Size() != int64(len("bob's file")) {
		t.Errorf("bob: Stat(/upload/x.txt) = %v, %v; want his own file", fi, err)
	}
	if _, err := os.Stat(filepath.Join(bob, "x (1).txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("alice's upload reached bob's directory: %v", err)
	}

	// A move onto an existing name is renamed in bob's directory only.
	if _, err := upload(t, sb, "/upload/y.txt", put, "y"); err != nil {
		t.Fatal(err)
	}
	m, err := sb.Move("/upload/y.txt", "/upload/x.txt", true)
	if err != nil || m.Final != "/upload/x (1).txt" || m.Where.Mount != "upload" {
		t.Errorf("bob's move = %+v, %v", m, err)
	}
	if got := readFile(t, filepath.Join(bob, "x (1).txt")); got != "y" {
		t.Errorf("bob's x (1).txt = %q", got)
	}
	if got := readFile(t, filepath.Join(alice, "x (1).txt")); got != "alice's upload" {
		t.Errorf("alice's x (1).txt = %q", got)
	}
	if fi, err := sa.Stat("/upload/x.txt"); err != nil || fi.Size() != int64(len("alice's upload")) {
		t.Errorf("alice: Stat(/upload/x.txt) after bob's move = %v, %v", fi, err)
	}
	if fi, err := sb.Stat("/upload/x.txt"); err != nil || fi.Size() != 1 {
		t.Errorf("bob: Stat(/upload/x.txt) after his move = %v, %v; want y through his redirect", fi, err)
	}
}

// TestDisplayNameClash: a session refuses a mount whose visible name
// equals that of another of its mounts ignoring case; the first one works.
func TestDisplayNameClash(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tbl, err := Open([]MountSpec{
		displayed("atmoz1", "upload", a, ConflictRename),
		displayed("atmoz2", "Upload", b, ConflictRename),
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s, errs := tbl.Session("alice", tbl.FullAccess())
	defer s.Close()
	var me *MountError
	if len(errs) != 1 || !errors.As(errs[0], &me) || me.Mount != "Upload" || !errors.Is(errs[0], ErrNameClash) {
		t.Fatalf("errors = %v, want a name clash of Upload", errs)
	}
	if want := `mount "Upload": the name differs only in case from that of mount "upload"`; errs[0].Error() != want {
		t.Errorf("error = %q, want %q", errs[0], want)
	}
	if got := s.Mounts(); !slices.Equal(got, []string{"upload"}) {
		t.Errorf("Mounts() = %v", got)
	}
	if _, err := upload(t, s, "/upload/f", put, "data"); err != nil {
		t.Errorf("upload to the first mount: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a, "f")); err != nil {
		t.Error(err)
	}
}

// TestUnavailableSpec: a spec named in Options.Unavailable is not opened,
// and a session granted it reports it under its visible name.
func TestUnavailableSpec(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	ok := filepath.Join(base, "ok")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "missing") // not created: Create is off
	tbl, err := Open([]MountSpec{
		displayed("atmoz1", "upload", ok, ConflictOverwrite),
		displayed("atmoz2", "inbox", missing, ConflictOverwrite),
	}, Options{Unavailable: []string{"atmoz2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	if tbl.Mount("atmoz2") != nil || len(tbl.Mounts()) != 1 {
		t.Errorf("the unavailable mount was opened: %v", tbl.Mounts())
	}
	s, errs := tbl.Session("alice", []Grant{{Mount: "atmoz1", Perm: PermAll}, {Mount: "atmoz2", Perm: PermAll}})
	defer s.Close()
	var me *MountError
	if len(errs) != 1 || !errors.As(errs[0], &me) || me.Mount != "inbox" || !errors.Is(errs[0], ErrUnavailable) {
		t.Fatalf("errors = %v, want inbox unavailable", errs)
	}
	if got := rootNames(t, s); !slices.Equal(got, []string{"upload"}) {
		t.Errorf("root lists %v", got)
	}
	if s.flatten {
		t.Error("flattened although a granted mount is unavailable")
	}
	if _, err := s.Stat("/inbox"); err == nil {
		t.Error("the unavailable mount resolves")
	}
}

// TestEmptyTable: without mounts Open fails, unless AllowEmpty, which
// gives an empty read-only root.
func TestEmptyTable(t *testing.T) {
	t.Parallel()

	if _, err := Open(nil, Options{}); err == nil {
		t.Error("Open without mounts succeeded")
	}
	tbl, err := Open(nil, Options{AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s := session(t, tbl, "alice", nil)
	if got := rootNames(t, s); len(got) != 0 {
		t.Errorf("root lists %v", got)
	}
	if fi, err := s.Stat("/"); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o555 {
		t.Errorf("Stat(/) = %v, %v", fi, err)
	}
	if _, err := s.OpenWrite("/f", put); !errors.Is(err, ErrDenied) {
		t.Errorf("upload into the empty root: %v", err)
	}
	if err := s.Mkdir("/d"); !errors.Is(err, ErrDenied) {
		t.Errorf("Mkdir in the empty root: %v", err)
	}
}

// TestDisplayValidated: a visible name must be a valid mount name.
func TestDisplayValidated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, d := range []string{".ssh", "a/b", "NUL", "_data"} {
		if err := ValidateSpecs([]MountSpec{displayed("atmoz1", d, dir, ConflictRename)}); err == nil {
			t.Errorf("visible name %q accepted", d)
		}
	}
	if err := ValidateSpecs([]MountSpec{displayed("atmoz1", "upload", filepath.Join(dir, "a"), ConflictRename), displayed("atmoz2", "upload", filepath.Join(dir, "b"), ConflictRename)}); err != nil {
		t.Errorf("two mounts with the same visible name: %v", err)
	}
}
