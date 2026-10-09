// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParsePerm(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]Perm{
		"read":                PermList | PermRead,
		"upload":              PermList | PermWrite | PermMkdir,
		"readwrite":           PermList | PermRead | PermWrite | PermOverwrite | PermRename | PermMkdir | PermSetstat,
		"full":                PermAll,
		"list,write":          PermList | PermWrite,
		"delete,rmdir,rename": PermDelete | PermRmdir | PermRename,
	} {
		got, err := ParsePerm(in)
		if err != nil || got != want {
			t.Errorf("ParsePerm(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if got, err := ParsePerm("\tlist , read\n"); err != nil || got != PermList|PermRead {
		t.Errorf("surrounding space: %v, %v", got, err)
	}
	for _, in := range []string{"", "admin", "list,", "list,exec", "Full"} {
		if _, err := ParsePerm(in); err == nil {
			t.Errorf("ParsePerm(%q) succeeded", in)
		}
	}
	if got := (PermList | PermWrite).String(); got != "list,write" {
		t.Errorf("String() = %q", got)
	}
	if got := (PermList | PermRead).String(); got != "read" {
		t.Errorf("String() = %q, want the preset name", got)
	}
	if got := PermNone.Flags(); got != "none" {
		t.Errorf("Flags() = %q", got)
	}
}

// permFixture returns a table with mounts "inbox" (base/inbox, a.txt) and
// "docs" (base/docs) using opts.
func permFixture(t *testing.T, opts MountOptions) (*Table, string) {
	t.Helper()
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "inbox", "a.txt"), "original")
	mustWrite(t, filepath.Join(base, "docs", "d.txt"), "doc")
	tbl, err := Open([]MountSpec{
		{Name: "inbox", Path: filepath.Join(base, "inbox"), Options: opts},
		{Name: "docs", Path: filepath.Join(base, "docs"), Options: opts},
	}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tbl.Close() })
	return tbl, base
}

func mustPerm(t *testing.T, s string) Perm {
	t.Helper()
	p, err := ParsePerm(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUploadPreset(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	inbox := filepath.Join(base, "inbox")

	// The only mount is flattened to "/"; docs is invisible.
	if s.flatten != true || len(s.Mounts()) != 1 {
		t.Fatalf("mounts = %v, flatten = %v", s.Mounts(), s.flatten)
	}
	if _, err := s.Stat("/a.txt"); err != nil {
		t.Errorf("Stat with list: %v", err)
	}
	if _, err := s.OpenRead("/a.txt"); !errors.Is(err, ErrDenied) {
		t.Errorf("OpenRead without read: %v", err)
	}
	if err := s.Mkdir("/sub"); err != nil {
		t.Errorf("Mkdir: %v", err)
	}
	for name, err := range map[string]error{
		"Remove": s.Remove("/a.txt"),
		"Rmdir":  s.Rmdir("/sub"),
	} {
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want ErrDenied", name, err)
		}
	}

	// New file: allowed. Existing file: a renamed copy, the original stays.
	if _, err := upload(t, s, "/new.txt", put, "n"); err != nil {
		t.Fatalf("new file: %v", err)
	}
	h, err := upload(t, s, "/a.txt", put, "copy")
	if err != nil || h.Path() != "/a (1).txt" {
		t.Fatalf("upload over existing = %v, %v", h, err)
	}
	if got := readFile(t, filepath.Join(inbox, "a.txt")); got != "original" {
		t.Errorf("original changed: %q", got)
	}

	// Times: allowed on files this session created, not on others.
	now := time.Now().Add(-time.Hour)
	if err := s.Setstat("/new.txt", Attrs{Atime: now, Mtime: now, HasTimes: true}); err != nil {
		t.Errorf("Setstat times on own file: %v", err)
	}
	// (/a.txt itself is redirected to this session's copy: stat_redirect.)
	mustWrite(t, filepath.Join(inbox, "other.txt"), "x")
	if err := s.Setstat("/other.txt", Attrs{Atime: now, Mtime: now, HasTimes: true}); !errors.Is(err, ErrDenied) {
		t.Errorf("Setstat times on another file: %v", err)
	}

	// Temp-name uploads: renaming an own file is allowed, others' is not.
	if _, err := upload(t, s, "/big.bin.filepart", put, "data"); err != nil {
		t.Fatal(err)
	}
	if final, err := s.Rename("/big.bin.filepart", "/big.bin", true); err != nil || final != "/big.bin" {
		t.Errorf("rename own temp file = %q, %v", final, err)
	}
	if err := s.Setstat("/big.bin", Attrs{Atime: now, Mtime: now, HasTimes: true}); err != nil {
		t.Errorf("Setstat after renaming own file: %v", err)
	}
	if _, err := s.Rename("/a.txt", "/b.txt", true); !errors.Is(err, ErrDenied) {
		t.Errorf("rename another file: %v", err)
	}
	if _, err := s.Rename("/sub", "/sub2", true); !errors.Is(err, ErrDenied) {
		t.Errorf("rename a directory: %v", err)
	}
	// Onto an existing name the rename policy keeps both.
	if _, err := upload(t, s, "/x.filepart", put, "x"); err != nil {
		t.Fatal(err)
	}
	if final, err := s.Rename("/x.filepart", "/a.txt", true); err != nil || final != "/a (2).txt" {
		t.Errorf("rename own file onto existing = %q, %v", final, err)
	}
	if got := readFile(t, filepath.Join(inbox, "a.txt")); got != "original" {
		t.Errorf("original changed: %q", got)
	}
}

// DoD M2: an upload user on an overwrite mount cannot replace a file, not
// even via a temporary name and rename.
func TestUploadCannotOverwrite(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.OnConflict = ConflictOverwrite
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})

	if _, err := s.OpenWrite("/a.txt", put); !errors.Is(err, ErrDenied) {
		t.Errorf("overwrite without the overwrite permission: %v", err)
	}
	if _, err := upload(t, s, "/a.txt.filepart", put, "evil"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rename("/a.txt.filepart", "/a.txt", true); !errors.Is(err, ErrDenied) {
		t.Errorf("replace via rename: %v", err)
	}
	if got := readFile(t, filepath.Join(base, "inbox", "a.txt")); got != "original" {
		t.Errorf("original changed: %q", got)
	}

	// With overwrite the same works.
	full := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: PermAll}})
	if _, err := full.Rename("/a.txt.filepart", "/a.txt", true); err != nil {
		t.Errorf("replace with overwrite: %v", err)
	}
}

func TestReadPresetAndGrants(t *testing.T) {
	t.Parallel()

	tbl, _ := permFixture(t, DefaultMountOptions())
	s, errs := tbl.Session("bob", []Grant{
		{Mount: "docs", Perm: mustPerm(t, "read")},
		{Mount: "inbox", Perm: mustPerm(t, "readwrite")},
		{Mount: "missing", Perm: PermAll},
	})
	defer s.Close()
	var me *MountError
	if len(errs) != 1 || !errors.As(errs[0], &me) || me.Mount != "missing" {
		t.Errorf("errs = %v, want one for the unknown mount", errs)
	}
	if s.flatten {
		t.Fatal("two mounts must not be flattened")
	}

	f, err := s.OpenRead("/docs/d.txt")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f.Close()
	if _, err := s.OpenWrite("/docs/new.txt", put); !errors.Is(err, ErrDenied) {
		t.Errorf("write with read: %v", err)
	}
	if err := s.Mkdir("/docs/sub"); !errors.Is(err, ErrDenied) {
		t.Errorf("mkdir with read: %v", err)
	}
	// readwrite has no delete.
	if err := s.Remove("/inbox/a.txt"); !errors.Is(err, ErrDenied) {
		t.Errorf("remove with readwrite: %v", err)
	}

	// The root lists the granted mounts, writable ones as 0755.
	l, err := s.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ls := make([]os.FileInfo, 10)
	n, _ := l.ListAt(ls, 0)
	got := map[string]fs.FileMode{}
	for _, fi := range ls[:n] {
		got[fi.Name()] = fi.Mode().Perm()
	}
	if len(got) != 2 || got["docs"] != 0o555 || got["inbox"] != 0o755 {
		t.Errorf("root listing = %v", got)
	}
}

func TestNoGrantNoAccess(t *testing.T) {
	t.Parallel()

	tbl, _ := permFixture(t, DefaultMountOptions())
	s := session(t, tbl, "nobody", nil)
	if _, err := s.Stat("/inbox/a.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat without a grant: %v", err)
	}
	l, err := s.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := l.ListAt(make([]os.FileInfo, 4), 0); n != 0 {
		t.Errorf("root lists %d entries", n)
	}
}

func TestSetstatModes(t *testing.T) {
	t.Parallel()

	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tt := range []struct {
		mode    SetstatMode
		wantErr error
		applied bool
	}{
		{SetstatTimes, nil, true},
		{SetstatIgnore, nil, false},
		{SetstatDeny, ErrDenied, false},
	} {
		opts := DefaultMountOptions()
		opts.SetstatMode = tt.mode
		tbl, base := permFixture(t, opts)
		s := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: PermAll}})

		err := s.Setstat("/a.txt", Attrs{Atime: when, Mtime: when, HasTimes: true})
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: Setstat = %v, want %v", tt.mode, err, tt.wantErr)
		}
		fi, _ := os.Stat(filepath.Join(base, "inbox", "a.txt"))
		if applied := fi.ModTime().Equal(when); applied != tt.applied {
			t.Errorf("%s: times applied = %v", tt.mode, applied)
		}

		// A size change on this session's own upload works in every mode.
		h, err := s.OpenWrite("/n.txt", put)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("12345"), 0); err != nil {
			t.Fatal(err)
		}
		if err := s.Setstat("/n.txt", Attrs{Size: 2, HasSize: true}); err != nil {
			t.Errorf("%s: truncate own upload: %v", tt.mode, err)
		}
		_ = h.Close(false)
	}
}

func TestUmask(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}

	opts := DefaultMountOptions()
	opts.Umask = 0o077
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: PermAll}})
	if _, err := upload(t, s, "/f.txt", put, "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]fs.FileMode{"f.txt": 0o600, "d": 0o700} {
		fi, err := os.Stat(filepath.Join(base, "inbox", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got&^want != 0 {
			t.Errorf("%s: mode %#o, want at most %#o", name, got, want)
		}
	}
}

func TestRenameTemplate(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.RenameTemplate = "{stem}_copy{n}{ext}"
	opts.MaxRenameAttempts = 2
	tbl, _ := permFixture(t, opts)
	s := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: PermAll}})

	var got []string
	for range 3 {
		h, err := upload(t, s, "/a.txt", put, "x")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, h.Path())
	}
	if got[0] != "/a_copy1.txt" || got[1] != "/a_copy2.txt" {
		t.Errorf("names = %q", got)
	}
	// Attempts exhausted: a timestamped name from the same template.
	if len(got[2]) != len("/a_copy20060102T150405Z-abcd.txt") {
		t.Errorf("fallback name = %q", got[2])
	}
}

func TestValidateOptions(t *testing.T) {
	t.Parallel()

	if err := DefaultMountOptions().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, mod := range map[string]func(*MountOptions){
		"policy":       func(o *MountOptions) { o.OnConflict = "merge" },
		"versions dir": func(o *MountOptions) { o.Versions.Dir = "a/b" },
		"temp dir":     func(o *MountOptions) { o.Versions.Dir = ".gosftpd-x" },
		"keep":         func(o *MountOptions) { o.Versions.Keep = -1 },
		"max age":      func(o *MountOptions) { o.Versions.MaxAge = -time.Hour },
		"max size":     func(o *MountOptions) { o.MaxFileSize = -1 },
		"no {n}":       func(o *MountOptions) { o.RenameTemplate = "{stem} copy{ext}" },
		"two {n}":      func(o *MountOptions) { o.RenameTemplate = "{stem} {n}-{n}{ext}" },
		"long":         func(o *MountOptions) { o.RenameTemplate = strings.Repeat("x", 62) + "{n}" },
		"not UTF-8":    func(o *MountOptions) { o.RenameTemplate = "\xff{n}" },
		"slash":        func(o *MountOptions) { o.RenameTemplate = "{stem}/{n}{ext}" },
		"placeholder":  func(o *MountOptions) { o.RenameTemplate = "{stem} {date} {n}{ext}" },
		"attempts":     func(o *MountOptions) { o.MaxRenameAttempts = 0 },
		"compound ext": func(o *MountOptions) { o.CompoundExts = []string{"tar.gz"} },
		"setstat":      func(o *MountOptions) { o.SetstatMode = "chmod" },
		"umask":        func(o *MountOptions) { o.Umask = 0o1022 },
	} {
		o := DefaultMountOptions()
		mod(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
}

func TestValidMountName(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]bool{
		"inbox": true, "My Files": true, "a.b_c-d": true,
		"": false, ".hidden": false, "a/b": false, "con": false, "COM1.txt": false, "nul ": false,
	} {
		if got := ValidMountName(name); got != want {
			t.Errorf("ValidMountName(%q) = %v", name, got)
		}
	}
}

// Review finding: an aborted empty upload must not delete a file that
// another user put at its path after this session renamed its own file away.
func TestAbortedUploadKeepsOthersFile(t *testing.T) {
	t.Parallel()

	tbl, base := permFixture(t, DefaultMountOptions())
	inbox := filepath.Join(base, "inbox")
	attacker := session(t, tbl, "attacker", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	partner := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})

	h, err := attacker.OpenWrite("/report.csv", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.Rename("/report.csv", "/junk", true); err != nil {
		t.Fatal(err)
	}
	if _, err := upload(t, partner, "/report.csv", put, "partner's data"); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(inbox, "report.csv")); got != "partner's data" {
		t.Errorf("partner's file = %q", got)
	}
}

// Review finding: with the overwrite policy another user may write into the
// file an aborted upload created; it must survive.
func TestAbortedUploadKeepsDataWrittenByOthers(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.OnConflict = ConflictOverwrite
	tbl, base := permFixture(t, opts)
	alice := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: PermAll}})

	h, err := alice.OpenWrite("/new.csv", put)
	if err != nil {
		t.Fatal(err)
	}
	// While alice's upload is open nobody else may write the file in place.
	if _, err := bob.OpenWrite("/new.csv", put); !errors.Is(err, ErrBusy) {
		t.Fatalf("second writer: %v", err)
	}
	if err := h.Close(true); err != nil {
		t.Fatal(err)
	}
	if _, err := upload(t, bob, "/new.csv", put, "bob's data"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(base, "inbox", "new.csv")); got != "bob's data" {
		t.Errorf("bob's file = %q", got)
	}
}

// Review finding: "created by this session" follows the file, not the path.
func TestCreatedIsTiedToTheFile(t *testing.T) {
	t.Parallel()

	tbl, base := permFixture(t, DefaultMountOptions())
	a := session(t, tbl, "a", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	b := session(t, tbl, "b", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	c := session(t, tbl, "c", []Grant{{Mount: "inbox", Perm: PermAll}})

	if _, err := upload(t, a, "/export.csv", put, "a"); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove("/export.csv"); err != nil {
		t.Fatal(err)
	}
	if _, err := upload(t, b, "/export.csv", put, "b"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Rename("/export.csv", "/hidden.csv", true); !errors.Is(err, ErrDenied) {
		t.Errorf("rename of another user's file at an own path: %v", err)
	}
	when := time.Now().Add(-time.Hour)
	if err := a.Setstat("/export.csv", Attrs{Atime: when, Mtime: when, HasTimes: true}); !errors.Is(err, ErrDenied) {
		t.Errorf("setstat of another user's file at an own path: %v", err)
	}
	if got := readFile(t, filepath.Join(base, "inbox", "export.csv")); got != "b" {
		t.Errorf("export.csv = %q", got)
	}
}

// Review finding: a granted home that is unavailable must not flatten the
// remaining mount, or /home/x would land in the shared one.
func TestUnavailableMountKeepsLayout(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "share", "a.txt"), "a")
	if err := os.MkdirAll(filepath.Join(base, "homes"), 0o755); err != nil {
		t.Fatal(err)
	}
	tbl, err := Open([]MountSpec{
		spec("share", filepath.Join(base, "share"), ConflictRename),
		spec("home", filepath.Join(base, "homes", UserPlaceholder), ConflictRename),
	}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s, errs := tbl.Session("alice", []Grant{{Mount: "share", Perm: PermAll}, {Mount: "home", Perm: PermAll}})
	defer s.Close()
	if len(errs) != 1 || s.flatten {
		t.Fatalf("errs = %v, flatten = %v", errs, s.flatten)
	}
	if _, err := s.OpenWrite("/home/private.txt", put); err == nil {
		t.Error("upload to the unavailable home succeeded")
	}
	if _, err := os.Stat(filepath.Join(base, "share", "home")); err == nil {
		t.Error("upload landed in the shared mount")
	}
	if _, err := s.Stat("/share/a.txt"); err != nil {
		t.Errorf("share: %v", err)
	}
}

// Review finding: removal enforces the entry type itself.
func TestRemoveEntryEnforcesType(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("no unlinkat")
	}

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "f"), "x")
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := removeEntry(root, "f", true); err == nil {
		t.Error("rmdir removed a file")
	}
	if err := removeEntry(root, "d", false); err == nil {
		t.Error("remove removed a directory")
	}
	for _, name := range []string{"f", "d"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := removeEntry(root, "f", false); err != nil {
		t.Errorf("remove file: %v", err)
	}
	if err := removeEntry(root, "d", true); err != nil {
		t.Errorf("remove dir: %v", err)
	}
}
