// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var (
	reput    = OpenFlags{Write: true, Creat: true, Append: true} // OpenSSH reput
	writeOff = OpenFlags{Write: true}                            // Cyberduck
)

func TestResumeAppendOnly(t *testing.T) {
	t.Parallel()

	for _, fl := range []OpenFlags{reput, writeOff} {
		tbl, base := permFixture(t, DefaultMountOptions()) // inbox/a.txt = "original"
		s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})

		h, err := s.OpenWrite("/a.txt", fl)
		if err != nil {
			t.Fatalf("%+v: %v", fl, err)
		}
		if off, ok := h.StartOffset(); !ok || off != 8 || h.Path() != "/a.txt" || h.Conflict() != ConflictNone {
			t.Errorf("%+v: start %d %v, path %q, conflict %q", fl, off, ok, h.Path(), h.Conflict())
		}
		// DoD M2: writing at offset 0 into an existing file is refused.
		if _, err := h.WriteAt([]byte("EVIL"), 0); !errors.Is(err, ErrImmutable) {
			t.Errorf("%+v: write below the start: %v", fl, err)
		}
		if _, err := h.WriteAt([]byte(" and more"), 8); err != nil {
			t.Errorf("%+v: append: %v", fl, err)
		}
		if err := s.Setstat("/a.txt", Attrs{Size: 4, HasSize: true}); !errors.Is(err, ErrImmutable) {
			t.Errorf("%+v: truncate below the start: %v", fl, err)
		}
		if err := s.Setstat("/a.txt", Attrs{Size: 12, HasSize: true}); err != nil {
			t.Errorf("%+v: truncate above the start: %v", fl, err)
		}
		if err := h.Close(false); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, filepath.Join(base, "inbox", "a.txt")); got != "original and" {
			t.Errorf("%+v: a.txt = %q", fl, got)
		}
	}
}

func TestResumeModes(t *testing.T) {
	t.Parallel()

	off := DefaultMountOptions()
	off.Resume = ResumeOff
	tbl, _ := permFixture(t, off)
	s := session(t, tbl, "u", []Grant{{Mount: "inbox", Perm: PermAll}})
	if _, err := s.OpenWrite("/a.txt", reput); !errors.Is(err, ErrResumeDisabled) {
		t.Errorf("resume = off: %v", err)
	}

	// Reading users cannot resume.
	tbl, _ = permFixture(t, DefaultMountOptions())
	r := session(t, tbl, "r", []Grant{{Mount: "inbox", Perm: mustPerm(t, "read")}})
	if _, err := r.OpenWrite("/a.txt", reput); !errors.Is(err, ErrDenied) {
		t.Errorf("read preset: %v", err)
	}

	// Overwrite policy: a plain write with the overwrite permission, the
	// append-only guard without it.
	ow := DefaultMountOptions()
	ow.OnConflict = ConflictOverwrite
	tbl, _ = permFixture(t, ow)
	full := session(t, tbl, "f", []Grant{{Mount: "inbox", Perm: PermAll}})
	h, err := full.OpenWrite("/a.txt", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.StartOffset(); ok || h.Conflict() != ConflictOverwritten {
		t.Errorf("overwrite + overwrite permission: guarded = %v, conflict %q", ok, h.Conflict())
	}
	if _, err := h.WriteAt([]byte("O"), 0); err != nil {
		t.Errorf("plain write: %v", err)
	}
	_ = h.Close(false)
	up := session(t, tbl, "p", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	h, err = up.OpenWrite("/a.txt", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.StartOffset(); !ok {
		t.Error("overwrite without the overwrite permission is not guarded")
	}
	_ = h.Close(false)
}

func TestStatRedirect(t *testing.T) {
	t.Parallel()

	tbl, base := permFixture(t, DefaultMountOptions())
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	other := session(t, tbl, "other", []Grant{{Mount: "inbox", Perm: PermAll}})

	if _, err := upload(t, s, "/a.txt", put, "new data"); err != nil { // goes to "a (1).txt"
		t.Fatal(err)
	}
	// paramiko put(confirm=True) compares the size: the copy answers.
	for name, fn := range map[string]func(string) (os.FileInfo, error){"Stat": s.Stat, "Lstat": s.Lstat} {
		fi, err := fn("/a.txt")
		if err != nil || fi.Size() != int64(len("new data")) {
			t.Errorf("%s(/a.txt) = %v, %v; want the copy", name, fi, err)
		}
	}
	when := time.Date(2021, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := s.Setstat("/a.txt", Attrs{Atime: when, Mtime: when, HasTimes: true}); err != nil {
		t.Errorf("Setstat through the redirect: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(base, "inbox", "a (1).txt")); !fi.ModTime().Equal(when) {
		t.Errorf("copy mtime = %v", fi.ModTime())
	}
	if fi, _ := os.Stat(filepath.Join(base, "inbox", "a.txt")); fi.ModTime().Equal(when) {
		t.Error("original mtime changed")
	}
	// Other sessions see the original.
	if fi, err := other.Stat("/a.txt"); err != nil || fi.Size() != int64(len("original")) {
		t.Errorf("other session: %v, %v", fi, err)
	}
	// Opening the path again ends the redirect.
	f, err := other.OpenRead("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := s.OpenWrite("/a.txt", OpenFlags{Write: true, Creat: true, Excl: true}); !errors.Is(err, ErrExists) {
		t.Fatalf("EXCL: %v", err)
	}
	if fi, err := s.Stat("/a.txt"); err != nil || fi.Size() != int64(len("original")) {
		t.Errorf("after reopening: %v, %v; want the original", fi, err)
	}

	// The redirect expires.
	if _, err := upload(t, s, "/a.txt", put, "third"); err != nil { // "a (2).txt"
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(RedirectTTL + time.Second) }
	if fi, err := s.Stat("/a.txt"); err != nil || fi.Size() != int64(len("original")) {
		t.Errorf("after the TTL: %v, %v; want the original", fi, err)
	}
}

func TestStatRedirectPosixRename(t *testing.T) {
	t.Parallel()

	tbl, _ := permFixture(t, DefaultMountOptions())
	s := session(t, tbl, "rclone", []Grant{{Mount: "inbox", Perm: PermAll}})
	if _, err := upload(t, s, "/a.txt.partial", put, "rclone data"); err != nil {
		t.Fatal(err)
	}
	final, err := s.Rename("/a.txt.partial", "/a.txt", true)
	if err != nil || final != "/a (1).txt" {
		t.Fatalf("rename = %q, %v", final, err)
	}
	// rclone checks the size after the move and would delete the
	// "failed copy" — with full access that would be the original.
	if fi, err := s.Stat("/a.txt"); err != nil || fi.Size() != int64(len("rclone data")) {
		t.Errorf("Stat after the move = %v, %v; want the moved file", fi, err)
	}
	// Remove is never redirected.
	if err := s.Remove("/a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stat("/a (1).txt"); err != nil {
		t.Errorf("the moved file was removed instead of the original: %v", err)
	}
}

func TestStatRedirectOff(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.StatRedirect = false
	tbl, _ := permFixture(t, opts)
	s := session(t, tbl, "u", []Grant{{Mount: "inbox", Perm: PermAll}})
	if _, err := upload(t, s, "/a.txt", put, "new data"); err != nil {
		t.Fatal(err)
	}
	if fi, err := s.Stat("/a.txt"); err != nil || fi.Size() != int64(len("original")) {
		t.Errorf("Stat = %v, %v; want the original", fi, err)
	}
}

func TestSymlinksDeny(t *testing.T) {
	t.Parallel()

	for _, policy := range []SymlinkPolicy{SymlinksInsideOnly, SymlinksDeny} {
		opts := DefaultMountOptions()
		opts.Symlinks = policy
		tbl, base := permFixture(t, opts)
		inbox := filepath.Join(base, "inbox")
		mustWrite(t, filepath.Join(inbox, "sub", "x.txt"), "x")
		symlink(t, "a.txt", filepath.Join(inbox, "link.txt"))
		symlink(t, "sub", filepath.Join(inbox, "linkdir"))
		s := session(t, tbl, "u", []Grant{{Mount: "inbox", Perm: PermAll}})

		deny := policy == SymlinksDeny
		for _, p := range []string{"/link.txt", "/linkdir/x.txt"} {
			_, err := s.Stat(p)
			if deny != errors.Is(err, ErrDenied) || (!deny && err != nil) {
				t.Errorf("%s: Stat(%s) = %v", policy, p, err)
			}
			f, err := s.OpenRead(p)
			if deny != (err != nil) {
				t.Errorf("%s: OpenRead(%s) = %v", policy, p, err)
			}
			if f != nil {
				f.Close()
			}
		}
		if _, err := s.OpenWrite("/linkdir/new.txt", put); deny != errors.Is(err, ErrDenied) {
			t.Errorf("%s: upload through a linked directory: %v", policy, err)
		}
		l, err := s.ReadDir("/")
		if err != nil {
			t.Fatal(err)
		}
		ls := make([]os.FileInfo, 16)
		n, _ := l.ListAt(ls, 0)
		l.Close()
		links := 0
		for _, fi := range ls[:n] {
			if fi.Mode()&os.ModeSymlink != 0 {
				links++
			}
		}
		if want := map[bool]int{false: 2, true: 0}[deny]; links != want {
			t.Errorf("%s: %d links listed, want %d", policy, links, want)
		}
	}
}

func TestStatFS(t *testing.T) {
	t.Parallel()

	tbl, _ := permFixture(t, DefaultMountOptions())
	full := session(t, tbl, "f", []Grant{{Mount: "inbox", Perm: PermAll}, {Mount: "docs", Perm: mustPerm(t, "read")}})
	st, err := full.StatFS("/inbox")
	if !StatFSSupported {
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("unsupported platform: %v", err)
		}
		return
	}
	if err != nil || st.Blocks == 0 || st.FragmentSize == 0 || st.ReadOnly {
		t.Errorf("StatFS(/inbox) = %+v, %v", st, err)
	}
	if st, err := full.StatFS("/docs"); err != nil || !st.ReadOnly {
		t.Errorf("read-only grant: %+v, %v", st, err)
	}
	if st, err := full.StatFS("/"); err != nil || !st.ReadOnly || st.Blocks != 0 {
		t.Errorf("synthetic root: %+v, %v", st, err)
	}
	none := session(t, tbl, "n", []Grant{{Mount: "inbox", Perm: PermWrite}})
	if _, err := none.StatFS("/"); !errors.Is(err, ErrDenied) && runtime.GOOS != "windows" {
		t.Errorf("without list: %v", err)
	}
}
