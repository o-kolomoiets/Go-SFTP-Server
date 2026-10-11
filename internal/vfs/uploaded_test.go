// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// partner returns an upload-preset session on inbox and its directory.
func partner(t *testing.T, opts MountOptions) (*Session, *Table, string) {
	t.Helper()
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	return s, tbl, filepath.Join(base, "inbox")
}

// move renames and returns whether the rename completed an upload.
func move(t *testing.T, s *Session, from, to string) bool {
	t.Helper()
	m, err := s.Move(from, to, true)
	if err != nil {
		t.Fatalf("Move(%s, %s): %v", from, to, err)
	}
	return m.Uploaded
}

// The first rename after an upload was closed ok is marked, once.
func TestUploadedMark(t *testing.T) {
	t.Parallel()
	s, _, inbox := partner(t, DefaultMountOptions())

	// A temporary name and its rename (WinSCP, rclone).
	if _, err := upload(t, s, "/x.pdf.filepart", put, "data"); err != nil {
		t.Fatal(err)
	}
	if !move(t, s, "/x.pdf.filepart", "/x.pdf") {
		t.Error("the rename that completes a temp upload is not marked")
	}
	marks := 0
	for i := range 100 { // back and forth: still the user's, never marked again
		from, to := "/x.pdf", "/x.pdf.filepart"
		if i%2 == 1 {
			from, to = to, from
		}
		if move(t, s, from, to) {
			marks++
		}
	}
	if marks != 0 {
		t.Errorf("%d more marks after the first", marks)
	}

	// Setting times keeps the mark (WinSCP and rclone do before renaming).
	if _, err := upload(t, s, "/s.part", put, "s"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	if err := s.Setstat("/s.part", Attrs{Atime: now, Mtime: now, HasTimes: true}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Move("/s.part", "/s", true)
	if err != nil || !m.Uploaded {
		t.Fatalf("rename after setstat = %+v, %v", m, err)
	}
	host := filepath.Join(inbox, "s")
	fi, err := os.Lstat(host)
	if err != nil {
		t.Fatal(err)
	}
	if m.Where.Mount != "inbox" || m.Where.HostPath != host || !os.SameFile(m.Where.Info, fi) {
		t.Errorf("Where = %+v, want inbox, %s and its identity", m.Where, host)
	}
}

// An aborted upload is not marked, and neither is one still open; both may
// still be renamed by their uploader.
func TestUploadedNotForPartialFiles(t *testing.T) {
	t.Parallel()
	s, _, _ := partner(t, DefaultMountOptions())

	h, err := s.OpenWrite("/f.part", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("partial"), 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(true); err != nil { // the connection broke
		t.Fatal(err)
	}
	if move(t, s, "/f.part", "/f") {
		t.Error("an aborted upload is marked")
	}

	o, err := s.OpenWrite("/o.part", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.WriteAt([]byte("still writing"), 0); err != nil {
		t.Fatal(err)
	}
	if move(t, s, "/o.part", "/o") {
		t.Error("an upload still open is marked")
	}
	if err := o.Close(false); err != nil {
		t.Fatal(err)
	}

	// An upload refused by max_file_size is not marked either.
	opts := DefaultMountOptions()
	opts.MaxFileSize = 4
	s2, _, _ := partner(t, opts)
	big, err := s2.OpenWrite("/big.part", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := big.WriteAt([]byte("0123456789"), 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("write past max_file_size: %v", err)
	}
	_ = big.Close(false)
	if move(t, s2, "/big.part", "/big") {
		t.Error("a refused upload is marked")
	}
}

// A resume of the user's own interrupted upload keeps the file the user's:
// the rename after it is allowed under the upload preset and marked.
func TestUploadedAfterResume(t *testing.T) {
	t.Parallel()
	s, _, inbox := partner(t, DefaultMountOptions())
	h, err := s.OpenWrite("/g.part", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("abc"), 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(true); err != nil {
		t.Fatal(err)
	}
	r, err := s.OpenWrite("/g.part", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteAt([]byte("def"), 3); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(false); err != nil {
		t.Fatal(err)
	}
	if !move(t, s, "/g.part", "/g") {
		t.Error("the rename after a resume is not marked")
	}
	if got := readFile(t, filepath.Join(inbox, "g")); got != "abcdef" {
		t.Errorf("g = %q", got)
	}

	// Resuming another user's file does not make it one's own.
	tbl := s.t
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	if _, err := upload(t, bob, "/h.txt", put, "bob"); err != nil {
		t.Fatal(err)
	}
	a, err := s.OpenWrite("/h.txt", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteAt([]byte(" and alice"), 3); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Move("/h.txt", "/i.txt", true); !errors.Is(err, ErrDenied) {
		t.Errorf("renaming another user's resumed file: %v, want ErrDenied", err)
	}
}

// Atomic uploads are published on close and marked like any other.
func TestUploadedAtomic(t *testing.T) {
	t.Parallel()
	opts := DefaultMountOptions()
	opts.AtomicUploads = true
	s, _, inbox := partner(t, opts)
	h, err := upload(t, s, "/t.part", put, "t")
	if err != nil {
		t.Fatal(err)
	}
	w := h.Located()
	fi, err := os.Lstat(filepath.Join(inbox, "t.part"))
	if err != nil || w.HostPath != filepath.Join(inbox, "t.part") || !os.SameFile(w.Info, fi) {
		t.Errorf("Located = %+v, %v", w, err)
	}
	if !move(t, s, "/t.part", "/t") {
		t.Error("the rename of an atomic upload is not marked")
	}
}

// Located gives the file an upload went to, with the conflict policy.
func TestLocatedUpload(t *testing.T) {
	t.Parallel()
	s, _, inbox := partner(t, DefaultMountOptions())
	h, err := upload(t, s, "/a.txt", put, "copy") // a.txt exists: renamed
	if err != nil {
		t.Fatal(err)
	}
	w := h.Located()
	host := filepath.Join(inbox, "a (1).txt")
	fi, err := os.Lstat(host)
	if err != nil {
		t.Fatal(err)
	}
	if w.Mount != "inbox" || w.HostPath != host || !os.SameFile(w.Info, fi) {
		t.Errorf("Located = %+v, want %s", w, host)
	}
}

func TestMountOfAndLocate(t *testing.T) {
	t.Parallel()
	docs := filepath.Join(t.TempDir(), "docs")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	s, _ := fixture(t, ConflictRename, spec("docs", docs, ConflictRename))
	cases := map[string]string{"/": "", "/share/a.txt": "share", "share": "share", "/docs/x/y": "docs", "/nope/x": "", "/../share/a.txt": "share"}
	for p, want := range cases {
		if got := s.MountOf(p); got != want {
			t.Errorf("MountOf(%q) = %q, want %q", p, got, want)
		}
	}
	w := s.Locate("/share/a.txt")
	fi, err := os.Lstat(w.HostPath)
	if err != nil || w.Mount != "share" || !os.SameFile(fi, w.Info) || filepath.Base(w.HostPath) != "a.txt" {
		t.Errorf("Locate = %+v, %v", w, err)
	}
	if w := s.Locate("/share/missing"); w.Info != nil || w.Mount != "share" {
		t.Errorf("Locate of a missing file = %+v", w)
	}
	if w := s.Locate("/"); w.Mount != "" || w.HostPath != "" {
		t.Errorf("Locate(/) = %+v", w)
	}
}

// winscpResume is how WinSCP resumes a .filepart: WRITE|CREAT, no TRUNC,
// writing from the old size (ROADMAP §6.2 row 3).
var winscpResume = OpenFlags{Write: true, Creat: true}

// partial uploads "part" to name and closes it as given: aborted, or
// normally, as WinSCP's Cancel and sftp's Ctrl-C do.
func partial(t *testing.T, s *Session, name string, aborted bool) {
	t.Helper()
	h, err := s.OpenWrite(name, put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("part"), 0); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(aborted); err != nil {
		t.Fatal(err)
	}
}

// A partial .filepart, aborted or cancelled, then a retry or a WinSCP
// resume. Where the conflict policy sends the retry to another file, the
// client's rename moves the partial file and must not be marked. Where the
// retry replaced the name with a complete file (version with TRUNC), or
// nothing was left to conflict with (an aborted atomic upload), the rename
// moves the complete file and is marked.
func TestUploadedRetriedTempNames(t *testing.T) {
	t.Parallel()
	for _, policy := range []ConflictPolicy{ConflictRename, ConflictVersion} {
		for _, atomic := range []bool{false, true} {
			for _, aborted := range []bool{false, true} {
				for _, retry := range []OpenFlags{put, winscpResume} {
					opts := DefaultMountOptions()
					opts.OnConflict, opts.AtomicUploads = policy, atomic
					s, _, inbox := partner(t, opts)
					partial(t, s, "/x.filepart", aborted)
					left := !atomic || !aborted // an aborted atomic upload leaves nothing
					h, err := s.OpenWrite("/x.filepart", retry)
					if err != nil {
						t.Fatalf("%s atomic=%v: retry: %v", policy, atomic, err)
					}
					off := int64(0)
					if retry == winscpResume && left {
						off = 4 // WinSCP writes from the size it found
					}
					if _, err := h.WriteAt([]byte("complete"), off); err != nil {
						t.Fatal(err)
					}
					if err := h.Close(false); err != nil {
						t.Fatal(err)
					}
					want := !left || (policy == ConflictVersion && retry == put)
					if got := move(t, s, "/x.filepart", "/x"); got != want {
						t.Errorf("%s atomic=%v aborted=%v %+v: marked %v, want %v (x = %q)", policy, atomic, aborted, retry, got, want,
							readFile(t, filepath.Join(inbox, "x")))
					}
				}
			}
		}
	}
}

// Under overwrite, a WinSCP resume or a retry writes the user's own file
// in place: it stays the user's and its rename is marked.
func TestUploadedOverwriteInPlace(t *testing.T) {
	t.Parallel()
	for _, retry := range []OpenFlags{put, winscpResume} {
		opts := DefaultMountOptions()
		opts.OnConflict = ConflictOverwrite
		tbl, base := permFixture(t, opts)
		s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "list,write,overwrite")}})
		partial(t, s, "/y.filepart", true)
		h, err := s.OpenWrite("/y.filepart", retry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("complete"), 0); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(false); err != nil {
			t.Fatal(err)
		}
		m, err := s.Move("/y.filepart", "/y", true) // write+overwrite, no rename permission
		if err != nil || !m.Uploaded {
			t.Errorf("%+v: rename = %+v, %v", retry, m, err)
		}
		if got := readFile(t, filepath.Join(base, "inbox", "y")); got != "complete" {
			t.Errorf("y = %q", got)
		}
	}
}

// Resumes that wrote nothing change nothing: they bring no mark back and
// are not news for hooks.
func TestUploadedEmptyResumes(t *testing.T) {
	t.Parallel()
	s, _, _ := partner(t, DefaultMountOptions())
	if _, err := upload(t, s, "/z.filepart", put, "z"); err != nil {
		t.Fatal(err)
	}
	marks := 0
	name := "/z.filepart"
	for i := range 5 {
		if i > 0 {
			r, err := s.OpenWrite(name, reput)
			if err != nil {
				t.Fatal(err)
			}
			if r.Fresh() {
				t.Error("an empty resume is fresh")
			}
			if err := r.Close(false); err != nil {
				t.Fatal(err)
			}
		}
		to := "/z" + string(rune('a'+i))
		if move(t, s, name, to) {
			marks++
		}
		name = to
	}
	if marks != 1 {
		t.Errorf("%d marks, want 1", marks)
	}
}

// A resume of another user's file is not fresh: it fires no hook.
func TestResumeOfOthersFileIsNotFresh(t *testing.T) {
	t.Parallel()
	s, tbl, _ := partner(t, DefaultMountOptions())
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	if _, err := upload(t, bob, "/payroll.csv", put, "bob"); err != nil {
		t.Fatal(err)
	}
	r, err := s.OpenWrite("/payroll.csv", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteAt([]byte("!"), 3); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(false); err != nil {
		t.Fatal(err)
	}
	if r.Fresh() {
		t.Error("a resume of another user's file is fresh")
	}
	own, err := s.OpenWrite("/mine.csv", put)
	if err != nil {
		t.Fatal(err)
	}
	if err := own.Close(false); err != nil || !own.Fresh() {
		t.Errorf("a new upload is not fresh: %v", err)
	}
}

// A resume with a write refused by the append-only guard is audited as
// denied; it marks nothing.
func TestUploadedNotAfterRefusedWrite(t *testing.T) {
	t.Parallel()
	s, _, _ := partner(t, DefaultMountOptions())
	partial(t, s, "/r.part", true)
	r, err := s.OpenWrite("/r.part", reput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteAt([]byte("EVIL"), 0); !errors.Is(err, ErrImmutable) {
		t.Fatalf("write below the start: %v", err)
	}
	if _, err := r.WriteAt([]byte("more"), 4); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(false); err != nil {
		t.Fatal(err)
	}
	if move(t, s, "/r.part", "/r") {
		t.Error("a resume with a refused write is marked")
	}
}

// A truncation refused by the append-only guard makes the upload refused,
// as a refused write does: audited as denied, and no mark.
func TestUploadedNotAfterRefusedTruncate(t *testing.T) {
	t.Parallel()
	s, _, _ := partner(t, DefaultMountOptions())
	partial(t, s, "/r.part", true)
	r, err := s.OpenWrite("/r.part", reput)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Setstat("/r.part", Attrs{Size: 0, HasSize: true}); !errors.Is(err, ErrImmutable) {
		t.Fatalf("truncate below the start: %v", err)
	}
	if _, err := r.WriteAt([]byte("more"), 4); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(false); err != nil {
		t.Fatal(err)
	}
	if !r.Refused() {
		t.Error("a refused truncation does not make the upload refused")
	}
	if move(t, s, "/r.part", "/r") {
		t.Error("marked after a refused truncation")
	}
}

// A write that fails in the file system (a full disk) leaves the upload
// incomplete: no mark, and an atomic upload is not published.
func TestUploadedNotAfterFailedWrite(t *testing.T) {
	t.Parallel()
	for _, atomic := range []bool{false, true} {
		opts := DefaultMountOptions()
		opts.AtomicUploads = atomic
		s, _, inbox := partner(t, opts)
		h, err := s.OpenWrite("/big.filepart", put)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("abc"), 0); err != nil {
			t.Fatal(err)
		}
		// Stand in for ENOSPC: a handle on the file that cannot write.
		w := h.f
		ro, err := h.v.root.Open(h.rel)
		if err != nil {
			t.Fatal(err)
		}
		h.f = ro
		if _, err := h.WriteAt([]byte("def"), 3); err == nil {
			t.Fatal("a write through a read-only handle succeeded")
		}
		_ = w.Close()
		err = h.Close(false)
		if !h.Failed() {
			t.Errorf("atomic=%v: Failed() = false after a failed write", atomic)
		}
		if atomic {
			if !errors.Is(err, errWriteFailed) {
				t.Errorf("atomic: Close = %v", err)
			}
			if _, err := os.Stat(filepath.Join(inbox, "big.filepart")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("atomic: an upload with a failed write was published: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if move(t, s, "/big.filepart", "/big") {
			t.Error("marked after a failed write")
		}
	}
}

// Under overwrite, an upload that writes an existing file in place without
// truncating it is news for hooks only if it changed the file; one that
// truncates it always changed it.
func TestInPlaceUploadsFresh(t *testing.T) {
	t.Parallel()
	opts := DefaultMountOptions()
	opts.OnConflict = ConflictOverwrite
	tbl, _ := permFixture(t, opts)
	alice := session(t, tbl, "alice", []Grant{{Mount: "inbox", Perm: mustPerm(t, "list,write,overwrite")}})
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	cases := []struct {
		name  string
		s     *Session
		fl    OpenFlags
		data  string
		fresh bool
	}{
		{"another user's file, WRITE, nothing written", alice, writeOff, "", false},
		{"another user's file, WRITE|CREAT, nothing written", alice, winscpResume, "", false},
		{"another user's file, WRITE, written", alice, writeOff, "!", true},
		{"another user's file, TRUNC, nothing written", alice, put, "", true},
		{"own file, WRITE, nothing written", bob, reput, "", false},
	}
	for i, c := range cases {
		name := "/f" + string(rune('a'+i)) + ".csv"
		if _, err := upload(t, bob, name, put, "bob"); err != nil {
			t.Fatal(err)
		}
		h, err := c.s.OpenWrite(name, c.fl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.data != "" {
			if _, err := h.WriteAt([]byte(c.data), 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.Close(false); err != nil {
			t.Fatal(err)
		}
		if h.Fresh() != c.fresh {
			t.Errorf("%s: Fresh() = %v, want %v", c.name, h.Fresh(), c.fresh)
		}
	}
}

// An empty overwrite of the user's own file in place changed it (TRUNC):
// it stays the user's and is marked.
func TestUploadedEmptyOverwriteOfOwnFile(t *testing.T) {
	t.Parallel()
	opts := DefaultMountOptions()
	opts.OnConflict = ConflictOverwrite
	tbl, _ := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "list,write,overwrite")}})
	if _, err := upload(t, s, "/batch.tmp", put, "x"); err != nil {
		t.Fatal(err)
	}
	h, err := s.OpenWrite("/batch.tmp", put)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	m, err := s.Move("/batch.tmp", "/batch.ready", true) // no rename permission: only as the user's file
	if err != nil || !m.Uploaded {
		t.Errorf("rename = %+v, %v", m, err)
	}
}

// While another user's upload has the file open, a rename is not marked.
func TestUploadedNotWhileAnotherUploadIsOpen(t *testing.T) {
	t.Parallel()
	s, tbl, _ := partner(t, DefaultMountOptions())
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	if _, err := upload(t, s, "/x.filepart", put, "data"); err != nil {
		t.Fatal(err)
	}
	r, err := bob.OpenWrite("/x.filepart", reput)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(false)
	if move(t, s, "/x.filepart", "/x") {
		t.Error("marked while another upload of the file is open")
	}
}

// An upload that opens clears the mark of the name its bytes go to, also
// through a stat redirect.
func TestUploadedClearedThroughRedirect(t *testing.T) {
	t.Parallel()
	s, _, _ := partner(t, DefaultMountOptions())
	if _, err := upload(t, s, "/a.txt", put, "mine"); err != nil { // a.txt exists: goes to "a (1).txt"
		t.Fatal(err)
	}
	r, err := s.OpenWrite("/a.txt", reput) // through the redirect to "a (1).txt"
	if err != nil {
		t.Fatal(err)
	}
	if r.Path() != "/a (1).txt" {
		t.Fatalf("the resume went to %s", r.Path())
	}
	if err := r.Close(false); err != nil {
		t.Fatal(err)
	}
	if move(t, s, "/a (1).txt", "/b.txt") {
		t.Error("marked after an upload to the name gave up what was there")
	}
}

// Under overwrite with atomic uploads, a retry to a fixed temporary name
// replaces the partial file: the rename moves the complete file and is
// marked, unless the retry was a WinSCP resume (written from the old size).
func TestUploadedRetriedTempNameOverwriteAtomic(t *testing.T) {
	t.Parallel()
	for _, retry := range []OpenFlags{put, winscpResume} {
		opts := DefaultMountOptions()
		opts.OnConflict, opts.AtomicUploads = ConflictOverwrite, true
		tbl, _ := permFixture(t, opts)
		s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "list,write,overwrite")}})
		partial(t, s, "/x.filepart", false)
		h, err := s.OpenWrite("/x.filepart", retry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("complete"), 0); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(false); err != nil {
			t.Fatal(err)
		}
		m, err := s.Move("/x.filepart", "/x", true)
		if err != nil {
			t.Fatal(err)
		}
		if want := retry == put; m.Uploaded != want {
			t.Errorf("%+v: marked %v, want %v", retry, m.Uploaded, want)
		}
	}
}

// Hooks hear of a setstat only when it set the times of the file the path
// names itself (ADR 0010).
func TestSetstatAtWhere(t *testing.T) {
	t.Parallel()
	now := time.Now()
	times := Attrs{Atime: now, Mtime: now, HasTimes: true}
	s, _, inbox := partner(t, DefaultMountOptions())
	if _, err := upload(t, s, "/t.txt", put, "t"); err != nil {
		t.Fatal(err)
	}
	w, err := s.SetstatAt("/t.txt", times)
	fi, _ := os.Lstat(filepath.Join(inbox, "t.txt"))
	if err != nil || w.HostPath != filepath.Join(inbox, "t.txt") || w.Info == nil || !os.SameFile(w.Info, fi) || w.Mount != "inbox" {
		t.Errorf("times on the named file: %+v, %v", w, err)
	}
	if _, err := upload(t, s, "/a.txt", put, "mine"); err != nil { // to "a (1).txt", redirected
		t.Fatal(err)
	}
	if w, err := s.SetstatAt("/a.txt", times); err != nil || w.HostPath != "" {
		t.Errorf("times through a stat redirect: %+v, %v", w, err)
	}
	h, err := s.OpenWrite("/open.txt", put)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := s.SetstatAt("/open.txt", times); err != nil || w.HostPath != "" {
		t.Errorf("times on an open upload: %+v, %v", w, err)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	if w, err := s.SetstatAt("/t.txt", Attrs{}); err != nil || w.HostPath != "" {
		t.Errorf("no times: %+v, %v", w, err)
	}
	opts := DefaultMountOptions()
	opts.SetstatMode = SetstatIgnore
	s2, _, _ := partner(t, opts)
	if _, err := upload(t, s2, "/t.txt", put, "t"); err != nil {
		t.Fatal(err)
	}
	if w, err := s2.SetstatAt("/t.txt", times); err != nil || w.HostPath != "" {
		t.Errorf("setstat_mode = ignore: %+v, %v", w, err)
	}
}

// h.owned is set before claim publishes the handle: other sessions read it
// (go test -race).
func TestOwnedSetBeforeClaim(t *testing.T) {
	t.Parallel()
	s, tbl, _ := partner(t, DefaultMountOptions())
	bob := session(t, tbl, "bob", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	if _, err := upload(t, s, "/mine.part", put, "abc"); err != nil {
		t.Fatal(err)
	}
	stop := time.Now().Add(100 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for time.Now().Before(stop) {
			if r, err := s.OpenWrite("/mine.part", reput); err == nil {
				_ = r.Close(false)
			}
		}
	}()
	now := time.Now()
	for time.Now().Before(stop) {
		_ = bob.Setstat("/a.txt", Attrs{Atime: now, Mtime: now, HasTimes: true})
	}
	<-done
}
