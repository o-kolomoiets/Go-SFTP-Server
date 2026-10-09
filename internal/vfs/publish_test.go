// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// shareFixture returns a session with full access to one mount "share"
// (base/share with a.txt) whose options mod changes.
func shareFixture(t *testing.T, mod func(*MountOptions)) (*Session, string) {
	t.Helper()
	base := t.TempDir()
	share := filepath.Join(base, "share")
	mustWrite(t, filepath.Join(share, "a.txt"), "original")
	o := DefaultMountOptions()
	mod(&o)
	tbl, err := Open([]MountSpec{{Name: "share", Path: share, Options: o}}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tbl.Close() })
	return session(t, tbl, "alice", tbl.FullAccess()), share
}

// tempFiles returns the temporary upload files in dir.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		if isTempName(de.Name()) {
			out = append(out, de.Name())
		}
	}
	return out
}

func listNames(t *testing.T, s *Session, vp string) []string {
	t.Helper()
	l, err := s.ReadDir(vp)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	buf := make([]os.FileInfo, 100)
	n, err := l.ListAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	var names []string
	for _, fi := range buf[:n] {
		names = append(names, fi.Name())
	}
	return names
}

func TestAtomicUpload(t *testing.T) {
	t.Parallel()

	s, share := shareFixture(t, func(o *MountOptions) { o.AtomicUploads = true })
	h, err := s.OpenWrite("new.txt", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("data"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(share, "new.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the target exists before the upload is closed: %v", err)
	}
	tmp := tempFiles(t, share)
	if len(tmp) != 1 || !strings.HasSuffix(tmp[0], tempSuffix) {
		t.Fatalf("temporary files = %q, want one", tmp)
	}
	if fi, err := os.Stat(filepath.Join(share, tmp[0])); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("temporary file: %v, %v; want mode 0600", fi.Mode(), err)
	}
	// FSTAT on the open handle arrives as a STAT of the name.
	if fi, err := s.Stat("new.txt"); err != nil || fi.Size() != 4 || fi.Name() != "new.txt" {
		t.Errorf("Stat of the open upload = %v, %v", fi, err)
	}
	if names := listNames(t, s, "/"); slices.ContainsFunc(names, isTempName) {
		t.Errorf("listing shows the temporary file: %q", names)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	if h.Path() != "/new.txt" || h.Conflict() != ConflictNone {
		t.Errorf("upload = %q (%s)", h.Path(), h.Conflict())
	}
	if got := readFile(t, filepath.Join(share, "new.txt")); got != "data" {
		t.Errorf("new.txt = %q", got)
	}
	fi, err := os.Stat(filepath.Join(share, "new.txt"))
	if want := DefaultMountOptions().filePerm(); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != want {
		t.Errorf("published file: %v, %v; want mode %v", fi.Mode(), err, want)
	}
	if tmp := tempFiles(t, share); len(tmp) != 0 {
		t.Errorf("temporary files left: %q", tmp)
	}
	// The uploader may set the times of what it just wrote.
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.Setstat("new.txt", Attrs{Atime: mtime, Mtime: mtime, HasTimes: true}); err != nil {
		t.Errorf("Setstat on the published file: %v", err)
	}
}

// WinSCP uploads to a.txt.filepart and renames it; an uploader without the
// rename permission may do that with the file it just published.
func TestAtomicUploadIsOwned(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.AtomicUploads = true
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	if _, err := upload(t, s, "/b.txt.filepart", put, "data"); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.Setstat("/b.txt.filepart", Attrs{Atime: mtime, Mtime: mtime, HasTimes: true}); err != nil {
		t.Errorf("setting the times of an own upload: %v", err)
	}
	if _, err := s.Rename("/b.txt.filepart", "/b.txt", false); err != nil {
		t.Errorf("renaming an own upload: %v", err)
	}
	if got := readFile(t, filepath.Join(base, "inbox", "b.txt")); got != "data" {
		t.Errorf("b.txt = %q", got)
	}
	if _, err := s.Rename("/a.txt", "/c.txt", false); !errors.Is(err, ErrDenied) {
		t.Errorf("renaming someone else's file: %v, want ErrDenied", err)
	}
}

func TestAtomicUploadAborted(t *testing.T) {
	t.Parallel()

	s, share := shareFixture(t, func(o *MountOptions) {
		o.AtomicUploads = true
		o.OnConflict = ConflictOverwrite
	})
	for _, name := range []string{"new.txt", "a.txt"} {
		h, err := s.OpenWrite(name, put)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("partial"), 0); err != nil {
			t.Fatal(err)
		}
		if err := h.Close(true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(share, "new.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an aborted upload created its target: %v", err)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "original" {
		t.Errorf("an aborted overwrite changed the file: %q", got)
	}
	if tmp := tempFiles(t, share); len(tmp) != 0 {
		t.Errorf("temporary files left: %q", tmp)
	}
}

func TestAtomicResumeRefused(t *testing.T) {
	t.Parallel()

	s, _ := shareFixture(t, func(o *MountOptions) { o.AtomicUploads = true })
	for _, fl := range []OpenFlags{{Write: true}, {Write: true, Append: true}} {
		if _, err := s.OpenWrite("a.txt", fl); !errors.Is(err, ErrResumeDisabled) {
			t.Errorf("resume %+v: %v, want ErrResumeDisabled", fl, err)
		}
	}
}

// The conflict policy applies when the upload is published: another file
// may have appeared under the name in the meantime.
func TestAtomicConflictAtPublish(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		policy   ConflictPolicy
		err      error
		path     string
		conflict string
		target   string
	}{
		{ConflictReject, ErrConflict, "/new.txt", ConflictNone, "other"},
		{ConflictOverwrite, nil, "/new.txt", ConflictOverwritten, "upload"},
		{ConflictRename, nil, "/new (1).txt", ConflictRenamed, "other"},
		{ConflictVersion, nil, "/new.txt", ConflictVersioned, "upload"},
	} {
		t.Run(string(tc.policy), func(t *testing.T) {
			t.Parallel()

			s, share := shareFixture(t, func(o *MountOptions) {
				o.AtomicUploads = true
				o.OnConflict = tc.policy
			})
			h, err := s.OpenWrite("new.txt", put)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.WriteAt([]byte("upload"), 0); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(share, "new.txt"), "other")
			if err := h.Close(false); !errors.Is(err, tc.err) {
				t.Fatalf("Close: %v, want %v", err, tc.err)
			}
			if tc.err == nil && (h.Path() != tc.path || h.Conflict() != tc.conflict) {
				t.Errorf("upload = %q (%s), want %q (%s)", h.Path(), h.Conflict(), tc.path, tc.conflict)
			}
			if got := readFile(t, filepath.Join(share, "new.txt")); got != tc.target {
				t.Errorf("new.txt = %q, want %q", got, tc.target)
			}
			if tmp := tempFiles(t, share); len(tmp) != 0 {
				t.Errorf("temporary files left: %q", tmp)
			}
			if tc.policy == ConflictRename {
				// rclone stats the requested name after an upload.
				if fi, err := s.Stat("new.txt"); err != nil || fi.Size() != int64(len("upload")) {
					t.Errorf("Stat of the requested name does not follow the rename: %v", err)
				}
			}
		})
	}
}

// OpenSSH scp truncates and sets the times by name while the upload is
// open: with atomic uploads they must reach the temporary file.
func TestAtomicScpOverwrite(t *testing.T) {
	t.Parallel()

	s, share := shareFixture(t, func(o *MountOptions) {
		o.AtomicUploads = true
		o.OnConflict = ConflictOverwrite
	})
	h, err := s.OpenWrite("a.txt", OpenFlags{Write: true, Creat: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.Setstat("a.txt", Attrs{Size: 3, HasSize: true, Atime: mtime, Mtime: mtime, HasTimes: true}); err != nil {
		t.Fatalf("Setstat on the open upload: %v", err)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "original" {
		t.Errorf("Setstat changed the target before the upload was closed: %q", got)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "new" {
		t.Errorf("a.txt = %q, want %q", got, "new")
	}
	if fi, err := os.Stat(filepath.Join(share, "a.txt")); err != nil || !fi.ModTime().Equal(mtime) {
		t.Errorf("mtime = %v, %v; want %v", fi.ModTime(), err, mtime)
	}
}

func TestTempNamesReserved(t *testing.T) {
	t.Parallel()

	s, share := shareFixture(t, func(*MountOptions) {})
	const name = ".gosftpd-0123456789abcdef.part"
	mustWrite(t, filepath.Join(share, name), "someone's upload")
	if names := listNames(t, s, "/"); slices.Contains(names, name) {
		t.Errorf("listing shows %s: %q", name, names)
	}
	for op, err := range map[string]error{
		"stat":       func() error { _, err := s.Stat(name); return err }(),
		"read":       func() error { _, err := s.OpenRead(name); return err }(),
		"write":      func() error { _, err := s.OpenWrite(name, put); return err }(),
		"write new":  func() error { _, err := s.OpenWrite(".gosftpd-x", put); return err }(),
		"mkdir":      s.Mkdir(".gosftpd-dir"),
		"below":      func() error { _, err := s.OpenWrite(".gosftpd-dir/f", put); return err }(),
		"remove":     s.Remove(name),
		"rename to":  func() error { _, err := s.Rename("a.txt", ".gosftpd-1.part", false); return err }(),
		"rename src": func() error { _, err := s.Rename(name, "b.txt", false); return err }(),
	} {
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want ErrDenied", op, err)
		}
	}
	if got := readFile(t, filepath.Join(share, name)); got != "someone's upload" {
		t.Errorf("temporary file changed: %q", got)
	}
}

// versionFixture returns a session on a mount with on_conflict = "version"
// whose clock is set by the returned function.
func versionFixture(t *testing.T, mod func(*MountOptions)) (*Session, string, func(time.Time)) {
	t.Helper()
	s, share := shareFixture(t, func(o *MountOptions) {
		o.OnConflict = ConflictVersion
		mod(o)
	})
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.t.now = func() time.Time { return now }
	return s, share, func(t time.Time) { now = t }
}

func TestVersionUpload(t *testing.T) {
	t.Parallel()

	s, share, _ := versionFixture(t, func(*MountOptions) {})
	h, err := s.OpenWrite("a.txt", put)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("v2"), 0); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "original" {
		t.Errorf("a.txt changed before the upload was closed: %q", got)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	const v1 = "/.versions/a.txt/a.20260102T030405Z.txt"
	if h.Path() != "/a.txt" || h.Conflict() != ConflictVersioned || h.Version() != v1 {
		t.Errorf("upload = %q (%s), version %q; want version %q", h.Path(), h.Conflict(), h.Version(), v1)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "v2" {
		t.Errorf("a.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(share, filepath.FromSlash(v1))); got != "original" {
		t.Errorf("version = %q", got)
	}

	// A second version in the same second gets a counter.
	h, err = upload(t, s, "a.txt", put, "v3")
	if err != nil || h.Version() != "/.versions/a.txt/a.20260102T030405Z-1.txt" {
		t.Errorf("second upload: %v, version %q", err, h.Version())
	}
	// A new file is not a conflict.
	if h, err := upload(t, s, "sub.txt", put, "x"); err != nil || h.Conflict() != ConflictNone || h.Version() != "" {
		t.Errorf("new file: %v, %s, %q", err, h.Conflict(), h.Version())
	}
	if tmp := tempFiles(t, share); len(tmp) != 0 {
		t.Errorf("temporary files left: %q", tmp)
	}

	// Clients read versions but cannot change them. The directory is not
	// listed, so that sync tools do not try to delete it.
	if names := listNames(t, s, "/"); slices.Contains(names, ".versions") {
		t.Errorf("the versions directory is listed: %q", names)
	}
	if names := listNames(t, s, "/.versions/a.txt"); len(names) != 2 {
		t.Errorf("versions of a.txt = %q", names)
	}
	f, err := s.OpenRead(v1)
	if err != nil {
		t.Fatalf("reading a version: %v", err)
	}
	_ = f.Close()
	for op, err := range map[string]error{
		"write":     func() error { _, err := s.OpenWrite(v1, put); return err }(),
		"write new": func() error { _, err := s.OpenWrite("/.versions/new.txt", put); return err }(),
		"mkdir":     s.Mkdir("/.versions/dir"),
		"remove":    s.Remove(v1),
		"rmdir":     s.Rmdir("/.versions/a.txt"),
		"rename":    func() error { _, err := s.Rename(v1, "/old.txt", false); return err }(),
		"rename in": func() error { _, err := s.Rename("/a.txt", "/.versions/a.txt/x", false); return err }(),
		"setstat":   s.Setstat(v1, Attrs{Mtime: time.Now(), Atime: time.Now(), HasTimes: true}),
		"rename vd": func() error { _, err := s.Rename("/.versions", "/v", false); return err }(),
	} {
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s in the versions directory: %v, want ErrDenied", op, err)
		}
	}
}

func TestVersionNeedsOnlyWrite(t *testing.T) {
	t.Parallel()

	opts := DefaultMountOptions()
	opts.OnConflict = ConflictVersion
	tbl, base := permFixture(t, opts)
	s := session(t, tbl, "partner", []Grant{{Mount: "inbox", Perm: mustPerm(t, "upload")}})
	h, err := upload(t, s, "/a.txt", put, "new")
	if err != nil || h.Conflict() != ConflictVersioned {
		t.Fatalf("replacing a file with write only: %v (%s)", err, h.Conflict())
	}
	if got := readFile(t, filepath.Join(base, "inbox", filepath.FromSlash(h.Version()))); got != "original" {
		t.Errorf("version = %q", got)
	}
}

func TestVersionRetention(t *testing.T) {
	t.Parallel()

	s, share, setNow := versionFixture(t, func(o *MountOptions) {
		o.Versions = VersionsOptions{Dir: "old", Keep: 3, MaxAge: 10 * time.Hour}
	})
	dir := filepath.Join(share, "old", "a.txt")
	start := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	versions := func() []string {
		des, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		return names
	}
	mustWrite(t, filepath.Join(dir, "notes"), "not a version") // kept
	for i := range 5 {
		setNow(start.Add(time.Duration(i) * time.Hour))
		if _, err := upload(t, s, "a.txt", put, "x"); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"a.20260102T020000Z.txt", "a.20260102T030000Z.txt", "a.20260102T040000Z.txt", "notes"}
	if got := versions(); !slices.Equal(got, want) {
		t.Errorf("after 5 uploads with keep = 3: %q, want %q", got, want)
	}

	setNow(start.Add(13*time.Hour + time.Minute))
	if _, err := upload(t, s, "a.txt", put, "x"); err != nil {
		t.Fatal(err)
	}
	want = []string{"a.20260102T040000Z.txt", "a.20260102T130100Z.txt", "notes"}
	if got := versions(); !slices.Equal(got, want) {
		t.Errorf("with max_age = 10h: %q, want %q", got, want)
	}
}

func TestVersionMove(t *testing.T) {
	t.Parallel()

	s, share, _ := versionFixture(t, func(*MountOptions) {})
	mustWrite(t, filepath.Join(share, "b.txt"), "b")
	if _, err := s.Move("b.txt", "a.txt", false); !errors.Is(err, ErrExists) {
		t.Errorf("v3 rename over a file: %v, want ErrExists", err)
	}
	m, err := s.Move("b.txt", "a.txt", true)
	const v1 = "/.versions/a.txt/a.20260102T030405Z.txt"
	if err != nil || m != (Moved{Final: "/a.txt", Conflict: ConflictVersioned, Version: v1}) {
		t.Fatalf("posix-rename = %+v, %v", m, err)
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "b" {
		t.Errorf("a.txt = %q", got)
	}
	if got := readFile(t, filepath.Join(share, filepath.FromSlash(v1))); got != "original" {
		t.Errorf("version = %q", got)
	}

	if err := s.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Move("dir", "a.txt", true); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory over a file: %v, want ErrNotRegular", err)
	}
	mustWrite(t, filepath.Join(share, "c.txt"), "c")
	if _, err := s.Move("c.txt", "dir", true); !errors.Is(err, ErrIsDir) {
		t.Errorf("file over a directory: %v, want ErrIsDir", err)
	}
	if got := readFile(t, filepath.Join(share, "c.txt")); got != "c" {
		t.Errorf("c.txt = %q", got)
	}
}

func TestMaxFileSize(t *testing.T) {
	t.Parallel()

	for _, atomic := range []bool{false, true} {
		s, share := shareFixture(t, func(o *MountOptions) {
			o.MaxFileSize = 10
			o.AtomicUploads = atomic
		})
		h, err := s.OpenWrite("big.bin", put)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte("0123456789"), 0); err != nil {
			t.Errorf("atomic %v: writing max_file_size bytes: %v", atomic, err)
		}
		for _, w := range []struct {
			off int64
			n   int
		}{{9, 2}, {10, 1}, {1 << 40, 1}, {math.MaxInt64, 1}, {-1, 1}} {
			if _, err := h.WriteAt(make([]byte, w.n), w.off); !errors.Is(err, ErrTooLarge) {
				t.Errorf("atomic %v: %d bytes at %d: %v, want ErrTooLarge", atomic, w.n, w.off, err)
			}
		}
		if err := s.Setstat("big.bin", Attrs{Size: 11, HasSize: true}); !errors.Is(err, ErrTooLarge) {
			t.Errorf("atomic %v: truncate past the limit: %v, want ErrTooLarge", atomic, err)
		}
		if err := s.Setstat("big.bin", Attrs{Size: 5, HasSize: true}); err != nil {
			t.Errorf("atomic %v: truncate below the limit: %v", atomic, err)
		}
		if err := h.Close(false); err != nil {
			t.Fatal(err)
		}
		// A refused write leaves an incomplete file: an atomic upload is
		// not published.
		got, err := os.ReadFile(filepath.Join(share, "big.bin"))
		switch {
		case atomic && !errors.Is(err, fs.ErrNotExist):
			t.Errorf("an atomic upload with a refused write was published: %q, %v", got, err)
		case !atomic && string(got) != "01234":
			t.Errorf("big.bin = %q, %v", got, err)
		}
		if tmp := tempFiles(t, share); len(tmp) != 0 {
			t.Errorf("temporary files left: %q", tmp)
		}
	}
}

func TestMinFreeSpace(t *testing.T) {
	t.Parallel()

	if !StatFSSupported {
		t.Skip("no statfs on this platform")
	}
	s, _ := shareFixture(t, func(o *MountOptions) { o.MinFreeSpace = math.MaxInt64 })
	if _, err := s.OpenWrite("new.txt", put); !errors.Is(err, ErrNoSpace) {
		t.Errorf("upload with too little free space: %v, want ErrNoSpace", err)
	}
	f, err := s.OpenRead("a.txt")
	if err != nil {
		t.Errorf("reading with too little free space: %v", err)
	} else {
		_ = f.Close()
	}

	s, _ = shareFixture(t, func(o *MountOptions) { o.MinFreeSpace = 0 })
	if _, err := upload(t, s, "new.txt", put, "x"); err != nil {
		t.Errorf("min_free_space = 0: %v", err)
	}
}

func TestCleanTemp(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	share := filepath.Join(base, "share")
	homes := filepath.Join(base, "homes")
	old := time.Now().Add(-TempMaxAge - time.Hour)
	files := map[string]bool{ // path: removed
		filepath.Join(share, ".gosftpd-1.part"):                  true,
		filepath.Join(share, "sub", ".gosftpd-2.part"):           true,
		filepath.Join(homes, "alice", ".gosftpd-3.part"):         true,
		filepath.Join(share, ".gosftpd-new.part"):                false, // recent
		filepath.Join(share, "upload.part"):                      false, // not ours
		filepath.Join(share, ".gosftpd-notes"):                   false,
		filepath.Join(share, ".gosftpd-dir.part", "kept.txt"):    false,
		filepath.Join(base, "outside", ".gosftpd-outside.part"):  false,
		filepath.Join(homes, "alice", "sub", ".gosftpd-4.part"):  true,
		filepath.Join(homes, "bob", ".gosftpd-5.part", "x.part"): false,
	}
	ro := filepath.Join(base, "ro")
	files[filepath.Join(ro, ".gosftpd-6.part")] = false // the server does not write there
	for p := range files {
		mustWrite(t, p, "x")
		if !strings.HasSuffix(p, "new.part") {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chtimes(filepath.Join(share, ".gosftpd-dir.part"), old, old); err != nil {
		t.Fatal(err)
	}
	roSpec := spec("ro", ro, ConflictRename)
	roSpec.ReadOnly = true
	tbl, err := Open([]MountSpec{
		spec("share", share, ConflictRename),
		spec("home", filepath.Join(homes, UserPlaceholder), ConflictRename),
		roSpec,
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	if n := tbl.CleanTemp(); n != 4 {
		t.Errorf("CleanTemp removed %d files, want 4", n)
	}
	for p, removed := range files {
		_, err := os.Stat(p)
		if removed != errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: removed %v, want %v (%v)", p, !removed, removed, err)
		}
	}
}
