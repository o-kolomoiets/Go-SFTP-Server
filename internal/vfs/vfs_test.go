// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture creates <tmp>/outside/secret.txt and <tmp>/share with a.txt, and
// returns a session on "share" (flattened unless more specs are given).
func fixture(t *testing.T, policy ConflictPolicy, extra ...MountSpec) (*Session, string) {
	t.Helper()
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "outside", "secret.txt"), "secret")
	mustWrite(t, filepath.Join(base, "share", "a.txt"), "original")
	specs := append([]MountSpec{spec("share", filepath.Join(base, "share"), policy)}, extra...)
	tbl, err := Open(specs, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tbl.Close() })
	return session(t, tbl, "alice", tbl.FullAccess()), base
}

// spec returns a mount spec with default options and the given policy.
func spec(name, path string, policy ConflictPolicy) MountSpec {
	o := DefaultMountOptions()
	o.OnConflict = policy
	return MountSpec{Name: name, Path: path, Options: o}
}

func session(t *testing.T, tbl *Table, user string, grants []Grant) *Session {
	t.Helper()
	s, errs := tbl.Session(user, grants)
	if len(errs) > 0 {
		t.Fatalf("Session: %v", errs)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func upload(t *testing.T, s *Session, vp string, fl OpenFlags, data string) (*WriteHandle, error) {
	t.Helper()
	h, err := s.OpenWrite(vp, fl)
	if err != nil {
		return nil, err
	}
	if _, err := h.WriteAt([]byte(data), 0); err != nil {
		t.Fatal(err)
	}
	return h, h.Close(false)
}

var put = OpenFlags{Write: true, Creat: true, Trunc: true}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	for _, d := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tbl, err := Open([]MountSpec{
		spec("one", filepath.Join(base, "one"), ConflictRename),
		spec("two", filepath.Join(base, "two"), ConflictRename),
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s := session(t, tbl, "alice", tbl.FullAccess())

	tests := []struct {
		in      string
		mount   string // "" means the synthetic root
		rel     string
		wantErr error
	}{
		{in: "/", rel: ""},
		{in: "", rel: ""},
		{in: "..", rel: ""},
		{in: "/../../etc/passwd", wantErr: fs.ErrNotExist},
		{in: "/one", mount: "one", rel: "."},
		{in: "one/a//b/./c/", mount: "one", rel: filepath.Join("a", "b", "c")},
		{in: "/one/../two/x", mount: "two", rel: "x"},
		{in: "/one/a/../../../two", mount: "two", rel: "."},
		{in: "/three/x", wantErr: fs.ErrNotExist},
		{in: "/one/a\x00b", wantErr: ErrInvalidPath},
		{in: "/one/\xff", wantErr: ErrInvalidPath},
		{in: "/one/" + strings.Repeat("d/", maxDepth+1), wantErr: ErrInvalidPath},
		{in: "/one/" + strings.Repeat("a", maxPathLen-5), mount: "one", rel: strings.Repeat("a", maxPathLen-5)},
		// The limit applies to the canonical path, which starts with "/":
		// a path that resolves is one that REALPATH can return.
		{in: "one/" + strings.Repeat("a", maxPathLen-4), wantErr: ErrInvalidPath},
	}
	for _, tt := range tests {
		v, rel, err := s.resolve(tt.in)
		if tt.wantErr != nil {
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("resolve(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolve(%q) error = %v", tt.in, err)
			continue
		}
		name := ""
		if v != nil {
			name = v.m.name
		}
		if name != tt.mount || rel != tt.rel {
			t.Errorf("resolve(%q) = (%q, %q), want (%q, %q)", tt.in, name, rel, tt.mount, tt.rel)
		}
	}
}

func TestOpenValidation(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	inner := filepath.Join(base, "inner")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	badOpts := DefaultMountOptions()
	badOpts.RenameTemplate = "{stem}{ext}"
	for _, specs := range [][]MountSpec{
		{spec("bad/name", base, ConflictRename)},
		{spec("NUL", base, ConflictRename)},
		{spec("a", "relative", ConflictRename)},
		{spec("a", base, ConflictRename), spec("A", inner, ConflictRename)},
		{spec("a", base, ConflictRename), spec("b", inner, ConflictRename)},
		{spec("a", base, ConflictRename), spec("h", filepath.Join(base, UserPlaceholder), ConflictRename)},
		{spec("h", filepath.Join(base, UserPlaceholder, "x"), ConflictRename)},
		{spec("a", filepath.Join(base, "missing"), ConflictRename)},
		{spec("a", base, "merge")},
		{{Name: "a", Path: base, Options: badOpts}},
	} {
		if tbl, err := Open(specs, Options{}); err == nil {
			tbl.Close()
			t.Errorf("Open(%+v) succeeded", specs)
		}
	}
}

// ST-1, ST-2: lexical escapes stay inside the mount.
func TestLexicalEscape(t *testing.T) {
	t.Parallel()

	s, _ := fixture(t, ConflictRename)
	for _, p := range []string{"../outside/secret.txt", "/../../outside/secret.txt", "a/../../outside/secret.txt", "/etc/passwd"} {
		if f, err := s.OpenRead(p); !errors.Is(err, fs.ErrNotExist) {
			if f != nil {
				f.Close()
			}
			t.Errorf("OpenRead(%q) error = %v, want not exist", p, err)
		}
	}
}

// ST-3, ST-4, ST-5: symlinks planted by a local user cannot lead outside.
func TestSymlinkEscape(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictOverwrite)
	share := filepath.Join(base, "share")
	symlink(t, filepath.Join(base, "outside"), filepath.Join(share, "abs"))
	symlink(t, filepath.Join("..", "outside"), filepath.Join(share, "rel"))
	symlink(t, filepath.Join("..", "outside", "secret.txt"), filepath.Join(share, "file"))

	for _, p := range []string{"abs/secret.txt", "rel/secret.txt", "file", "rel/", "abs/./secret.txt"} {
		if f, err := s.OpenRead(p); err == nil {
			f.Close()
			t.Errorf("OpenRead(%q) escaped the mount", p)
		}
		if _, err := s.Stat(p); err == nil {
			t.Errorf("Stat(%q) escaped the mount", p)
		}
		if h, err := s.OpenWrite(p, put); err == nil {
			h.Close(false)
			t.Errorf("OpenWrite(%q) escaped the mount", p)
		}
	}
	if l, err := s.ReadDir("rel"); err == nil {
		l.Close()
		t.Error("ReadDir through a symlink escaped the mount")
	}
	if err := s.Mkdir("rel/new"); err == nil {
		t.Error("Mkdir through a symlink escaped the mount")
	}
	if _, err := s.Rename("a.txt", "rel/stolen.txt", false); err == nil {
		t.Error("Rename into a symlinked directory escaped the mount")
	}
	if got := readFile(t, filepath.Join(base, "outside", "secret.txt")); got != "secret" {
		t.Errorf("outside file changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(base, "outside", "stolen.txt")); err == nil {
		t.Error("a file was created outside the mount")
	}
}

func TestEscapeErrorIsDenied(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	symlink(t, filepath.Join(base, "outside"), filepath.Join(base, "share", "out"))
	_, err := s.Stat("out/secret.txt")
	if !errors.Is(err, ErrDenied) {
		t.Errorf("escape error = %v, want ErrDenied (did os.Root change its message?)", err)
	}
}

func TestSymlinkInsideMount(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	symlink(t, "a.txt", filepath.Join(base, "share", "alias"))
	f, err := s.OpenRead("alias")
	if err != nil {
		t.Fatalf("symlink inside the mount: %v", err)
	}
	f.Close()
}

func TestSymlinkAndLinkRefused(t *testing.T) {
	t.Parallel()

	s, _ := fixture(t, ConflictRename)
	if err := s.Symlink("/etc", "x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Symlink error = %v", err)
	}
	if err := s.Link("a.txt", "b"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Link error = %v", err)
	}
}

func TestConflictRename(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	share := filepath.Join(base, "share")

	h, err := upload(t, s, "/a.txt", put, "first copy")
	if err != nil {
		t.Fatal(err)
	}
	if h.Path() != "/a (1).txt" || h.Conflict() != ConflictRenamed {
		t.Errorf("upload went to %q (%s)", h.Path(), h.Conflict())
	}
	if h, err = upload(t, s, "/a.txt", OpenFlags{Write: true, Creat: true}, "scp style"); err != nil || h.Path() != "/a (2).txt" {
		t.Errorf("second upload: %v, %q", err, h.Path())
	}
	if got := readFile(t, filepath.Join(share, "a.txt")); got != "original" {
		t.Errorf("original changed: %q", got)
	}
	if got := readFile(t, filepath.Join(share, "a (1).txt")); got != "first copy" {
		t.Errorf("copy = %q", got)
	}
}

func TestConflictReject(t *testing.T) {
	t.Parallel()

	s, _ := fixture(t, ConflictReject)
	if _, err := s.OpenWrite("a.txt", put); !errors.Is(err, ErrConflict) {
		t.Errorf("error = %v, want ErrConflict", err)
	}
}

func TestConflictOverwrite(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictOverwrite)
	h, err := upload(t, s, "a.txt", put, "new")
	if err != nil || h.Conflict() != ConflictOverwritten {
		t.Fatalf("overwrite: %v, %s", err, h.Conflict())
	}
	if got := readFile(t, filepath.Join(base, "share", "a.txt")); got != "new" {
		t.Errorf("file = %q, want %q", got, "new")
	}
}

// OpenSSH scp writes in place without TRUNC and then truncates via FSETSTAT;
// the result must not keep the tail of a longer old file.
func TestScpOverwriteTruncates(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictOverwrite)
	h, err := s.OpenWrite("a.txt", OpenFlags{Write: true, Creat: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Setstat("a.txt", Attrs{Size: 3, HasSize: true}); err != nil {
		t.Fatalf("Setstat size on the open upload: %v", err)
	}
	if err := h.Close(false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(base, "share", "a.txt")); got != "new" {
		t.Errorf("file = %q, want %q", got, "new")
	}
}

func TestSetstat(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	if err := s.Setstat("a.txt", Attrs{Size: 0, HasSize: true}); !errors.Is(err, ErrDenied) {
		t.Errorf("truncating a file without an open upload: %v, want ErrDenied", err)
	}
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.Setstat("a.txt", Attrs{Atime: mtime, Mtime: mtime, HasTimes: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(base, "share", "a.txt"))
	if err != nil || !fi.ModTime().Equal(mtime) {
		t.Errorf("mtime = %v, %v; want %v", fi.ModTime(), err, mtime)
	}
}

func TestExcl(t *testing.T) {
	t.Parallel()

	s, _ := fixture(t, ConflictOverwrite)
	if _, err := s.OpenWrite("a.txt", OpenFlags{Write: true, Creat: true, Excl: true}); !errors.Is(err, ErrExists) {
		t.Errorf("EXCL error = %v, want ErrExists", err)
	}
	if _, err := s.OpenWrite("missing.txt", OpenFlags{Write: true}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("WRITE without CREAT on a missing file: %v", err)
	}
}

func TestAbortedReservationRemoved(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	h, err := s.OpenWrite("a.txt", put)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "share", "a (1).txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty aborted reservation still exists: %v", err)
	}
}

func TestConcurrentUploadsSameName(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	const n = 50
	var wg sync.WaitGroup
	paths := make(chan string, n)
	for i := range n {
		wg.Go(func() {
			h, err := upload(t, s, "a.txt", put, strconv.Itoa(i))
			if err != nil {
				t.Error(err)
				return
			}
			paths <- h.Path()
		})
	}
	wg.Wait()
	close(paths)
	seen := map[string]bool{}
	for p := range paths {
		if seen[p] {
			t.Errorf("two uploads wrote %q", p)
		}
		seen[p] = true
	}
	if len(seen) != n {
		t.Errorf("%d distinct files, want %d", len(seen), n)
	}
	if got := readFile(t, filepath.Join(base, "share", "a.txt")); got != "original" {
		t.Errorf("original changed: %q", got)
	}
}

// Another session's isCreated reads every open upload, so a handle must be
// complete before claim publishes it.
func TestClaimPublishesCompleteHandle(t *testing.T) {
	t.Parallel()

	alice, _ := fixture(t, ConflictRename)
	bob := session(t, alice.t, "bob", alice.t.FullAccess())
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 200 {
			if _, err := upload(t, alice, "new"+strconv.Itoa(i)+".txt", put, "x"); err != nil {
				t.Error(err)
				return
			}
		}
	})
	now := time.Now()
	for range 200 {
		_ = bob.Setstat("a.txt", Attrs{Atime: now, Mtime: now, HasTimes: true})
	}
	wg.Wait()
}

func TestRename(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	share := filepath.Join(base, "share")
	mustWrite(t, filepath.Join(share, "b.txt"), "b")

	if _, err := s.Rename("a.txt", "b.txt", false); !errors.Is(err, ErrExists) {
		t.Errorf("v3 rename over an existing file: %v, want ErrExists", err)
	}
	final, err := s.Rename("a.txt", "b.txt", true)
	if err != nil || final != "/b (1).txt" {
		t.Errorf("posix-rename with rename policy = %q, %v", final, err)
	}
	if got := readFile(t, filepath.Join(share, "b.txt")); got != "b" {
		t.Errorf("target changed: %q", got)
	}
	if final, err := s.Rename("b (1).txt", "c.txt", false); err != nil || final != "/c.txt" {
		t.Errorf("plain rename = %q, %v", final, err)
	}
	if err := s.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	if final, err := s.Rename("dir", "dir2", false); err != nil || final != "/dir2" {
		t.Errorf("directory rename = %q, %v", final, err)
	}
}

func TestPosixRenameOverwrite(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictOverwrite)
	mustWrite(t, filepath.Join(base, "share", "b.txt"), "b")
	if _, err := s.Rename("a.txt", "b.txt", true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(base, "share", "b.txt")); got != "original" {
		t.Errorf("b.txt = %q, want the renamed file", got)
	}
}

func TestReadOnlyMount(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "a.txt"), "x")
	ro := spec("ro", base, ConflictRename)
	ro.ReadOnly = true
	tbl, err := Open([]MountSpec{ro}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s := session(t, tbl, "alice", tbl.FullAccess())

	if _, err := s.OpenWrite("new.txt", put); !errors.Is(err, ErrDenied) {
		t.Errorf("OpenWrite: %v", err)
	}
	for name, err := range map[string]error{
		"Mkdir":   s.Mkdir("d"),
		"Remove":  s.Remove("a.txt"),
		"Setstat": s.Setstat("a.txt", Attrs{HasTimes: true}),
	} {
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want ErrDenied", name, err)
		}
	}
	f, err := s.OpenRead("a.txt")
	if err != nil {
		t.Fatalf("reading a read-only mount: %v", err)
	}
	f.Close()
}

func TestVirtualRoot(t *testing.T) {
	t.Parallel()

	_, base := fixture(t, ConflictRename)
	other := filepath.Join(base, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	docs := spec("docs", other, ConflictRename)
	docs.ReadOnly = true
	tbl, err := Open([]MountSpec{spec("share", filepath.Join(base, "share"), ConflictRename), docs}, Options{Flatten: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tbl.Close()
	s := session(t, tbl, "alice", tbl.FullAccess())

	l, err := s.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	ls := make([]os.FileInfo, 10)
	n, err := l.ListAt(ls, 0)
	if !errors.Is(err, io.EOF) || n != 2 || ls[0].Name() != "docs" || ls[1].Name() != "share" {
		t.Errorf("root listing = %d entries (%v), err %v", n, ls[:n], err)
	}
	if ls[0].Mode().Perm() != 0o555 || ls[1].Mode().Perm() != 0o755 {
		t.Errorf("mount modes = %v, %v", ls[0].Mode(), ls[1].Mode())
	}
	if err := s.Mkdir("/new"); !errors.Is(err, ErrDenied) {
		t.Errorf("Mkdir in the virtual root: %v", err)
	}
	if err := s.Rmdir("/share"); !errors.Is(err, ErrDenied) {
		t.Errorf("Rmdir of a mount: %v", err)
	}
	if _, err := s.Rename("/share/a.txt", "/docs/a.txt", false); err == nil {
		t.Error("rename across mounts succeeded")
	}
	if f, err := s.OpenRead("/share/a.txt"); err != nil {
		t.Errorf("OpenRead(/share/a.txt): %v", err)
	} else {
		f.Close()
	}
}

func TestListing(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	share := filepath.Join(base, "share")
	for i := range 600 {
		mustWrite(t, filepath.Join(share, "dir", fmt.Sprintf("f%03d", i)), "")
	}
	mkfifo(t, filepath.Join(share, "dir", "fifo"))
	l, err := s.ReadDir("dir")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	total := 0
	buf := make([]os.FileInfo, 100)
	for {
		n, err := l.ListAt(buf, int64(total))
		for _, fi := range buf[:n] {
			if fi.Name() == "fifo" {
				t.Error("FIFO is listed")
			}
		}
		total += n
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if total != 600 {
		t.Errorf("listed %d entries, want 600", total)
	}
}

func TestSplitExtAndCandidate(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"report.pdf":     "report (1).pdf",
		"archive.tar.gz": "archive (1).tar.gz",
		".env":           ".env (1)",
		"README":         "README (1)",
		"a (1).txt":      "a (1) (1).txt",
	} {
		stem, ext := splitExt(in, DefaultCompoundExtensions)
		if got := candidate(DefaultRenameTemplate, stem, "1", ext); got != want {
			t.Errorf("candidate(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("λ", 200) + ".txt"
	stem, ext := splitExt(long, DefaultCompoundExtensions)
	got := candidate(DefaultRenameTemplate, stem, "1", ext)
	if len(got) > maxNameLen || !strings.HasSuffix(got, " (1).txt") || !utf8Valid(got) {
		t.Errorf("long candidate = %d bytes, %q", len(got), got[len(got)-12:])
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

func TestFallbackRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a"), "a")
	mustWrite(t, filepath.Join(dir, "b"), "b")
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := fallbackRename(root, "a", "b"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("file over existing file: %v, want ErrExist", err)
	}
	if err := fallbackRename(root, "a", "c"); err != nil {
		t.Errorf("file rename: %v", err)
	}
	if err := fallbackRename(root, "d", "b"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("directory over existing file: %v, want ErrExist", err)
	}
	if err := fallbackRename(root, "d", "e"); err != nil {
		t.Errorf("directory rename: %v", err)
	}
	if err := fallbackRename(root, "missing", "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing source: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "c")); got != "a" {
		t.Errorf("c = %q", got)
	}
}

func TestStatAndRemoveErrors(t *testing.T) {
	t.Parallel()

	s, base := fixture(t, ConflictRename)
	share := filepath.Join(base, "share")
	mustWrite(t, filepath.Join(share, "d", "f"), "x")

	if fi, err := s.Stat("/"); err != nil || !fi.IsDir() || fi.Name() != "/" {
		t.Errorf("Stat(/) = %v, %v", fi, err)
	}
	if fi, err := s.Lstat("a.txt"); err != nil || fi.Size() != int64(len("original")) {
		t.Errorf("Lstat(a.txt) = %v, %v", fi, err)
	}
	if _, err := s.Stat("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(missing) = %v", err)
	}
	for name, err := range map[string]error{
		"Remove(dir)":       s.Remove("d"),
		"Rmdir(file)":       s.Rmdir("a.txt"),
		"Rmdir(non-empty)":  s.Rmdir("d"),
		"Mkdir(existing)":   s.Mkdir("d"),
		"Remove(missing)":   s.Remove("missing"),
		"Remove(mount)":     s.Remove("/"),
		"Mkdir(bad path)":   s.Mkdir("a\x00b"),
		"Rename(missing)":   func() error { _, err := s.Rename("missing", "x", false); return err }(),
		"OpenRead(dir)":     func() error { _, err := s.OpenRead("d"); return err }(),
		"ReadDir(file)":     func() error { _, err := s.ReadDir("a.txt"); return err }(),
		"OpenWrite(dir)":    func() error { _, err := s.OpenWrite("d", put); return err }(),
		"OpenWrite(mount)":  func() error { _, err := s.OpenWrite("/", put); return err }(),
		"Setstat(negative)": s.Setstat("a.txt", Attrs{Size: -1, HasSize: true}),
	} {
		if err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
	for _, tc := range []struct {
		err  error
		want error
	}{
		{s.Remove("d"), ErrIsDir},
		{s.Rmdir("a.txt"), ErrNotDir},
		{s.Rmdir("d"), ErrNotEmpty},
		{s.Mkdir("d"), ErrExists},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("error %v, want %v", tc.err, tc.want)
		}
	}
	if got := s.RealPath("a/../../b/"); got != "/b" {
		t.Errorf("RealPath = %q", got)
	}
	if err := s.Remove("a.txt"); err != nil {
		t.Errorf("Remove(a.txt): %v", err)
	}
}

func TestParseConflictPolicy(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"rename", "reject", "overwrite", "version"} {
		if _, err := ParseConflictPolicy(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if _, err := ParseConflictPolicy("merge"); err == nil {
		t.Error("unknown policy accepted")
	}
}
