// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Fuzz targets (ROADMAP §8.3). Run one with
// go test -run='^$' -fuzz='^FuzzResolve$' -fuzztime=60s ./internal/vfs

func fuzzPathSeeds(f *testing.F) {
	f.Helper()
	for _, s := range []string{
		"", "/", ".", "..", "/a.txt", "a/b/../c", "/share/../../etc/passwd", "//share//x",
		"/share/evil/secret.txt", "../outside/secret.txt", "/share/.gosftpd-1.part",
		"/share/.versions/a.txt", "C:\\Windows", "\\\\server\\share", "a\x00b", "/share/" + strings.Repeat("x/", 70),
		"/share/aux", "/share/a.", "/share/a ", "\xff\xfe", "/ŝhare/ä",
	} {
		f.Add(s)
	}
}

// FuzzResolve: resolve never panics and yields "." or a local path without
// "..", the same one again for its canonical client path.
func FuzzResolve(f *testing.F) {
	fuzzPathSeeds(f)
	base := f.TempDir()
	var tables []*Table
	for _, flatten := range []bool{false, true} {
		specs := []MountSpec{spec("share", filepath.Join(base, "share"), ConflictRename)}
		if !flatten {
			specs = append(specs, spec("docs", filepath.Join(base, "docs"), ConflictRename))
		}
		for _, s := range specs {
			if err := os.MkdirAll(s.Path, 0o755); err != nil {
				f.Fatal(err)
			}
		}
		tbl, err := Open(specs, Options{Flatten: flatten})
		if err != nil {
			f.Fatal(err)
		}
		f.Cleanup(func() { tbl.Close() })
		tables = append(tables, tbl)
	}
	f.Fuzz(func(t *testing.T, vp string) {
		for _, tbl := range tables {
			s, errs := tbl.Session("alice", tbl.FullAccess())
			if len(errs) > 0 {
				t.Fatal(errs)
			}
			v, rel, err := s.resolve(vp)
			if err != nil || v == nil {
				continue
			}
			if rel != "." && (!filepath.IsLocal(rel) || filepath.IsAbs(rel)) {
				t.Fatalf("resolve(%q) = %q: not a local path", vp, rel)
			}
			for c := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
				if c == ".." {
					t.Fatalf("resolve(%q) = %q contains ..", vp, rel)
				}
			}
			v2, rel2, err := s.resolve(s.virtual(v, rel))
			if err != nil || v2 != v || rel2 != rel {
				t.Fatalf("resolve(%q) = %q, but its client path %q resolves to %q, %v", vp, rel, s.virtual(v, rel), rel2, err)
			}
		}
	})
}

// FuzzResolveInRoot: on a tree with symlinks that point inside, outside and
// in loops, no operation reads, creates or changes anything outside the
// mount.
func FuzzResolveInRoot(f *testing.F) {
	fuzzPathSeeds(f)
	for _, s := range []string{"/in/a.txt", "/out/secret.txt", "/abs/secret.txt", "/loop/x", "/in", "/out"} {
		f.Add(s)
	}
	if err := os.Symlink("x", filepath.Join(f.TempDir(), "l")); err != nil {
		f.Skipf("symlinks unavailable: %v", err)
	}
	links := map[string]string{"in": ".", "out": "../outside", "loop": "loop", "file": "a.txt", "secret": "../outside/secret.txt"}

	f.Fuzz(func(t *testing.T, vp string) {
		base := t.TempDir()
		share := filepath.Join(base, "share")
		outside := filepath.Join(base, "outside")
		mustWrite(t, filepath.Join(share, "a.txt"), "inside")
		mustWrite(t, filepath.Join(outside, "secret.txt"), "secret")
		for name, target := range links {
			if err := os.Symlink(target, filepath.Join(share, name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(outside, filepath.Join(share, "abs")); err != nil {
			t.Fatal(err)
		}
		secret, err := os.Stat(filepath.Join(outside, "secret.txt"))
		if err != nil {
			t.Fatal(err)
		}
		o := DefaultMountOptions()
		o.OnConflict = ConflictOverwrite
		o.MinFreeSpace = 0
		tbl, err := Open([]MountSpec{{Name: "share", Path: share, Options: o}}, Options{Flatten: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tbl.Close()
		s, errs := tbl.Session("alice", tbl.FullAccess())
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		defer s.Close()
		if r, err := s.OpenRead(vp); err == nil {
			fi, err := r.Stat()
			_ = r.Close()
			if err == nil && os.SameFile(fi, secret) {
				t.Fatalf("OpenRead(%q) opened the file outside the mount", vp)
			}
		}
		if h, err := s.OpenWrite(vp, OpenFlags{Write: true, Creat: true}); err == nil {
			_, _ = h.WriteAt([]byte("x"), 0)
			_ = h.Close(false)
		}
		_ = s.Mkdir(vp)
		_ = s.Setstat(vp, Attrs{Size: 0, HasSize: true})
		_, _ = s.Rename("/a.txt", vp, true)
		_, _ = s.Rename(vp, "/moved", true)

		if got := readFileT(t, filepath.Join(outside, "secret.txt")); got != "secret" {
			t.Fatalf("%q: the file outside the mount changed: %q", vp, got)
		}
		if des, err := os.ReadDir(outside); err != nil || len(des) != 1 {
			t.Fatalf("%q: entries outside the mount: %v, %v", vp, des, err)
		}
		if des, err := os.ReadDir(base); err != nil || len(des) != 2 {
			t.Fatalf("%q: entries next to the mount: %v, %v", vp, des, err)
		}
	})
}

// FuzzConflictName: every name freeName tries is in the same directory,
// fits in 255 bytes, keeps valid UTF-8 valid and differs from the original.
func FuzzConflictName(f *testing.F) {
	for _, s := range []string{
		"report.pdf", "archive.tar.gz", ".env", "README", "a (1).txt", "x.",
		strings.Repeat("λ", 127) + ".txt", strings.Repeat("a", 251) + " (1)",
		"a." + strings.Repeat("e", 252), strings.Repeat("b", 255),
	} {
		f.Add(s, uint8(3), DefaultRenameTemplate)
	}
	f.Add("a.b.c", uint8(200), "{n}-{stem}{ext}")
	// Review finding: a skipped candidate must not use up an attempt.
	f.Add("1", uint8(5), "{n}")
	f.Add(strings.Repeat("a", 251)+" (1)", uint8(5), DefaultRenameTemplate)
	f.Add("a.txt", uint8(1), "{stem}{stem}{stem}{n}{ext}")
	f.Fuzz(func(t *testing.T, name string, fails uint8, tmpl string) {
		if name == "" || len(name) > maxNameLen || name == "." || name == ".." || strings.ContainsAny(name, `/\`+"\x00") {
			return // not a file name
		}
		o := DefaultMountOptions()
		o.MaxRenameAttempts = 5
		if ValidateRenameTemplate(tmpl) == nil {
			o.RenameTemplate = tmpl
		}
		rel := filepath.Join("dir", name)
		tries := 0
		final, err := o.freeName(rel, func(cand string) error {
			tries++
			base := filepath.Base(cand)
			switch {
			case filepath.Dir(cand) != "dir":
				t.Fatalf("candidate %q for %q is in another directory", cand, name)
			case len(base) > maxNameLen:
				t.Fatalf("candidate for %q has %d bytes", name, len(base))
			case base == name:
				t.Fatalf("candidate for %q equals the original", name)
			case utf8.ValidString(name) && !utf8.ValidString(base):
				t.Fatalf("candidate %q for %q is not valid UTF-8", base, name)
			}
			if tries <= int(fails)%(o.MaxRenameAttempts+1) {
				return fs.ErrExist
			}
			return nil
		})
		if err != nil {
			t.Fatalf("freeName(%q): %v", name, err)
		}
		if final == "" {
			t.Fatal("empty name")
		}
	})
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return string(b)
}
