// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// memFS is a file system in memory for the rule computation and the
// reload check. Tests write paths with slashes; native turns them into
// this system's.
type memFS struct {
	t     *testing.T
	nodes map[string]*memNode
	next  uint64 // the next inode number
}

type memNode struct {
	mode     fs.FileMode // fs.ModeDir, fs.ModeSymlink, fs.ModeDevice or 0
	dev, ino uint64
	target   string // a symlink's, native
	noList   bool   // ReadDir fails: 0710 to gosftpd
	noSearch bool   // the entries cannot be looked up: 0600
}

// native turns a slash path of a test into this system's absolute path:
// /etc/x stays on Unix and becomes C:\etc\x on Windows.
func native(p string) string {
	if runtime.GOOS == "windows" {
		return `C:` + filepath.FromSlash(p)
	}
	return p
}

// slash is the opposite of native.
func slash(p string) string {
	if runtime.GOOS == "windows" {
		return filepath.ToSlash(strings.TrimPrefix(p, "C:"))
	}
	return p
}

func newMemFS(t *testing.T) *memFS {
	t.Helper()
	m := &memFS{t: t, nodes: map[string]*memNode{}, next: 2}
	m.nodes[native("/")] = &memNode{mode: fs.ModeDir, dev: 1, ino: 1}
	return m
}

// add creates p, and its missing parents as directories on their parent's
// device.
func (m *memFS) add(p string, mode fs.FileMode, newDev bool) *memNode {
	m.t.Helper()
	path := native(p)
	parent := filepath.Dir(path)
	if m.nodes[parent] == nil {
		m.add(slash(parent), fs.ModeDir, false)
	}
	if !m.nodes[parent].mode.IsDir() {
		m.t.Fatalf("memFS: %s is not a directory", parent)
	}
	dev := m.nodes[parent].dev
	if newDev {
		dev = m.next + 1000
	}
	n := &memNode{mode: mode, dev: dev, ino: m.next}
	m.next++
	m.nodes[path] = n
	return n
}

func (m *memFS) dirs(ps ...string) *memFS {
	m.t.Helper()
	for _, p := range ps {
		if m.nodes[native(p)] == nil {
			m.add(p, fs.ModeDir, false)
		}
	}
	return m
}

func (m *memFS) files(ps ...string) *memFS {
	m.t.Helper()
	for _, p := range ps {
		m.add(p, 0, false)
	}
	return m
}

// volume makes p the root of a file system of its own.
func (m *memFS) volume(p string) *memFS {
	m.t.Helper()
	m.add(p, fs.ModeDir, true)
	return m
}

func (m *memFS) device(p string) *memFS {
	m.t.Helper()
	m.add(p, fs.ModeDevice|fs.ModeCharDevice, false)
	return m
}

// symlink creates p pointing to target, which is absolute (a slash path)
// or relative to p's directory.
func (m *memFS) symlink(p, target string) *memFS {
	m.t.Helper()
	n := m.add(p, fs.ModeSymlink, false)
	n.target = filepath.FromSlash(target)
	if strings.HasPrefix(target, "/") {
		n.target = native(target)
	}
	return m
}

// hardlink gives the file at old a second name.
func (m *memFS) hardlink(p, old string) *memFS {
	m.t.Helper()
	m.nodes[native(p)] = m.node(old)
	return m
}

func (m *memFS) noList(p string) *memFS {
	m.t.Helper()
	m.node(p).noList = true
	return m
}

func (m *memFS) noSearch(p string) *memFS {
	m.t.Helper()
	m.node(p).noSearch = true
	return m
}

func (m *memFS) node(p string) *memNode {
	m.t.Helper()
	n := m.nodes[native(p)]
	if n == nil {
		m.t.Fatalf("memFS: no %s", p)
	}
	return n
}

// remove deletes p and everything below it.
func (m *memFS) remove(p string) *memFS {
	m.t.Helper()
	path := native(p)
	for k := range m.nodes {
		if beneath(k, path) {
			delete(m.nodes, k)
		}
	}
	return m
}

// rename moves p, with everything below it, to q, replacing q.
func (m *memFS) rename(p, q string) *memFS {
	m.t.Helper()
	from, to := native(p), native(q)
	m.remove(q)
	for k, n := range m.nodes {
		if rel, ok := relative(k, from); ok {
			delete(m.nodes, k)
			m.nodes[filepath.Join(to, rel)] = n
		}
	}
	return m
}

// replace gives the file p a new inode, as a rename over it does.
func (m *memFS) replace(p string) *memFS {
	m.t.Helper()
	old := m.node(p)
	n := *old
	n.ino = m.next
	m.next++
	m.nodes[native(p)] = &n
	return m
}

// walk resolves path, and a final symlink too with follow. It returns the
// path reached, with every symlink resolved.
func (m *memFS) walk(path string, follow bool) (string, *memNode, error) {
	vol := filepath.VolumeName(path)
	root := vol + string(filepath.Separator)
	if !filepath.IsAbs(path) {
		return "", nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrInvalid}
	}
	rest := components(path[len(vol):])
	cur, hops := root, 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		if c == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		if m.nodes[cur].noSearch {
			return "", nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrPermission}
		}
		next := filepath.Join(cur, c)
		n := m.nodes[next]
		switch {
		case n == nil:
			return "", nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
		case n.mode&fs.ModeSymlink != 0 && (len(rest) > 0 || follow):
			if hops++; hops > 40 {
				return "", nil, &fs.PathError{Op: "stat", Path: path, Err: syscall.ELOOP}
			}
			t := n.target
			if !filepath.IsAbs(t) {
				t = filepath.Join(cur, t)
			}
			tv := filepath.VolumeName(t)
			rest = append(components(t[len(tv):]), rest...)
			cur = tv + string(filepath.Separator)
		case len(rest) > 0 && !n.mode.IsDir():
			return "", nil, &fs.PathError{Op: "stat", Path: path, Err: syscall.ENOTDIR}
		default:
			cur = next
		}
	}
	return cur, m.nodes[cur], nil
}

func components(p string) []string {
	var cs []string
	for c := range strings.SplitSeq(filepath.ToSlash(p), "/") {
		if c != "" && c != "." {
			cs = append(cs, c)
		}
	}
	return cs
}

func (m *memFS) Lstat(path string) (Info, error) {
	_, n, err := m.walk(path, false)
	if err != nil {
		return Info{}, err
	}
	return Info{Dev: n.dev, Ino: n.ino, Mode: n.mode}, nil
}

func (m *memFS) Stat(path string) (Info, error) {
	_, n, err := m.walk(path, true)
	if err != nil {
		return Info{}, err
	}
	return Info{Dev: n.dev, Ino: n.ino, Mode: n.mode}, nil
}

func (m *memFS) ReadDir(path string) ([]string, error) {
	r, n, err := m.walk(path, true)
	switch {
	case err != nil:
		return nil, err
	case !n.mode.IsDir():
		return nil, &fs.PathError{Op: "readdir", Path: path, Err: syscall.ENOTDIR}
	case n.noList || n.noSearch:
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	var names []string
	for k := range m.nodes {
		if k != r && filepath.Dir(k) == r {
			names = append(names, filepath.Base(k))
		}
	}
	slices.Sort(names)
	return names, nil
}

func (m *memFS) EvalSymlinks(path string) (string, error) {
	r, _, err := m.walk(path, true)
	return r, err
}

func TestMemFS(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/a/f").symlink("/a/l", "f").symlink("/b", "/a").symlink("/loop", "/loop")
	if r, err := m.EvalSymlinks(native("/b/l")); err != nil || r != native("/a/f") {
		t.Errorf("EvalSymlinks(/b/l) = %q, %v", r, err)
	}
	if i, err := m.Lstat(native("/b/l")); err != nil || i.Mode&fs.ModeSymlink == 0 {
		t.Errorf("Lstat(/b/l) = %v, %v", i, err)
	}
	if _, err := m.Stat(native("/loop")); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("Stat(/loop) = %v", err)
	}
	if _, err := m.Stat(native("/a/f/x")); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("Stat(/a/f/x) = %v", err)
	}
	if names, err := m.ReadDir(native("/b")); err != nil || !slices.Equal(names, []string{"f", "l"}) {
		t.Errorf("ReadDir(/b) = %v, %v", names, err)
	}
	m.noSearch("/a")
	if _, err := m.Stat(native("/a/f")); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Stat below a directory that cannot be searched = %v", err)
	}
}
