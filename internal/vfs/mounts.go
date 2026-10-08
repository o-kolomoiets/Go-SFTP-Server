// SPDX-License-Identifier: Apache-2.0

// Package vfs exposes a set of host directories ("mounts") as one virtual
// POSIX tree. Every file operation goes through an *os.Root per mount, so a
// client path can never resolve outside its mount, whether via "..",
// absolute paths or symlinks.
package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ConflictPolicy decides what an upload does when the target file exists.
type ConflictPolicy string

// Conflict policies.
const (
	ConflictRename    ConflictPolicy = "rename"
	ConflictReject    ConflictPolicy = "reject"
	ConflictOverwrite ConflictPolicy = "overwrite"
)

// ParseConflictPolicy validates a policy name.
func ParseConflictPolicy(s string) (ConflictPolicy, error) {
	switch p := ConflictPolicy(s); p {
	case ConflictRename, ConflictReject, ConflictOverwrite:
		return p, nil
	default:
		return "", fmt.Errorf("unknown conflict policy %q (want rename, reject or overwrite)", s)
	}
}

const (
	maxPathLen  = 4096
	maxDepth    = 64
	maxNameLen  = 255
	filePerm    = 0o644
	dirPerm     = 0o755
	maxRenameNo = 100
)

var mountNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)

// ValidMountName reports whether name can be used as a mount name.
func ValidMountName(name string) bool { return mountNameRE.MatchString(name) }

// MountSpec describes one directory to expose.
type MountSpec struct {
	Name     string // the top-level directory clients see
	Path     string // absolute host path
	ReadOnly bool
}

// Options configure a Table.
type Options struct {
	OnConflict ConflictPolicy
	// Flatten exposes a single mount as "/" instead of "/<name>".
	Flatten bool
}

// Mount is an opened MountSpec.
type Mount struct {
	name     string
	hostPath string
	readOnly bool
	root     *os.Root
}

// Name returns the mount name.
func (m *Mount) Name() string { return m.name }

// HostPath returns the host directory (for server-side messages only).
func (m *Mount) HostPath() string { return m.hostPath }

// ReadOnly reports whether the mount rejects modifications.
func (m *Mount) ReadOnly() bool { return m.readOnly }

// Table is the set of mounts served to clients.
type Table struct {
	mounts  []*Mount // sorted by name
	byName  map[string]*Mount
	flatten bool
	policy  ConflictPolicy
	started time.Time
}

// Open validates specs and opens an os.Root for every mount.
func Open(specs []MountSpec, opts Options) (*Table, error) {
	if len(specs) == 0 {
		return nil, errors.New("no directories to serve")
	}
	policy := opts.OnConflict
	if policy == "" {
		policy = ConflictRename
	}
	if _, err := ParseConflictPolicy(string(policy)); err != nil {
		return nil, err
	}
	if err := validateSpecs(specs); err != nil {
		return nil, err
	}

	t := &Table{
		byName:  make(map[string]*Mount, len(specs)),
		flatten: opts.Flatten && len(specs) == 1,
		policy:  policy,
		started: time.Now(),
	}
	for _, s := range specs {
		root, err := os.OpenRoot(s.Path)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("mount %q: %w", s.Name, err)
		}
		m := &Mount{name: s.Name, hostPath: s.Path, readOnly: s.ReadOnly, root: root}
		t.mounts = append(t.mounts, m)
		t.byName[s.Name] = m
	}
	slices.SortFunc(t.mounts, func(a, b *Mount) int { return strings.Compare(a.name, b.name) })
	return t, nil
}

func validateSpecs(specs []MountSpec) error {
	seen := make(map[string]bool, len(specs))
	for i, s := range specs {
		if !ValidMountName(s.Name) {
			return fmt.Errorf("mount name %q: use letters, digits, '.', '_', '-' and spaces (max 64)", s.Name)
		}
		key := strings.ToLower(s.Name)
		if seen[key] {
			return fmt.Errorf("duplicate mount name %q", s.Name)
		}
		seen[key] = true
		if !filepath.IsAbs(s.Path) {
			return fmt.Errorf("mount %q: path %q is not absolute", s.Name, s.Path)
		}
		for _, o := range specs[:i] {
			if within(s.Path, o.Path) || within(o.Path, s.Path) {
				return fmt.Errorf("mounts %q and %q overlap", o.Name, s.Name)
			}
		}
	}
	return nil
}

// within reports whether p equals dir or lies below it.
func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// Mounts returns the mounts sorted by name.
func (t *Table) Mounts() []*Mount { return slices.Clone(t.mounts) }

// Flattened reports whether the single mount is served as "/".
func (t *Table) Flattened() bool { return t.flatten }

// Policy returns the conflict policy.
func (t *Table) Policy() ConflictPolicy { return t.policy }

// Close releases all mount roots.
func (t *Table) Close() error {
	errs := make([]error, 0, len(t.mounts))
	for _, m := range t.mounts {
		errs = append(errs, m.root.Close())
	}
	return errors.Join(errs...)
}

// resolve maps a client path to a mount and a path relative to its root.
// m == nil means the synthetic root "/" (only when not flattened); rel == "."
// means the mount root itself.
func (t *Table) resolve(vp string) (m *Mount, rel string, err error) {
	if len(vp) > maxPathLen || strings.IndexByte(vp, 0) >= 0 || !utf8.ValidString(vp) {
		return nil, "", ErrInvalidPath
	}
	p := path.Clean("/" + vp)

	var rest string
	if t.flatten {
		m, rest = t.mounts[0], p[1:]
	} else {
		if p == "/" {
			return nil, "", nil
		}
		var name string
		name, rest, _ = strings.Cut(p[1:], "/")
		if m = t.byName[name]; m == nil {
			return nil, "", fs.ErrNotExist
		}
	}
	if rest == "" {
		return m, ".", nil
	}
	if strings.Count(rest, "/") >= maxDepth || !fs.ValidPath(rest) {
		return nil, "", ErrInvalidPath
	}
	if runtime.GOOS == "windows" {
		for c := range strings.SplitSeq(rest, "/") {
			if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
				return nil, "", ErrInvalidPath
			}
		}
	}
	local, err := filepath.Localize(rest)
	if err != nil {
		return nil, "", ErrInvalidPath
	}
	return m, local, nil
}

// topLevel reports whether vp names an entry directly in the synthetic root.
func (t *Table) topLevel(vp string) bool {
	return !t.flatten && path.Dir(path.Clean("/"+vp)) == "/"
}

// virtual returns the canonical client path of rel inside m.
func (t *Table) virtual(m *Mount, rel string) string {
	rel = filepath.ToSlash(rel)
	if t.flatten {
		return path.Clean("/" + rel)
	}
	return path.Clean("/" + m.name + "/" + rel)
}
