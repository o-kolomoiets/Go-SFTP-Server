// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// previewFS is the file system as serve finds it when it computes the
// rules: with the directories that it creates before, for each mount with
// create = true whose directory (the parent of {user}) does not exist yet.
// Preview then warns as serve does about the directory that holds such a
// mount directory, as gosftpd init's share next to gosftpd.toml.
type previewFS struct {
	FS
	// created are the directories still to be created, by their path
	// with every symlink resolved, with the device of the directory they
	// will be created in.
	created map[string]uint64
}

func newPreviewFS(fsys FS, c *config.Config) FS {
	p := previewFS{FS: fsys, created: map[string]uint64{}}
	for _, name := range sortedKeys(c.Mounts) {
		m := c.Mounts[name]
		if !m.Create {
			continue
		}
		dir := filepath.Clean(m.Path)
		if filepath.Base(dir) == vfs.UserPlaceholder {
			dir = filepath.Dir(dir)
		}
		existing, missing, ok := p.lookup(dir)
		if !ok || missing == "" {
			continue
		}
		info, err := fsys.Stat(existing)
		if err != nil || !info.IsDir() {
			continue // creating it would fail the start
		}
		for d := filepath.Join(existing, missing); d != existing; d = filepath.Dir(d) {
			p.created[d] = info.Dev
		}
	}
	return p
}

// lookup splits path, which may not exist, into its nearest existing
// ancestor with every symlink resolved and the rest below it.
func (p previewFS) lookup(path string) (existing, missing string, ok bool) {
	for d := filepath.Clean(path); ; d = filepath.Dir(d) {
		if _, err := p.FS.Lstat(d); !errors.Is(err, fs.ErrNotExist) {
			r, err := p.FS.EvalSymlinks(d)
			return filepath.Clean(r), missing, err == nil
		}
		if isRoot(d) {
			return "", "", false
		}
		missing = filepath.Join(filepath.Base(d), missing)
	}
}

// virtual returns path resolved when it is a directory still to be
// created.
func (p previewFS) virtual(path string) (string, bool) {
	existing, missing, ok := p.lookup(path)
	if !ok || missing == "" {
		return "", false
	}
	v := filepath.Join(existing, missing)
	_, ok = p.created[v]
	return v, ok
}

func (p previewFS) Lstat(path string) (Info, error) {
	info, err := p.FS.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if v, ok := p.virtual(path); ok {
			return Info{Dev: p.created[v], Mode: fs.ModeDir}, nil
		}
	}
	return info, err
}

func (p previewFS) Stat(path string) (Info, error) {
	info, err := p.FS.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if v, ok := p.virtual(path); ok {
			return Info{Dev: p.created[v], Mode: fs.ModeDir}, nil
		}
	}
	return info, err
}

// ReadDir adds the directories to be created to their parent's names.
func (p previewFS) ReadDir(path string) ([]string, error) {
	names, err := p.FS.ReadDir(path)
	var dir string
	switch {
	case err == nil:
		if r, err := p.FS.EvalSymlinks(path); err == nil {
			dir = filepath.Clean(r)
		}
	case errors.Is(err, fs.ErrNotExist):
		v, ok := p.virtual(path)
		if !ok {
			return nil, err
		}
		dir = v
	default:
		return nil, err
	}
	for d := range p.created {
		if filepath.Dir(d) == dir && !slices.Contains(names, filepath.Base(d)) {
			names = append(names, filepath.Base(d))
		}
	}
	return names, nil
}

func (p previewFS) EvalSymlinks(path string) (string, error) {
	r, err := p.FS.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		if v, ok := p.virtual(path); ok {
			return v, nil
		}
	}
	return r, err
}
