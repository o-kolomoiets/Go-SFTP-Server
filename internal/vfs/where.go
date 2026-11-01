// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// Where locates the file of an event for hooks (ADR 0010).
type Where struct {
	Mount    string      // the visible name (Mount.Display)
	HostPath string      // "" when the path names no file in a mount
	Info     fs.FileInfo // the file's identity when the event happened; nil if unknown
}

// hostPath returns the host path of rel in v: for a home mount, inside the
// user's directory.
func (v *view) hostPath(rel string) string { return filepath.Join(v.root.Name(), rel) }

// MountOf returns the visible name of the mount a client path lies in, or
// "" for the virtual root and paths that name no mount. Nothing is opened.
func (s *Session) MountOf(vp string) string {
	if s.flatten {
		return s.views[0].name()
	}
	p := path.Clean("/" + vp)
	if p == "/" {
		return ""
	}
	name, _, _ := strings.Cut(p[1:], "/")
	if v := s.byName[name]; v != nil {
		return v.name()
	}
	return ""
}

// Locate returns the mount and host path of vp and the identity of what is
// there now, without permission checks and without stat redirects: for
// hooks, right after an operation succeeded.
func (s *Session) Locate(vp string) Where {
	v, rel, err := s.resolve(vp)
	if err != nil || v == nil {
		return Where{Mount: s.MountOf(vp)}
	}
	w := Where{Mount: v.name(), HostPath: v.hostPath(rel)}
	if fi, err := v.root.Lstat(rel); err == nil {
		w.Info = fi
	}
	return w
}
