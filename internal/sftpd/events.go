// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"log/slog"
	"path"

	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// SetHooks hands the session's file events to d (ADR 0010); connID is the
// connection's audit ID, for exec hooks.
func (h *Handler) SetHooks(d *hooks.Dispatcher, connID string) {
	h.hooks, h.connID = d, connID
}

// event records a file event; one on a path in a mount gets the mount's
// name.
func (h *Handler) event(op, p string, attrs ...slog.Attr) []slog.Attr {
	if m := h.s.MountOf(p); m != "" {
		attrs = append([]slog.Attr{slog.String("mount", m)}, attrs...)
	}
	h.audit.Event(op, attrs...)
	return attrs
}

// fileEvent is what a hook needs of a successful file operation besides
// its audit line.
type fileEvent struct {
	path, final, target string
	uploaded            bool             // an fs.rename that completes an upload
	where               func() vfs.Where // the file with its identity; nil: Locate
	gone                bool             // fs.remove, fs.rmdir: nothing to check
	skip                bool             // not news for hooks
}

// notify hands a successful file event to the hooks that want it; attrs
// are those of its audit line.
func (h *Handler) notify(op string, f fileEvent, attrs []slog.Attr) {
	if h.hooks == nil || f.skip {
		return
	}
	name := f.path
	if f.final != "" {
		name = f.final
	}
	mount := h.s.MountOf(name)
	if !h.hooks.Wants(op, f.uploaded, mount, path.Base(name)) {
		return
	}
	var w vfs.Where
	if f.where != nil {
		w = f.where()
	} else {
		w = h.s.Locate(name)
	}
	if f.gone {
		w.Info = nil
	}
	h.hooks.Notify(&hooks.Event{
		Name: op, Uploaded: f.uploaded, Mount: mount, User: h.s.User(), ConnID: h.connID,
		Path: f.path, FinalPath: f.final, TargetPath: f.target,
		Line:     h.audit.Render(op, attrs...),
		HostPath: w.HostPath, Info: w.Info, Gone: f.gone,
	})
}
