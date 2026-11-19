// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// Change is what a change of the configuration did. While the App
// shares, gosftpd reads the change at once (a reload, ADR 0005); when it
// does not share, the next start reads it.
type Change struct {
	Warnings string // what the gosftpd commands warned about
	Reloaded bool   // gosftpd read the change while sharing
	// ReloadFailed is the reason gosftpd gave for refusing the change
	// (config, mounts or audit_output): it keeps serving with what it
	// had, and the configuration file has the change for the next start.
	// ReloadDetail is what it logged about it.
	ReloadFailed string
	ReloadDetail string
	// RestartRequired are the settings that apply only once gosftpd
	// starts again (Restart): under Landlock also a new folder, or
	// uploads to a folder that was read-only (ADR 0011).
	RestartRequired []string
	// Disconnected is how many connections the reload closed: those of
	// the people disabled or removed.
	Disconnected int
}

// ErrNotSharing is a Restart while the App does not share.
var ErrNotSharing = errors.New("not sharing")

// AddPerson adds a person who may use access, folder name to permissions
// (read, upload, readwrite, full).
func (a *App) AddPerson(ctx context.Context, p NewPerson, access map[string]string) (Change, error) {
	switch {
	case p.Name == "":
		return Change{}, errors.New("give the person a name")
	case p.Password == "" && p.Key == "":
		return Change{}, fmt.Errorf("give %s a password or their public key", p.Name)
	case p.Password != "" && p.Key != "":
		return Change{}, fmt.Errorf("give %s a password or a public key, not both", p.Name)
	}
	return a.change(ctx, func(ctx context.Context) (string, error) {
		if p.Password != "" {
			return a.admin().AddWithPassword(ctx, p.Name, p.Password, access)
		}
		return a.admin().AddWithKey(ctx, p.Name, p.Key, access)
	})
}

// SetAccess replaces what the person may do: folder name to permissions,
// none when access is empty. A person connected keeps the access they had
// until they disconnect (ADR 0005).
func (a *App) SetAccess(ctx context.Context, name string, access map[string]string) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().SetAccess(ctx, name, access) })
}

// SetPassword gives the person a new password; a person who logged in
// with a key may then use either.
func (a *App) SetPassword(ctx context.Context, name, password string) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().SetPassword(ctx, name, password) })
}

// Disable refuses the person's logins and ends their connections.
func (a *App) Disable(ctx context.Context, name string) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().Disable(ctx, name) })
}

// Enable lets a disabled person log in again.
func (a *App) Enable(ctx context.Context, name string) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().Enable(ctx, name) })
}

// Remove removes the person and ends their connections.
func (a *App) Remove(ctx context.Context, name string) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().Remove(ctx, name) })
}

// SetFolders replaces the shared folders; the people lose the folders
// that go away. The last folder cannot go.
func (a *App) SetFolders(ctx context.Context, folders []supervisor.Folder) (Change, error) {
	return a.change(ctx, func(ctx context.Context) (string, error) { return a.admin().SetFolders(ctx, folders) })
}

// OnConflict values: what an upload to an existing file does.
var OnConflict = []string{"rename", "reject", "overwrite", "version"}

// SetOnConflict sets what an upload to an existing file does, for every
// folder.
func (a *App) SetOnConflict(ctx context.Context, v string) (Change, error) {
	if !slices.Contains(OnConflict, v) {
		return Change{}, fmt.Errorf("on_conflict %q: want one of %s", v, strings.Join(OnConflict, ", "))
	}
	return a.change(ctx, func(ctx context.Context) (string, error) {
		return a.admin().Change(ctx, func(s *supervisor.Settings) { s.OnConflict = v })
	})
}

// change runs one change of the configuration, then, while sharing, the
// reload that applies it. Changes run one at a time. A change that fails
// half-way may have written part of itself (Remove removes the person,
// then fails to turn password logins off): gosftpd reads the file all
// the same, so that it serves what the file says, and the error is
// returned with what the reload did.
func (a *App) change(ctx context.Context, run func(context.Context) (string, error)) (Change, error) {
	a.changeMu.Lock()
	defer a.changeMu.Unlock()
	a.mu.Lock()
	mark := a.logSeq
	a.mu.Unlock()
	w, runErr := run(ctx)
	c := Change{Warnings: w}
	a.mu.Lock()
	srv, stopping := a.srv, a.stopping
	a.mu.Unlock()
	if srv == nil || stopping {
		return c, runErr // the next start reads it
	}
	r, err := srv.Reload(ctx, a.G.Layout.AuditLog())
	if errors.Is(err, supervisor.ErrNotRunning) {
		return c, runErr // gosftpd exited meanwhile: Done tells
	}
	if err != nil {
		return c, firstErr(runErr, fmt.Errorf("applying the change: %w", err))
	}
	c.Reloaded = r.OK
	c.RestartRequired = r.RestartRequired
	c.Disconnected = r.Disconnected
	if !r.OK {
		c.ReloadFailed = r.Reason
		c.ReloadDetail = a.logSince(ctx, mark)
	}
	return c, runErr
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// logSince returns the warnings and errors gosftpd logged after mark,
// waiting a moment for them: the operational log can come after the
// audit event.
func (a *App) logSince(ctx context.Context, mark int) string {
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		var lines []string
		for _, e := range a.logTail {
			if e.seq > mark {
				lines = append(lines, e.text)
			}
		}
		a.mu.Unlock()
		if len(lines) > 0 || time.Now().After(deadline) {
			return strings.Join(lines, "\n")
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Restart stops gosftpd, as Stop does, and starts it again once it has
// exited: for the settings a reload says apply only at a restart. Stop
// waits up to shutdown_timeout for the connections to end and cuts the
// rest, so the window restarts at once only with nobody connected, or
// when the person says so (ADR 0013, "Restarts").
func (a *App) Restart(ctx context.Context) (supervisor.Details, error) {
	a.changeMu.Lock()
	defer a.changeMu.Unlock()
	a.mu.Lock()
	old := a.srv
	if old != nil {
		a.stopping = true
	}
	a.mu.Unlock()
	if old == nil {
		return supervisor.Details{}, ErrNotSharing
	}
	old.Stop()
	select {
	case <-old.Done():
	case <-ctx.Done():
		return supervisor.Details{}, ctx.Err()
	}
	a.mu.Lock()
	if a.srv == old {
		a.srv, a.stopping, a.follower = nil, false, nil
		a.activity.Exited()
	}
	a.mu.Unlock()
	if a.Lock != nil {
		_ = a.Lock.ClearServer()
	}
	return a.Start(ctx, nil)
}
