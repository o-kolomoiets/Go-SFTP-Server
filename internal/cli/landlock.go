// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// startSandbox applies Landlock (ADR 0011). Tests replace it, so that go
// test never sandboxes its own process: a ruleset cannot be lifted.
var startSandbox = sandbox.Start

// applySandbox is serve's sandbox step, once the listeners are bound and
// before any hook can run: it clears the ambient capabilities, which exec
// hooks would inherit (AmbientCapabilities=CAP_NET_BIND_SERVICE for port
// 22), and applies Landlock; ephemeral is the directory of serve
// --ephemeral, held open. A *sandbox.RequiredError becomes a
// configError (exit status 2); any other error fails the start with exit
// status 1.
func applySandbox(ctx context.Context, c *config.Config, mounts *vfs.Table, ephemeral *sandbox.MountDir, log *slog.Logger) (sandbox.Result, error) {
	cleared, err := sandbox.ClearAmbient()
	if err != nil {
		return sandbox.Result{}, err
	}
	if cleared != 0 {
		log.InfoContext(ctx, "ambient capabilities cleared", "set", fmt.Sprintf("%#x", cleared))
	}
	res, err := startSandbox(ctx, sandbox.Options{Config: c, Mounts: heldMounts(mounts), Ephemeral: ephemeral, Log: log})
	if _, ok := errors.AsType[*sandbox.RequiredError](err); ok {
		return res, configError{err}
	}
	return res, err
}

// heldMounts returns the mount directories as the table holds them open:
// the rules are added through these descriptors.
func heldMounts(t *vfs.Table) []sandbox.MountDir {
	held := t.HeldDirs()
	dirs := make([]sandbox.MountDir, len(held))
	for i, h := range held {
		dirs[i] = sandbox.MountDir{Name: h.Mount, FD: h.FD, Dev: h.Dev, Ino: h.Ino}
	}
	return dirs
}

// explain returns a function that adds the Landlock hint to a permission
// error on a path that the ruleset applied at start does not cover with
// need; without a ruleset it changes nothing. r.mu is held.
func (r *running) explain(need sandbox.Rights) func(error) error {
	rs := r.ruleset
	return func(err error) error { return rs.Explain(err, need) }
}

// landlockReload is what a reload changes because Landlock was applied at
// start (ADR 0011).
type landlockReload struct {
	// restart are the keys for restart_required.
	restart []string
	// unavailable are mounts left out until a restart.
	unavailable []string
	// staleHooks counts the exec hooks left out.
	staleHooks int
}

// checkLandlock checks what the new configuration c uses against the rules
// applied at start, which are not computed again, and changes c to what
// can be served without a restart: a new or moved mount that the rules do
// not cover, or one recreated or remounted since the start, is left out
// as unavailable; a mount whose new rights are not covered keeps its
// running read_only and create; a new audit.output that is not covered
// keeps the running one; exec hooks are left out. A trusted file that is
// not covered fails when it is read, as an unreadable file does, and its
// key is listed; an include or the revocation list fails the reload when
// it is read, so they are not. r.mu is held.
func (r *running) checkLandlock(ctx context.Context, c *config.Config) landlockReload {
	var out landlockReload
	rs := r.ruleset
	if rs == nil {
		return out
	}
	restart := func(key string) {
		if !slices.Contains(out.restart, key) {
			out.restart = append(out.restart, key)
		}
	}
	warn := func(key, path, outcome string) {
		r.log.WarnContext(ctx, "configuration", "detail", key+": "+path+": "+sandbox.Hint+"; "+outcome)
	}
	mounts := map[string]string{} // by the key of their use
	for name, m := range c.Mounts {
		mounts[sandbox.MountUse(name, m).Key] = name
	}
	auditUncovered := false
	for _, f := range rs.Check(sandbox.Uses(c)) {
		if name, ok := mounts[f.Key]; ok {
			r.checkMount(c, name, f, restart, warn, &out)
			continue
		}
		switch f.Key {
		case "audit.output":
			auditUncovered = true
		case "include", "auth.revoked_keys_file":
			// Reading it fails the reload, with the hint.
		default:
			restart(f.Key)
		}
	}

	// The audit file is reopened before the configuration is read: an
	// unchanged audit.output that is no longer covered has failed already,
	// with the hint. A new one is opened only when it is covered.
	if next := c.Audit.Output; next != r.c.Audit.Output && (auditUncovered || rs.KeepsOpen(next)) {
		c.Audit.Output = r.c.Audit.Output
		restart("audit.output")
		warn("audit.output", next, "the running audit output stays")
	} else if auditUncovered {
		restart("audit.output")
	}

	if c.ExecHook() >= 0 {
		kept := make([]*config.Hook, 0, len(c.Hooks))
		for _, h := range c.Hooks {
			if h != nil && h.Exec != nil {
				r.log.WarnContext(ctx, "configuration", "detail", fmt.Sprintf("hook %q is left out until a restart: Landlock was applied at start, and gosftpd applies it only without exec hooks", h.Name))
				out.staleHooks++
				continue
			}
			kept = append(kept, h)
		}
		c.Hooks = kept
		restart("hooks")
	}
	return out
}

// checkMount decides what happens to mount name of c, whose use f the
// rules do not cover: with its path unchanged and its running rights
// covered, it keeps its running read_only or create (or both); otherwise
// it is left out as unavailable.
func (r *running) checkMount(c *config.Config, name string, f sandbox.Finding, restart func(string), warn func(key, path, outcome string), out *landlockReload) {
	m := c.Mounts[name]
	old := r.c.Mounts[name]
	if old != nil && filepath.Clean(old.Path) == filepath.Clean(m.Path) {
		ro, create := m.ReadOnly != old.ReadOnly, m.Create != old.Create
		for _, keep := range [][2]bool{{ro, false}, {false, create}, {ro, create}} {
			if !keep[0] && !keep[1] {
				continue
			}
			k := *m
			if keep[0] {
				k.ReadOnly = old.ReadOnly
			}
			if keep[1] {
				k.Create = old.Create
			}
			if len(r.ruleset.Check([]sandbox.Use{sandbox.MountUse(name, &k)})) > 0 {
				continue
			}
			if keep[0] {
				key := toml.Key{"mounts", name, "read_only"}.String()
				restart(key)
				warn(key, f.Checked, fmt.Sprintf("the mount stays read_only = %v", old.ReadOnly))
			}
			if keep[1] {
				key := toml.Key{"mounts", name, "create"}.String()
				restart(key)
				warn(key, f.Checked, fmt.Sprintf("the mount stays create = %v", old.Create))
			}
			m.ReadOnly, m.Create = k.ReadOnly, k.Create
			return
		}
	}
	out.unavailable = append(out.unavailable, name)
	restart(f.Key)
	warn(f.Key, f.Checked, "the mount is unavailable until then")
}

// previewLandlock adds, for config validate --check-fs, the warnings that
// serve would log when it applies Landlock. A rule that would be placed on
// / is a warning in "auto" and an error in "required", as at start.
func previewLandlock(c *config.Config) ([]string, error) {
	warns, err := sandbox.Preview(c)
	for i, w := range warns {
		warns[i] = "landlock: " + w
	}
	if re, ok := errors.AsType[*sandbox.RootError](err); ok {
		// As serve says it.
		skip := "landlock: not applied: a rule would be placed on / (" + re.Key + ")"
		if c.Server.Landlock == config.LandlockRequired {
			return warns, configError{fmt.Errorf("%s; server.landlock is %q", skip, config.LandlockRequired)}
		}
		return append(warns, skip), nil
	}
	if err != nil {
		return warns, configError{fmt.Errorf("landlock: failed: %w", err)}
	}
	return warns, nil
}
