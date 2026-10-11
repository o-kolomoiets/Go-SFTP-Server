// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/sdnotify"
	"github.com/o-kolomoiets/go-sftp-server/internal/server"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// running is a serving gosftpd: what a reload reads again and replaces
// (ADR 0005).
type running struct {
	flags  *pflag.FlagSet
	opts   serveOptions // config is the absolute path of the file in use
	getenv func(string) string
	log    *slog.Logger
	level  *slog.LevelVar
	out    *auditOutput
	al     *audit.Logger
	srv    *server.Server

	mu     sync.Mutex // serializes reloads; guards the fields below
	c      *config.Config
	mounts *vfs.Table   // a reference to the current table
	tables []*vfs.Table // every table built, until no connection uses it
	keys   config.KeyFiles
	// hostKeys are the host keys in use; reloaded gets a value after each
	// reload, for watchHostCerts.
	hostKeys hostKeys
	reloaded chan struct{}
}

// Reasons a reload fails, for the server.reload event.
const (
	reloadConfig      = "config"       // the configuration cannot be read or is invalid
	reloadMounts      = "mounts"       // the mount table cannot be built
	reloadAuditOutput = "audit_output" // a new audit.output cannot be opened
)

// hupKey carries a channel that triggers reloads instead of SIGHUP (tests).
type hupKey struct{}

// reloadLoop reloads on every value from hup until ctx is done. A signal
// that arrives during a reload triggers one more (hup has a buffer of one).
func (r *running) reloadLoop(ctx context.Context, hup <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		// The timestamp is taken after the signal, as systemd requires.
		if err := sdnotify.Reloading(); err != nil {
			r.log.DebugContext(ctx, "sd_notify", "err", err)
		}
		status := "configuration reloaded"
		if !r.reload(ctx) {
			status = "configuration reload failed, see the log"
		}
		if err := sdnotify.Notify("READY=1\nSTATUS=" + status); err != nil {
			r.log.DebugContext(ctx, "sd_notify", "err", err)
		}
	}
}

// reload reopens the audit log, then applies the configuration file again.
// Any error keeps the running configuration. It reports success.
func (r *running) reload(ctx context.Context) bool {
	start := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mounts == nil {
		return false // shutting down
	}
	// First, and whatever the result: logrotate moved the file.
	if err := r.out.reopen(); err != nil {
		r.log.ErrorContext(ctx, "cannot reopen the audit log; writing it fails until it can be opened", "err", err)
	}
	r.al.Probe()

	restart, disconnected, reason, err := r.apply(ctx)
	attrs := []slog.Attr{slog.String("result", "ok")}
	if err != nil {
		r.log.ErrorContext(ctx, "configuration reload failed; the running configuration stays", "err", err)
		// The error text can name host paths; the audit log never does.
		attrs = []slog.Attr{slog.String("result", "error"), slog.String("reason", reason)}
	} else {
		r.log.InfoContext(ctx, "configuration reloaded", "disconnected", disconnected)
		if len(restart) > 0 {
			attrs = append(attrs, slog.String("restart_required", strings.Join(restart, ",")))
		}
		if disconnected > 0 {
			attrs = append(attrs, slog.Int("disconnected", disconnected))
		}
	}
	r.al.Event("server.reload", append(attrs, slog.Int64("duration_ms", time.Since(start).Milliseconds()))...)
	return err == nil
}

// apply builds the new configuration and switches to it. Everything that
// can fail comes first; the switch cannot fail.
func (r *running) apply(ctx context.Context) (restart []string, disconnected int, reason string, err error) {
	c, masked, err := buildConfig(r.flags, r.opts, r.getenv, true)
	if err != nil {
		return nil, 0, reloadConfig, err
	}
	warn := func(details []string) {
		for _, d := range details {
			r.log.WarnContext(ctx, "configuration", "detail", d)
		}
	}
	warn(masked)
	warns, err := c.Validate()
	warn(warns)
	if err != nil {
		return nil, 0, reloadConfig, problemsError{c.File, err}
	}
	// Before the file checks, so that they check the files in use.
	restart = keepRestartOnly(r.c, c)
	for _, k := range restart {
		r.log.WarnContext(ctx, "this setting changes only at restart; the running value stays", "key", k)
	}
	// Revocation does not wait for host key files (ADR 0008): with a host
	// key that cannot be used, the running host keys stay, and the file
	// checks below cover those.
	hostKeys, warns, err := loadHostKeys(c.Server.HostKeys, hostKeyOptions{certs: c.Server.HostCertificates, lenient: true})
	warn(warns)
	if err != nil {
		r.log.WarnContext(ctx, "host keys cannot be used; the running host keys stay", "err", err)
		hostKeys = r.hostKeys
		c.Server.HostKeys = hostKeys.paths()
		c.Server.HostCertificates = r.c.Server.HostCertificates
	}
	warns, unavailable, err := c.CheckFSReload(r.liveMounts())
	warn(warns)
	if err != nil {
		return nil, 0, reloadConfig, problemsError{c.File, err}
	}
	authn, keys, warns, err := c.BuildAuthenticator(config.AuthOptions{Reload: true, Previous: r.keys})
	warn(warns)
	if err != nil {
		return nil, 0, reloadConfig, err
	}
	level, err := parseLevel(c.Log.Level)
	if err != nil {
		return nil, 0, reloadConfig, err
	}
	specs, err := c.MountSpecs()
	if err != nil {
		return nil, 0, reloadConfig, err
	}
	specs = slices.DeleteFunc(specs, func(s vfs.MountSpec) bool { return slices.Contains(unavailable, s.Name) })
	mounts, mountWarns, err := r.mounts.Reload(specs, vfs.Options{Flatten: c.Defaults.Flatten, Unavailable: unavailable})
	if err != nil {
		return nil, 0, reloadMounts, err
	}
	for _, w := range mountWarns {
		r.log.WarnContext(ctx, "mount unavailable", "err", w)
	}
	var auditFile *os.File
	newAudit := c.Audit.Output != r.c.Audit.Output
	if newAudit {
		if auditFile, err = openAuditFile(c.Audit.Output); err != nil {
			_ = mounts.Close()
			return nil, 0, reloadAuditOutput, err
		}
	}
	if disconnected, err = r.srv.Reload(serverConfig(c, authn, mounts, hostKeys)); err != nil {
		_ = mounts.Close()
		if auditFile != nil {
			_ = auditFile.Close()
		}
		return nil, 0, reloadConfig, err
	}

	if newAudit {
		r.out.use(c.Audit.Output, auditFile)
		r.al.Probe() // a new file may end a failure at once
	}
	r.level.Set(level)
	_ = r.mounts.Close()
	hostKeys.logChanges(ctx, r.log, r.hostKeys)
	r.c, r.mounts, r.keys, r.hostKeys = c, mounts, keys, hostKeys
	r.tables = append(r.tables, mounts)
	select {
	case r.reloaded <- struct{}{}:
	default:
	}
	return restart, disconnected, "", nil
}

// liveMounts returns the mounts of the tables that connections still use;
// r.mu must be held.
func (r *running) liveMounts() []config.LiveMount {
	r.tables = slices.DeleteFunc(r.tables, func(t *vfs.Table) bool { return !t.Live() })
	var live []config.LiveMount
	for _, t := range r.tables {
		for _, m := range t.Mounts() {
			live = append(live, config.LiveMount{Name: m.Name(), Path: m.HostPath(), ReadOnly: m.ReadOnly()})
		}
	}
	return live
}

// keepRestartOnly copies the settings that change only at restart from the
// running configuration cur into next, and returns the keys that differ.
func keepRestartOnly(cur, next *config.Config) []string {
	var changed []string
	keep := func(key string, differ bool, copyOld func()) {
		if differ {
			changed = append(changed, key)
			copyOld()
		}
	}
	keep("server.listen", !slices.Equal(cur.Server.Listen, next.Server.Listen),
		func() { next.Server.Listen = cur.Server.Listen })
	keep("server.host_key_auto_generate", cur.Server.HostKeyAutoGenerate != next.Server.HostKeyAutoGenerate,
		func() { next.Server.HostKeyAutoGenerate = cur.Server.HostKeyAutoGenerate })
	keep("server.crypto_policy", cur.Server.CryptoPolicy != next.Server.CryptoPolicy,
		func() { next.Server.CryptoPolicy = cur.Server.CryptoPolicy })
	keep("log.format", cur.Log.Format != next.Log.Format,
		func() { next.Log.Format = cur.Log.Format })
	keep("audit.events", !slices.Equal(cur.Audit.Events, next.Audit.Events),
		func() { next.Audit.Events = cur.Audit.Events })
	keep("audit.on_error", cur.Audit.OnError != next.Audit.OnError,
		func() { next.Audit.OnError = cur.Audit.OnError })
	return changed
}

// currentHostCerts returns the certificates of the host keys in use.
func (r *running) currentHostCerts() []hostCert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostKeys.certs()
}

// currentMounts returns the current mount table with a reference the
// caller closes, or nil once the server shuts down.
func (r *running) currentMounts() *vfs.Table {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mounts == nil || !r.mounts.Acquire() {
		return nil
	}
	return r.mounts
}

// shutdownTimeout returns the current shutdown_timeout.
func (r *running) shutdownTimeout() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Duration(r.c.Server.ShutdownTimeout)
}

// release closes the reference to the current mount table; reloads after
// it do nothing.
func (r *running) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mounts != nil {
		_ = r.mounts.Close()
		r.mounts = nil
	}
}
