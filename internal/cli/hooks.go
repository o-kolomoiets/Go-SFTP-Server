// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
)

// buildHooks returns the hooks of c (ADR 0010). At start (running nil) a
// problem with a hook's files is an error. On reload a hook whose argv
// files fail their checks is left out, since they are run as they are at
// each run; one whose secret cannot be used keeps its running secret,
// which is held in memory. Each gives a warning and counts in stale, so
// that a broken hook file never blocks the rest of a reload.
func buildHooks(c *config.Config, running map[string]hooks.Spec) (specs []hooks.Spec, warns []string, stale int, err error) {
	var errs []error
	for _, h := range c.Hooks {
		if h == nil {
			continue
		}
		secret, argvErr, secretErr := config.HookFiles(h)
		if running == nil {
			if e := errors.Join(argvErr, secretErr); e != nil {
				errs = append(errs, fmt.Errorf("hook %q: %w", h.Name, e))
				continue
			}
			specs = append(specs, c.HookSpec(h, secret))
			continue
		}
		if argvErr != nil {
			warns = append(warns, fmt.Sprintf("hook %q is left out until its program is fixed: %v", h.Name, argvErr))
			stale++
			continue
		}
		if secretErr != nil {
			prev, ok := running[h.Name]
			if !ok || prev.Webhook == nil {
				warns = append(warns, fmt.Sprintf("hook %q is left out until its secret is fixed: %v", h.Name, secretErr))
				stale++
				continue
			}
			warns = append(warns, fmt.Sprintf("hook %q keeps its running secret: %v", h.Name, secretErr))
			secret = prev.Webhook.Secret
			stale++
		}
		specs = append(specs, c.HookSpec(h, secret))
	}
	return specs, warns, stale, errors.Join(errs...)
}

// specsByName indexes hooks for the next reload.
func specsByName(specs []hooks.Spec) map[string]hooks.Spec {
	m := make(map[string]hooks.Spec, len(specs))
	for _, s := range specs {
		m[s.Name] = s
	}
	return m
}

// warnOrphans warns that a PID 1 does not reap what exec hooks leave.
func warnOrphans(ctx context.Context, log *slog.Logger, specs []hooks.Spec) {
	if os.Getpid() == 1 && slices.ContainsFunc(specs, func(s hooks.Spec) bool { return s.Exec != nil }) {
		log.WarnContext(ctx, "gosftpd runs as PID 1 with exec hooks: processes they leave are not reaped; run the container with an init (docker run --init)")
	}
}
