// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
)

// adminListener is the bound admin listener (ADR 0009).
type adminListener struct {
	ln    net.Listener
	admin *obs.Admin
	log   *slog.Logger
	done  chan struct{} // closed when Serve returned; nil before start
}

// listenAdmin binds metrics.listen. On a loopback address, requests must
// name a loopback host (DNS rebinding).
func listenAdmin(ctx context.Context, addr string, m *obs.Metrics, h *obs.Health, pprof *atomic.Bool, log *slog.Logger) (*adminListener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics.listen: %w", err)
	}
	tcp, _ := ln.Addr().(*net.TCPAddr)
	loopback := tcp != nil && tcp.IP.IsLoopback()
	// Validate warned about addresses; a host name is known only now.
	if host, _, _ := net.SplitHostPort(addr); !loopback && !config.NonLoopback(host) {
		log.WarnContext(ctx, "configuration", "detail", fmt.Sprintf("metrics.listen: %q is not a loopback address (%s): %s", addr, ln.Addr(), config.NotLoopbackRisk))
	}
	admin := obs.NewAdmin(obs.AdminOptions{Metrics: m, Health: h, CheckHost: loopback, Pprof: pprof, Log: log})
	return &adminListener{ln: ln, admin: admin, log: log}, nil
}

func (a *adminListener) addr() string { return a.ln.Addr().String() }

// start serves in the background; an error is logged and does not stop
// the SFTP server.
func (a *adminListener) start() {
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		if err := a.admin.Serve(a.ln); err != nil {
			a.log.Error("admin listener failed; the SFTP server keeps running", "err", err)
		}
	}()
}

// stop lets requests in progress finish for up to a second, then closes
// the listener and every connection.
func (a *adminListener) stop(ctx context.Context) {
	if a.done == nil {
		_ = a.ln.Close()
		return
	}
	a.admin.Shutdown(context.WithoutCancel(ctx))
	<-a.done
}

// auditProbeInterval is how often recoverAudit checks the audit log (a
// variable for tests).
var auditProbeInterval = 5 * time.Second

// recoverAudit retries a failing audit log every interval until ctx is
// done, so that the server recovers, /readyz turns ready again and
// gosftpd_audit_log_failing returns to 0, also in fail-open mode, without
// waiting for a client.
func recoverAudit(ctx context.Context, al *audit.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if al.Failing() {
			al.Recover()
		}
	}
}
