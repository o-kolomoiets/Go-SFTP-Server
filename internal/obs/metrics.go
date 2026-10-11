// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Label values. Every metric has a closed set of them, defined here, so that
// no value comes from a client (ADR 0009).
var (
	// ConnResults are the results of gosftpd_connections_total: those of
	// conn.close, then no_version (the client sent nothing) and
	// handshake_failed (it sent something, but never reached
	// authentication).
	ConnResults    = []string{"ok", "error", "idle_timeout", "keepalive_timeout", "revoked", "no_version", "handshake_failed"}
	RefusedReasons = []string{"banned", "max_connections", "max_connections_per_ip", "max_preauth_connections", "audit_unavailable"}
	AuthMethods    = []string{"publickey", "password", "other"}
	Ops            = []string{"upload", "download", "rename", "mkdir", "rmdir", "remove", "setstat", "list", "stat", "other"}
	OpResults      = []string{"ok", "denied", "not_found", "error", "aborted"}
	Directions     = []string{"upload", "download"}
	ConflictOps    = []string{"upload", "rename"}
	Conflicts      = []string{"renamed", "overwritten", "versioned", "rejected"}

	successFailure = []string{"success", "failure"}
	okError        = []string{"ok", "error"}
)

// TransferBuckets are the bounds of gosftpd_transfer_duration_seconds.
var TransferBuckets = []float64{0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 1800, 7200}

// Sources are values owned by other packages, read at each scrape.
type Sources struct {
	BansActive       func() int    // sources banned now; 0 with bans off
	AuditWriteErrors func() uint64 // failed writes to the audit output
	AuditFailing     func() bool   // writes to the audit output fail now
}

// Metrics are the metrics of a gosftpd process. Every method does nothing
// on a nil *Metrics, so code runs the same without the admin listener.
type Metrics struct {
	reg Registry

	connsActive  *Gauge
	conns        *CounterVec
	refused      *CounterVec
	logins       *CounterVec
	authAttempts *CounterVec
	ops          *CounterVec
	bytes        *CounterVec
	durations    *HistogramVec
	conflicts    *CounterVec
	bans         *Counter
	mountsDown   *Gauge
	reloads      *CounterVec
	reloadOK     *Gauge
	reloadTime   *Gauge

	sources atomic.Pointer[Sources]
}

// NewMetrics returns the metrics of this process; version is gosftpd's.
// The time of the last successful reload starts as now (the start).
func NewMetrics(version string) *Metrics {
	m := &Metrics{}
	r := &m.reg
	newInfo(r, "gosftpd_build_info", "gosftpd version and the Go version it was built with.",
		map[string]string{"version": version, "goversion": runtime.Version()})
	m.connsActive = newGauge(r, "gosftpd_connections_active", "Admitted connections being served, before and after login.")
	m.conns = newCounterVec(r, "gosftpd_connections_total", "Admitted connections that ended, by result.",
		Label{"result", ConnResults})
	m.refused = newCounterVec(r, "gosftpd_connections_refused_total", "Connections refused before the SSH handshake, by reason.",
		Label{"reason", RefusedReasons})
	m.logins = newCounterVec(r, "gosftpd_logins_total", "Connections that reached authentication, by result (auth.success or auth.failure).",
		Label{"result", successFailure})
	m.authAttempts = newCounterVec(r, "gosftpd_auth_attempts_total", "Authentication requests other than none, by method and result.",
		Label{"method", AuthMethods}, Label{"result", successFailure})
	m.ops = newCounterVec(r, "gosftpd_sftp_operations_total", "SFTP operations, by operation and result; a transfer counts when it is closed.",
		Label{"op", Ops}, Label{"result", OpResults})
	m.bytes = newCounterVec(r, "gosftpd_transfer_bytes_total", "Bytes uploaded and downloaded, counted as they are transferred.",
		Label{"direction", Directions})
	m.durations = newHistogramVec(r, "gosftpd_transfer_duration_seconds", "Time from open to close of uploads and downloads.",
		TransferBuckets, Label{"direction", Directions})
	m.conflicts = newCounterVec(r, "gosftpd_conflicts_total", "Uploads and posix-renames onto an existing name, by the outcome of the conflict policy.",
		Label{"op", ConflictOps}, Label{"conflict", Conflicts})
	m.bans = newCounter(r, "gosftpd_bans_total", "Sources banned after repeated login failures.")
	m.mountsDown = newGauge(r, "gosftpd_mounts_unavailable", "Mounts left out by the last reload because their directory cannot be used.")
	m.reloads = newCounterVec(r, "gosftpd_config_reloads_total", "Configuration reloads, by result.",
		Label{"result", okError})
	m.reloadOK = newGauge(r, "gosftpd_config_last_reload_successful", "Whether the last configuration reload succeeded (1 at start).")
	m.reloadTime = newGauge(r, "gosftpd_config_last_reload_success_timestamp_seconds", "Time of the start or of the last successful configuration reload.")
	m.reloadOK.Set(1)
	m.reloadTime.Set(unixSeconds(time.Now()))

	newFunc(r, typeGauge, "gosftpd_bans_active", "Sources banned now.", func() (float64, bool) {
		if s := m.sources.Load(); s != nil && s.BansActive != nil {
			return float64(s.BansActive()), true
		}
		return 0, false
	})
	newFunc(r, typeCounter, "gosftpd_audit_write_errors_total", "Failed writes to the audit output, recovery probes included.", func() (float64, bool) {
		if s := m.sources.Load(); s != nil && s.AuditWriteErrors != nil {
			return float64(s.AuditWriteErrors()), true
		}
		return 0, false
	})
	newFunc(r, typeGauge, "gosftpd_audit_log_failing", "1 while writes to the audit output fail, else 0.", func() (float64, bool) {
		if s := m.sources.Load(); s != nil && s.AuditFailing != nil {
			return boolFloat(s.AuditFailing()), true
		}
		return 0, false
	})
	registerRuntime(r)
	return m
}

// Registry returns the registry that holds the metrics.
func (m *Metrics) Registry() *Registry { return &m.reg }

// SetSources sets the values read at each scrape.
func (m *Metrics) SetSources(s Sources) {
	if m != nil {
		m.sources.Store(&s)
	}
}

// ConnectionStarted counts an admitted connection as active.
func (m *Metrics) ConnectionStarted() {
	if m != nil {
		m.connsActive.Add(1)
	}
}

// ConnectionEnded counts the end of an admitted connection with one of
// ConnResults.
func (m *Metrics) ConnectionEnded(result string) {
	if m != nil {
		m.connsActive.Add(-1)
		m.conns.Add(1, result)
	}
}

// ConnectionRefused counts a connection refused before the handshake, for
// one of RefusedReasons.
func (m *Metrics) ConnectionRefused(reason string) {
	if m != nil {
		m.refused.Add(1, reason)
	}
}

// Login counts a connection's authentication result.
func (m *Metrics) Login(success bool) {
	if m != nil {
		m.logins.Add(1, successOrFailure(success))
	}
}

// AuthAttempt counts an authentication request as x/crypto reports it;
// method is the SSH method name.
func (m *Metrics) AuthAttempt(method string, success bool) {
	if m == nil {
		return
	}
	switch method {
	case "publickey", "password":
	default:
		method = "other"
	}
	m.authAttempts.Add(1, method, successOrFailure(success))
}

// Operation counts an SFTP operation by its audit event name ("fs.upload")
// and result (one of OpResults).
func (m *Metrics) Operation(event, result string) {
	if m != nil {
		m.ops.Add(1, opOf(event), result)
	}
}

// opOf maps an audit event name to an operation of Ops.
func opOf(event string) string {
	op, ok := strings.CutPrefix(event, "fs.")
	if !ok {
		return "other"
	}
	switch op {
	case "upload", "download", "rename", "mkdir", "rmdir", "remove", "setstat", "list", "stat":
		return op
	}
	return "other"
}

// Transferred counts bytes of an upload or a download.
func (m *Metrics) Transferred(upload bool, n int) {
	if m != nil && n > 0 {
		m.bytes.Add(uint64(n), direction(upload))
	}
}

// TransferClosed records the time from open to close of a transfer.
func (m *Metrics) TransferClosed(upload bool, d time.Duration) {
	if m != nil {
		m.durations.Observe(d.Seconds(), direction(upload))
	}
}

// Conflict counts the outcome of the conflict policy for an upload or a
// posix-rename (event "fs.upload" or "fs.rename"): one of Conflicts;
// "none" and "" are not conflicts.
func (m *Metrics) Conflict(event, conflict string) {
	if m != nil {
		m.conflicts.Add(1, conflict, opOf(event))
	}
}

// Banned counts a ban.
func (m *Metrics) Banned() {
	if m != nil {
		m.bans.Inc()
	}
}

// Reloaded counts a configuration reload.
func (m *Metrics) Reloaded(ok bool, now time.Time) {
	if m == nil {
		return
	}
	if ok {
		m.reloads.Add(1, "ok")
		m.reloadOK.Set(1)
		m.reloadTime.Set(unixSeconds(now))
		return
	}
	m.reloads.Add(1, "error")
	m.reloadOK.Set(0)
}

// SetMountsUnavailable sets how many mounts the last reload left out.
func (m *Metrics) SetMountsUnavailable(n int) {
	if m != nil {
		m.mountsDown.Set(float64(n))
	}
}

func successOrFailure(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

func direction(upload bool) string {
	if upload {
		return "upload"
	}
	return "download"
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// Value returns the value of one series as written, such as
// `gosftpd_connections_total{result="ok"}`, for tests and diagnostics.
func (m *Metrics) Value(series string) (float64, bool) {
	var b strings.Builder
	_, _ = m.reg.WriteTo(&b)
	for line := range strings.Lines(b.String()) {
		name, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		if ok && name == series {
			f, err := strconv.ParseFloat(v, 64)
			return f, err == nil
		}
	}
	return 0, false
}
