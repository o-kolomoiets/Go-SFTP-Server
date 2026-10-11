// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) map[string]*parsedFamily {
	t.Helper()
	return parseExposition(t, write(t, m.Registry()))
}

// The families of ADR 0009, with their types; process metrics that a
// platform cannot read are left out.
var wantFamilies = map[string]string{
	"gosftpd_build_info":                                   "gauge",
	"gosftpd_connections_active":                           "gauge",
	"gosftpd_connections_total":                            "counter",
	"gosftpd_connections_refused_total":                    "counter",
	"gosftpd_logins_total":                                 "counter",
	"gosftpd_auth_attempts_total":                          "counter",
	"gosftpd_sftp_operations_total":                        "counter",
	"gosftpd_transfer_bytes_total":                         "counter",
	"gosftpd_transfer_duration_seconds":                    "histogram",
	"gosftpd_conflicts_total":                              "counter",
	"gosftpd_bans_active":                                  "gauge",
	"gosftpd_bans_total":                                   "counter",
	"gosftpd_mounts_unavailable":                           "gauge",
	"gosftpd_config_reloads_total":                         "counter",
	"gosftpd_config_last_reload_successful":                "gauge",
	"gosftpd_config_last_reload_success_timestamp_seconds": "gauge",
	"gosftpd_audit_write_errors_total":                     "counter",
	"gosftpd_audit_log_failing":                            "gauge",
	"gosftpd_hook_deliveries_total":                        "counter",
	"gosftpd_hook_retries_total":                           "counter",
	"gosftpd_hook_queue_length":                            "gauge",
	"gosftpd_hooks_not_updated":                            "gauge",
	"go_info":                                              "gauge",
	"go_goroutines":                                        "gauge",
	"go_threads":                                           "gauge",
	"go_memstats_heap_alloc_bytes":                         "gauge",
	"go_memstats_sys_bytes":                                "gauge",
	"go_gc_duration_seconds":                               "summary",
	"process_start_time_seconds":                           "gauge",
}

func newTestMetrics() *Metrics {
	m := NewMetrics("v1.2.3")
	m.SetSources(Sources{
		BansActive:       func() int { return 2 },
		AuditWriteErrors: func() uint64 { return 5 },
		AuditFailing:     func() bool { return true },
		HookQueueLength:  func() int { return 7 },
	})
	return m
}

func TestMetricsFamilies(t *testing.T) {
	t.Parallel()

	fams := scrape(t, newTestMetrics())
	for name, typ := range wantFamilies {
		f := fams[name]
		if f == nil {
			t.Errorf("%s missing", name)
			continue
		}
		if f.typ != typ {
			t.Errorf("%s is a %s, want %s", name, f.typ, typ)
		}
	}
	if runtime.GOOS == "linux" {
		for _, name := range []string{"process_cpu_seconds_total", "process_max_fds", "process_resident_memory_bytes", "process_virtual_memory_bytes", "process_open_fds"} {
			if fams[name] == nil {
				t.Errorf("%s missing on Linux", name)
			}
		}
	}
	for name, f := range fams {
		checkName(t, name, f)
	}
	// Every combination of label values exists from the start.
	for name, n := range map[string]int{
		"gosftpd_connections_total":         len(ConnResults),
		"gosftpd_connections_refused_total": len(RefusedReasons),
		"gosftpd_logins_total":              2,
		"gosftpd_auth_attempts_total":       len(AuthMethods) * 2,
		"gosftpd_sftp_operations_total":     len(Ops) * len(OpResults),
		"gosftpd_transfer_bytes_total":      len(Directions),
		"gosftpd_transfer_duration_seconds": len(Directions) * (len(TransferBuckets) + 3),
		"gosftpd_conflicts_total":           len(ConflictOps) * len(Conflicts),
		"gosftpd_config_reloads_total":      2,
		"gosftpd_hook_deliveries_total":     len(HookKinds) * len(HookResults),
	} {
		if got := len(fams[name].samples); got != n {
			t.Errorf("%s has %d lines, want %d", name, got, n)
		}
		for _, s := range fams[name].samples {
			if s.value != 0 {
				t.Errorf("%s = %v at start", s.series(), s.value)
			}
		}
	}
	build := fams["gosftpd_build_info"].samples[0]
	if build.labels["version"] != "v1.2.3" || build.labels["goversion"] != runtime.Version() || build.value != 1 {
		t.Errorf("build_info: %v", build)
	}
	for name, want := range map[string]float64{"gosftpd_bans_active": 2, "gosftpd_audit_write_errors_total": 5, "gosftpd_audit_log_failing": 1, "gosftpd_config_last_reload_successful": 1, "gosftpd_hook_queue_length": 7} {
		if got := fams[name].samples[0].value; got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if ts := fams["gosftpd_config_last_reload_success_timestamp_seconds"].samples[0].value; time.Since(time.Unix(int64(ts), 0)) > time.Minute {
		t.Errorf("last reload timestamp %v is not the start", ts)
	}
	gc := fams["go_gc_duration_seconds"].samples
	if len(gc) != 7 || gc[0].labels["quantile"] != "0" || gc[4].labels["quantile"] != "1" {
		t.Errorf("go_gc_duration_seconds: %v", gc)
	}
}

// checkName applies the naming rules that promlinter would: a prefix,
// _total on counters only, base units.
func checkName(t *testing.T, name string, f *parsedFamily) {
	t.Helper()
	if !strings.HasPrefix(name, "gosftpd_") && !strings.HasPrefix(name, "go_") && !strings.HasPrefix(name, "process_") {
		t.Errorf("%s: no gosftpd_, go_ or process_ prefix", name)
	}
	if (f.typ == "counter") != strings.HasSuffix(name, "_total") {
		t.Errorf("%s: a %s must end in _total exactly when it is a counter", name, f.typ)
	}
	base := strings.TrimSuffix(name, "_total")
	for _, unit := range []string{"milliseconds", "microseconds", "kilobytes", "megabytes", "minutes", "hours"} {
		if strings.Contains(base, unit) {
			t.Errorf("%s: not a base unit", name)
		}
	}
	if (f.typ == "histogram" || f.typ == "summary" || strings.Contains(base, "duration") || strings.Contains(base, "timestamp")) && !strings.HasSuffix(base, "_seconds") {
		t.Errorf("%s: a time must be in _seconds", name)
	}
	if strings.Contains(base, "bytes") && !strings.HasSuffix(base, "_bytes") {
		t.Errorf("%s: bytes must be the unit suffix", name)
	}
	if f.help == "" || !strings.HasSuffix(f.help, ".") {
		t.Errorf("%s: HELP %q is empty or no sentence", name, f.help)
	}
	for _, s := range f.samples {
		for k, v := range s.labels {
			if k == "le" || k == "quantile" {
				continue
			}
			if v == "" || strings.ContainsAny(v, "/@ ") && k != "version" && k != "goversion" {
				t.Errorf("%s: label %s=%q does not look like a closed set value", s.series(), k, v)
			}
		}
	}
}

func TestMetricsMethods(t *testing.T) {
	t.Parallel()

	m := newTestMetrics()
	m.ConnectionStarted()
	m.ConnectionStarted()
	m.ConnectionEnded("no_version")
	m.ConnectionEnded("bogus") // outside the set: dropped, but no longer active
	m.ConnectionRefused("banned")
	m.Login(true)
	m.Login(false)
	m.AuthAttempt("publickey", false)
	m.AuthAttempt("keyboard-interactive", false)
	m.AuthAttempt("password", true)
	m.Operation("fs.upload", "aborted")
	m.Operation("fs.statvfs", "ok")
	m.Operation("fs.stat", "ok")
	m.Operation("session.start", "ok")
	m.Transferred(true, 100)
	m.Transferred(false, 7)
	m.Transferred(false, 0)
	m.TransferClosed(true, 2*time.Second)
	m.Conflict("fs.upload", "renamed")
	m.Conflict("fs.rename", "rejected")
	m.Conflict("fs.upload", "none")
	m.Banned()
	m.Reloaded(false, time.Unix(1, 0))
	m.SetMountsUnavailable(3)

	for series, want := range map[string]float64{
		`gosftpd_connections_active`:                                          0,
		`gosftpd_connections_total{result="no_version"}`:                      1,
		`gosftpd_connections_refused_total{reason="banned"}`:                  1,
		`gosftpd_logins_total{result="success"}`:                              1,
		`gosftpd_logins_total{result="failure"}`:                              1,
		`gosftpd_auth_attempts_total{method="publickey",result="failure"}`:    1,
		`gosftpd_auth_attempts_total{method="other",result="failure"}`:        1,
		`gosftpd_auth_attempts_total{method="password",result="success"}`:     1,
		`gosftpd_sftp_operations_total{op="upload",result="aborted"}`:         1,
		`gosftpd_sftp_operations_total{op="other",result="ok"}`:               2,
		`gosftpd_sftp_operations_total{op="stat",result="ok"}`:                1,
		`gosftpd_transfer_bytes_total{direction="upload"}`:                    100,
		`gosftpd_transfer_bytes_total{direction="download"}`:                  7,
		`gosftpd_transfer_duration_seconds_count{direction="upload"}`:         1,
		`gosftpd_transfer_duration_seconds_bucket{direction="upload",le="1"}`: 0,
		`gosftpd_transfer_duration_seconds_bucket{direction="upload",le="5"}`: 1,
		`gosftpd_conflicts_total{conflict="renamed",op="upload"}`:             1,
		`gosftpd_conflicts_total{conflict="rejected",op="rename"}`:            1,
		`gosftpd_bans_total`:                           1,
		`gosftpd_config_reloads_total{result="error"}`: 1,
		`gosftpd_config_last_reload_successful`:        0,
		`gosftpd_mounts_unavailable`:                   3,
	} {
		if got, ok := m.Value(series); !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", series, got, ok, want)
		}
	}
	m.Reloaded(true, time.Unix(1700000000, 500000000))
	if v, _ := m.Value("gosftpd_config_last_reload_success_timestamp_seconds"); v != 1700000000.5 {
		t.Errorf("timestamp = %v", v)
	}
	if v, _ := m.Value("gosftpd_config_last_reload_successful"); v != 1 {
		t.Errorf("last reload successful = %v", v)
	}
	scrape(t, m)
}

// A nil *Metrics does nothing, so that servers without the admin listener
// need no checks.
func TestNilMetrics(t *testing.T) {
	t.Parallel()

	var m *Metrics
	m.SetSources(Sources{})
	m.ConnectionStarted()
	m.ConnectionEnded("ok")
	m.ConnectionRefused("banned")
	m.Login(true)
	m.AuthAttempt("password", false)
	m.Operation("fs.upload", "ok")
	m.Transferred(true, 1)
	m.TransferClosed(true, time.Second)
	m.Conflict("fs.upload", "renamed")
	m.Banned()
	m.Reloaded(true, time.Now())
	m.SetMountsUnavailable(1)
	m.HookDelivery("exec", "ok")
	m.HookRetry()
	m.SetHooksNotUpdated(1)
}

// Without sources the values owned elsewhere are left out, not 0.
func TestMetricsWithoutSources(t *testing.T) {
	t.Parallel()

	fams := scrape(t, NewMetrics("dev"))
	for _, name := range []string{"gosftpd_bans_active", "gosftpd_audit_write_errors_total", "gosftpd_audit_log_failing", "gosftpd_hook_queue_length"} {
		if fams[name] != nil {
			t.Errorf("%s written without a source", name)
		}
	}
}

func TestOpOf(t *testing.T) {
	t.Parallel()

	for _, op := range Ops {
		if op == "other" {
			continue
		}
		if got := opOf("fs." + op); got != op {
			t.Errorf("opOf(fs.%s) = %s", op, got)
		}
	}
	for _, e := range []string{"fs.symlink", "fs.link", "fs.readlink", "fs.statvfs", "fs.denied", "conn.close", "upload"} {
		if got := opOf(e); got != "other" {
			t.Errorf("opOf(%s) = %s, want other", e, got)
		}
	}
	if !slices.Contains(Ops, "other") {
		t.Error("Ops has no other")
	}
}
