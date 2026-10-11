// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
)

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestServeAdmin: the admin listener serves health, readiness and
// metrics; reloads are counted; metrics.listen changes only at restart;
// /readyz reports stopping during the drain.
func TestServeAdmin(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	alice := newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	base := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
shutdown_timeout = "1m"
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
`
	writeFile(t, path, base+"[metrics]\nlisten = \"127.0.0.1:0\"\n")
	ts := startServe(t, "--config", path)
	m := regexp.MustCompile(`metrics: http://(127\.0\.0\.1:\d+)/metrics`).FindStringSubmatch(ts.stderr.String())
	if m == nil {
		t.Fatalf("no metrics address in the banner:\n%s", ts.stderr.String())
	}
	admin := "http://" + m[1]
	if evs := events(t, ts.stdout.String(), "server.start"); len(evs) != 1 || evs[0]["metrics_listen"] != m[1] {
		t.Errorf("server.start = %v", evs)
	}
	if code, body := get(t, admin+"/readyz"); code != 200 || body != "ready\n" {
		t.Errorf("/readyz = %d %q", code, body)
	}

	held, err := ts.login("alice", alice)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	sc, err := sftp.NewClient(held)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Mkdir("/d"); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := execute(t, "healthcheck", "--address", ts.addr, "--ready"); code != exitOK {
		t.Errorf("healthcheck: %s %s", out, stderr)
	}
	if code, out, stderr := execute(t, "healthcheck", "--url", admin+"/readyz"); code != exitOK {
		t.Errorf("healthcheck --url: %s %s", out, stderr)
	}

	// A reload that changes metrics.listen keeps the running listener.
	writeFile(t, path, base+"[metrics]\nlisten = \"127.0.0.1:1\"\n")
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" || ev["restart_required"] != "metrics.listen" {
		t.Errorf("server.reload = %v", ev)
	}
	// pprof is not in this build: the reload fails, and shows in metrics.
	if !obs.PprofBuilt {
		writeFile(t, path, base+"[metrics]\nlisten = \"127.0.0.1:0\"\npprof = true\n")
		if ev := ts.reload(t, ts.stdout.String); ev["result"] != "error" {
			t.Errorf("server.reload with pprof = %v", ev)
		}
	}
	code, text := get(t, admin+"/metrics")
	if code != 200 {
		t.Fatalf("/metrics = %d", code)
	}
	for _, want := range []string{
		`gosftpd_logins_total{result="success"} 1`,
		`gosftpd_sftp_operations_total{op="mkdir",result="ok"} 1`,
		`gosftpd_config_reloads_total{result="ok"} 1`,
		`gosftpd_connections_active 1`,
		`gosftpd_connections_total{result="no_version"} 1`, // the healthcheck
		"gosftpd_audit_log_failing 0",
		"gosftpd_bans_active 0",
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	if !obs.PprofBuilt && !strings.Contains(text, "gosftpd_config_last_reload_successful 0\n") {
		t.Error("the failed reload does not show")
	}

	// SIGTERM: during the drain the admin listener says stopping.
	ts.cancel()
	ts.cancel = nil
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, body := get(t, admin+"/readyz"); code == 503 && body == "stopping\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never said stopping")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _ := get(t, admin+"/healthz"); code != 200 {
		t.Errorf("/healthz during the drain = %d", code)
	}
	sc.Close()
	held.Close()
	if code := <-ts.done; code != exitOK {
		t.Errorf("exit code %d", code)
	}
	// The admin listener stopped with the server.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, admin+"/healthz", nil)
	if resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req); err == nil {
		resp.Body.Close()
		t.Error("the admin listener still answers after the server stopped")
	}
}

// A metrics.listen that cannot be bound fails the start.
func TestServeAdminBindFails(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "`+filepath.ToSlash(filepath.Join(dir, "data"))+`"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { data = "full" }
[metrics]
listen = "192.0.2.1:9090"
`)
	code, _, stderr := execute(t, "serve", "--allow-root", "--config", path)
	if code != exitFailure || !strings.Contains(stderr, "metrics.listen") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// metric returns the value of one series from the admin listener.
func metric(t *testing.T, admin, series string) (float64, bool) {
	t.Helper()
	_, text := get(t, admin+"/metrics")
	for line := range strings.Lines(text) {
		name, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && name == series {
			f, err := strconv.ParseFloat(v, 64)
			return f, err == nil
		}
	}
	return 0, false
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServeAdminAuditAndMounts: while the audit log fails (fail-closed),
// /readyz says audit_unavailable and the gauge is 1; both recover without
// any client; a mount a reload leaves out shows in metrics.
func TestServeAdminAuditAndMounts(t *testing.T) {
	isolate(t)
	old := auditProbeInterval
	auditProbeInterval = 50 * time.Millisecond
	t.Cleanup(func() { auditProbeInterval = old })
	dir := t.TempDir()
	for _, d := range []string{"data", "extra"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "`+filepath.ToSlash(filepath.Join(dir, "data"))+`"
[mounts.extra]
path = "`+filepath.ToSlash(filepath.Join(dir, "extra"))+`"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { data = "full", extra = "full" }
[metrics]
listen = "127.0.0.1:0"
`)
	ts := startServe(t, "--config", path)
	m := regexp.MustCompile(`metrics: http://(127\.0\.0\.1:\d+)/metrics`).FindStringSubmatch(ts.stderr.String())
	if m == nil {
		t.Fatalf("no metrics address in the banner:\n%s", ts.stderr.String())
	}
	admin := "http://" + m[1]
	if v, ok := metric(t, admin, "gosftpd_mounts_unavailable"); !ok || v != 0 {
		t.Errorf("mounts_unavailable at start = %v, %v", v, ok)
	}

	// A reload leaves out the missing mount; its server.reload event fails
	// to be written.
	if err := os.Remove(filepath.Join(dir, "extra")); err != nil {
		t.Fatal(err)
	}
	ts.stdout.setFail(true)
	ts.hup <- syscall.SIGHUP
	waitUntil(t, "/readyz says audit_unavailable", func() bool {
		code, body := get(t, admin+"/readyz")
		return code == 503 && body == "audit_unavailable\n"
	})
	for series, want := range map[string]float64{
		"gosftpd_audit_log_failing":  1,
		"gosftpd_mounts_unavailable": 1,
	} {
		if v, ok := metric(t, admin, series); !ok || v != want {
			t.Errorf("%s = %v, %v; want %v", series, v, ok, want)
		}
	}
	if v, _ := metric(t, admin, "gosftpd_audit_write_errors_total"); v < 1 {
		t.Errorf("audit_write_errors_total = %v", v)
	}
	if _, ok := silentProbe(t, ts.addr); ok {
		t.Error("a connection was admitted while the audit log fails")
	}

	// The output works again: the server recovers with no client.
	ts.stdout.setFail(false)
	waitUntil(t, "/readyz says ready", func() bool {
		code, _ := get(t, admin+"/readyz")
		return code == 200
	})
	if v, _ := metric(t, admin, "gosftpd_audit_log_failing"); v != 0 {
		t.Errorf("audit_log_failing after recovery = %v", v)
	}
	if v, _ := metric(t, admin, `gosftpd_connections_refused_total{reason="audit_unavailable"}`); v < 1 {
		t.Errorf("refusals for the audit log = %v", v)
	}
	if len(events(t, ts.stdout.String(), "server.audit_recovered")) == 0 {
		t.Error("no server.audit_recovered event")
	}
}

// silentProbe connects without speaking SSH and reports whether the server
// sent its banner (admitted) or closed the connection.
func silentProbe(t *testing.T, addr string) (string, bool) {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	n, _ := c.Read(b)
	return string(b[:n]), strings.HasPrefix(string(b[:n]), "SSH-2.0-")
}

// recoverAudit clears a failure in either mode with no other writes
// (review finding: a fail-open log stayed failing on a quiet server).
func TestRecoverAudit(t *testing.T) {
	t.Parallel()

	for _, failOpen := range []bool{false, true} {
		var out lockedBuffer
		al, err := audit.NewWithOptions(&out, slog.New(slog.DiscardHandler), audit.Options{FailOpen: failOpen})
		if err != nil {
			t.Fatal(err)
		}
		out.setFail(true)
		al.Event("server.start")
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); recoverAudit(ctx, al, 10*time.Millisecond) }()
		time.Sleep(50 * time.Millisecond)
		if !al.Failing() || al.WriteErrors() < 3 {
			t.Errorf("fail-open %v: while failing: failing %v, %d write errors (want a probe per tick)", failOpen, al.Failing(), al.WriteErrors())
		}
		out.setFail(false)
		waitUntil(t, "the audit log recovers", func() bool { return !al.Failing() })
		cancel()
		<-done
		if !strings.Contains(out.String(), "server.audit_recovered") {
			t.Errorf("fail-open %v: no server.audit_recovered", failOpen)
		}
	}
}
