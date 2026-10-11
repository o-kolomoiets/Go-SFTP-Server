// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

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
