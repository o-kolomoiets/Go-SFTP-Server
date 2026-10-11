// SPDX-License-Identifier: Apache-2.0

//go:build pprof

package obs

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPprof(t *testing.T) {
	t.Parallel()

	var on atomic.Bool
	var logs bytes.Buffer
	a := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil), Pprof: &on, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	h := a.Handler()
	if w := request(t, h, http.MethodGet, "/debug/pprof/"); w.Code != http.StatusNotFound {
		t.Errorf("pprof off: %d", w.Code)
	}
	on.Store(true) // a reload turns it on
	if w := request(t, h, http.MethodGet, "/debug/pprof/"); w.Code != 200 || !strings.Contains(w.Body.String(), "goroutine") {
		t.Errorf("index: %d", w.Code)
	}
	if w := request(t, h, http.MethodGet, "/debug/pprof/goroutine?debug=1"); w.Code != 200 {
		t.Errorf("goroutine profile: %d", w.Code)
	}
	// The command line holds host paths.
	if w := request(t, h, http.MethodGet, "/debug/pprof/cmdline"); w.Code != http.StatusNotFound {
		t.Errorf("cmdline: %d", w.Code)
	}
	for _, path := range []string{"/debug/pprof/profile?seconds=61", "/debug/pprof/trace?seconds=600", "/debug/pprof/heap?seconds=61"} {
		if w := request(t, h, http.MethodGet, path); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", path, w.Code)
		}
	}
	if w := request(t, h, http.MethodPost, "/debug/pprof/symbol"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST symbol: %d", w.Code)
	}
	// Two profiles at a time.
	for range adminMaxProfiles {
		a.profiles <- struct{}{}
	}
	if w := request(t, h, http.MethodGet, "/debug/pprof/heap"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("third profile: %d", w.Code)
	}
	<-a.profiles
	<-a.profiles
	if !strings.Contains(logs.String(), "pprof request") {
		t.Errorf("pprof requests not logged: %s", logs.String())
	}
}
