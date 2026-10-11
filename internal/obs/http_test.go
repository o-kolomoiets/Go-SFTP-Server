// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func request(t *testing.T, h http.Handler, method, target string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			req.Host = header[i+1]
			continue
		}
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestHealthAndReadiness(t *testing.T) {
	t.Parallel()

	var audit atomic.Bool
	audit.Store(true)
	health := NewHealth(audit.Load)
	h := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: health}).Handler()

	check := func(path string, code int, body string) {
		t.Helper()
		w := request(t, h, http.MethodGet, path)
		if w.Code != code || w.Body.String() != body+"\n" {
			t.Errorf("GET %s = %d %q, want %d %q", path, w.Code, w.Body.String(), code, body)
		}
	}
	check("/healthz", 200, "ok")
	check("/readyz", 503, "starting")
	health.SetReady()
	check("/readyz", 200, "ready")
	audit.Store(false)
	check("/readyz", 503, "audit_unavailable")
	check("/healthz", 200, "ok")
	audit.Store(true)
	health.SetStopping()
	check("/readyz", 503, "stopping")
	health.SetReady() // stopping is for good
	check("/readyz", 503, "stopping")
	check("/healthz", 200, "ok")
}

func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()

	m := NewMetrics("dev")
	m.Login(true)
	h := NewAdmin(AdminOptions{Metrics: m, Health: NewHealth(nil)}).Handler()

	// Whatever the client asks for, it gets the text format, never 406.
	for _, accept := range []string{"", "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited", "application/openmetrics-text; version=1.0.0", "text/html"} {
		w := request(t, h, http.MethodGet, "/metrics", "Accept", accept)
		if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
			t.Fatalf("Accept %q: %d %q", accept, w.Code, w.Header().Get("Content-Type"))
		}
		fams := parseExposition(t, w.Body.String())
		if fams["gosftpd_logins_total"] == nil {
			t.Fatal("no gosftpd metrics")
		}
	}
	w := request(t, h, http.MethodHead, "/metrics")
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Type") == "" {
		t.Errorf("HEAD /metrics = %d, %d bytes, %q", w.Code, w.Body.Len(), w.Header().Get("Content-Type"))
	}
}

func TestAdminRoutes(t *testing.T) {
	t.Parallel()

	h := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil)}).Handler()
	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			w := request(t, h, method, path)
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s = %d, Allow %q", method, path, w.Code, w.Header().Get("Allow"))
			}
		}
		// The server drops the body of a HEAD response; the recorder does not.
		if w := request(t, h, http.MethodHead, path); w.Code == http.StatusMethodNotAllowed {
			t.Errorf("HEAD %s = %d", path, w.Code)
		}
	}
	for _, path := range []string{"/", "/metricsx", "/debug/pprof/", "/debug/pprof/cmdline", "/healthz/x"} {
		if PprofBuilt && strings.HasPrefix(path, "/debug/pprof/") {
			continue // pprof_test.go
		}
		if w := request(t, h, http.MethodGet, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, w.Code)
		}
	}
}

// On a loopback listener, a request must name a loopback host: a web page
// cannot reach it through DNS rebinding.
func TestAdminHostCheck(t *testing.T) {
	t.Parallel()

	h := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil), CheckHost: true}).Handler()
	for host, ok := range map[string]bool{
		"127.0.0.1:9090": true, "127.0.0.1": true, "[::1]:9090": true, "::1": true,
		"localhost:9090": true, "LOCALHOST": true, "127.1.2.3:80": true,
		"rebind.example:9090": false, "attacker.example": false, "10.0.0.1:9090": false,
		"localhost.attacker.example": false, "": false,
	} {
		w := request(t, h, http.MethodGet, "/healthz", "Host", host)
		if got := w.Code == 200; got != ok {
			t.Errorf("Host %q: %d", host, w.Code)
		}
		if !ok && w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", host, w.Code)
		}
	}
	open := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil)}).Handler()
	if w := request(t, open, http.MethodGet, "/healthz", "Host", "gosftpd.internal:9090"); w.Code != 200 {
		t.Errorf("without CheckHost: %d", w.Code)
	}
}

// /metrics and pprof take at most 4 slots; when they are taken a request
// gets 503 at once; health checks are never limited.
func TestAdminBusy(t *testing.T) {
	t.Parallel()

	a := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil)})
	h := a.Handler()
	for range adminMaxScrapes {
		a.scrapes <- struct{}{}
	}
	w := request(t, h, http.MethodGet, "/metrics")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Errorf("full: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := request(t, h, http.MethodGet, "/healthz"); w.Code != 200 {
		t.Errorf("/healthz while busy: %d", w.Code)
	}
	<-a.scrapes
	if w := request(t, h, http.MethodGet, "/metrics"); w.Code != 200 {
		t.Errorf("after a slot freed: %d", w.Code)
	}
}

func TestLimitListener(t *testing.T) {
	t.Parallel()

	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 2)
	defer ln.Close()
	var d net.Dialer
	for range 3 {
		c, err := d.DialContext(t.Context(), "tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	a, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	third := make(chan net.Conn)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(third)
			return
		}
		third <- c
	}()
	select {
	case <-third:
		t.Fatal("a third connection was accepted while two are open")
	case <-time.After(100 * time.Millisecond):
	}
	_ = a.Close()
	_ = a.Close() // releases once
	c := <-third
	if c == nil {
		t.Fatal("accept failed")
	}
	_ = b.Close()
	_ = c.Close()
	if len(ln.sem) != 0 {
		t.Errorf("%d slots still taken", len(ln.sem))
	}
}

// Serve answers until Shutdown, which returns with no goroutine left
// (TestMain checks).
func TestAdminServe(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	health := NewHealth(nil)
	health.SetReady()
	a := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: health, CheckHost: true})
	served := make(chan error, 1)
	go func() { served <- a.Serve(ln) }()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/readyz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ready\n" {
		t.Errorf("GET /readyz = %d %q", resp.StatusCode, body)
	}
	// An idle client connection does not hold up Shutdown.
	var d net.Dialer
	idle, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	start := time.Now()
	a.Shutdown(context.Background())
	if err := <-served; err != nil {
		t.Errorf("Serve returned %v after Shutdown", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Shutdown took %v", d)
	}
	client.CloseIdleConnections()
}

// With every connection slot taken by idle keep-alive connections, Shutdown
// still returns after its second: Accept waiting for a slot ends when the
// listener closes (review finding: SIGTERM stalled for the idle timeout).
func TestAdminShutdownWithAllSlotsTaken(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := NewAdmin(AdminOptions{Metrics: NewMetrics("dev"), Health: NewHealth(nil)})
	served := make(chan error, 1)
	go func() { served <- a.Serve(ln) }()
	var d net.Dialer
	conns := make([]net.Conn, 0, adminMaxConns)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	buf := make([]byte, 512)
	for range adminMaxConns {
		c, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		if _, err := c.Write([]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(buf); err != nil || !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
			t.Fatalf("GET /healthz: %q, %v", buf[:n], err)
		}
	}
	// One more waits in the backlog; Accept waits for a slot.
	extra, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	a.Shutdown(context.Background())
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve() = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Shutdown took %v with every slot taken", d)
	}
}
