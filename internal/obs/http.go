// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Readiness tokens of /readyz.
const (
	NotReadyStarting = "starting"
	NotReadyStopping = "stopping"
	NotReadyAudit    = "audit_unavailable"
)

// Health is the state /healthz and /readyz report.
type Health struct {
	state          atomic.Int32 // 0 starting, 1 ready, 2 stopping
	auditAvailable func() bool
}

// NewHealth returns a Health that is starting. auditAvailable reports
// whether the audit log lets the server accept connections; nil means
// always.
func NewHealth(auditAvailable func() bool) *Health {
	return &Health{auditAvailable: auditAvailable}
}

// SetReady marks the server ready: its SSH listeners accept.
func (h *Health) SetReady() { h.state.CompareAndSwap(0, 1) }

// SetStopping marks the server stopping, for good.
func (h *Health) SetStopping() { h.state.Store(2) }

// Ready reports whether the server takes new connections, and otherwise
// why not: one of the NotReady tokens.
func (h *Health) Ready() (bool, string) {
	switch h.state.Load() {
	case 0:
		return false, NotReadyStarting
	case 2:
		return false, NotReadyStopping
	}
	if h.auditAvailable != nil && !h.auditAvailable() {
		return false, NotReadyAudit
	}
	return true, ""
}

// Limits of the admin server (ADR 0009).
const (
	adminMaxConns       = 64
	adminMaxScrapes     = 4 // /metrics and pprof together
	adminMaxProfiles    = 2 // pprof
	adminMaxProfileSecs = 60
	adminHeaderBytes    = 8 << 10
	adminShutdownWait   = time.Second
)

// AdminOptions configure the admin server.
type AdminOptions struct {
	Metrics *Metrics
	Health  *Health
	// CheckHost answers 421 to a request whose Host is not a loopback
	// address or localhost, so that a web page cannot reach a loopback
	// listener through DNS rebinding. Set it when the listener is on
	// loopback.
	CheckHost bool
	// Pprof turns /debug/pprof on and off; it has an effect only in
	// binaries built with -tags pprof (PprofBuilt).
	Pprof *atomic.Bool
	Log   *slog.Logger
}

// Admin is the HTTP admin server: /healthz, /readyz, /metrics and, if
// built in and turned on, /debug/pprof.
type Admin struct {
	o        AdminOptions
	srv      *http.Server
	scrapes  chan struct{}
	profiles chan struct{}
}

// NewAdmin returns an admin server.
func NewAdmin(o AdminOptions) *Admin {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Pprof == nil {
		o.Pprof = new(atomic.Bool)
	}
	a := &Admin{
		o:        o,
		scrapes:  make(chan struct{}, adminMaxScrapes),
		profiles: make(chan struct{}, adminMaxProfiles),
	}
	a.srv = &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// net/http/pprof extends its own deadline for profiles.
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: adminHeaderBytes,
		ErrorLog:       slog.NewLogLogger(o.Log.Handler(), slog.LevelDebug),
	}
	return a
}

// Handler returns the routes. Other methods than GET and HEAD get 405,
// unknown paths 404.
func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		text(w, http.StatusOK, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ok, why := a.o.Health.Ready(); !ok {
			text(w, http.StatusServiceUnavailable, why)
			return
		}
		text(w, http.StatusOK, "ready")
	})
	mux.HandleFunc("GET /metrics", a.metrics)
	if PprofBuilt {
		mux.Handle("GET /debug/pprof/", http.HandlerFunc(a.pprof))
	}
	if !a.o.CheckHost {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			text(w, http.StatusMisdirectedRequest, "the admin listener is on loopback: use a loopback address or localhost as the host")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *Admin) metrics(w http.ResponseWriter, r *http.Request) {
	release, ok := acquire(a.scrapes)
	if !ok {
		busy(w)
		return
	}
	defer release()
	// Whatever the Accept header asks for: the text format is the only
	// one, and Prometheus takes it.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	if _, err := a.o.Metrics.Registry().WriteTo(w); err != nil {
		a.o.Log.DebugContext(r.Context(), "writing metrics failed", "err", err)
	}
}

func (a *Admin) pprof(w http.ResponseWriter, r *http.Request) {
	if !a.o.Pprof.Load() {
		http.NotFound(w, r)
		return
	}
	if s := r.URL.Query().Get("seconds"); s != "" {
		if sec, err := strconv.ParseFloat(s, 64); err == nil && sec > adminMaxProfileSecs {
			text(w, http.StatusBadRequest, "seconds: at most "+strconv.Itoa(adminMaxProfileSecs))
			return
		}
	}
	releaseProfile, ok := acquire(a.profiles)
	if !ok {
		busy(w)
		return
	}
	defer releaseProfile()
	release, ok := acquire(a.scrapes)
	if !ok {
		busy(w)
		return
	}
	defer release()
	a.o.Log.InfoContext(r.Context(), "pprof request", "path", r.URL.Path, "query", r.URL.RawQuery, "remote_addr", r.RemoteAddr)
	servePprof(w, r)
}

// acquire takes a slot of sem without waiting.
func acquire(sem chan struct{}) (release func(), ok bool) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	default:
		return nil, false
	}
}

func busy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	text(w, http.StatusServiceUnavailable, "busy")
}

func text(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body + "\n"))
}

// loopbackHost reports whether a Host header names a loopback address or
// localhost.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Serve serves ln until Shutdown; at most 64 connections are open at a
// time, further ones wait in the listen backlog. It returns nil after
// Shutdown.
func (a *Admin) Serve(ln net.Listener) error {
	err := a.srv.Serve(newLimitListener(ln, adminMaxConns))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops the server: it lets requests in progress finish for up
// to a second, then closes every connection.
func (a *Admin) Shutdown(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, adminShutdownWait)
	defer cancel()
	if err := a.srv.Shutdown(ctx); err != nil {
		_ = a.srv.Close()
	}
}

// limitListener accepts a connection only while fewer than cap(sem) are
// open. Close ends a wait for a free slot: http.Server.Shutdown waits for
// Accept to return before it looks at its deadline.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, n int) *limitListener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
