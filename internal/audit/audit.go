// SPDX-License-Identifier: Apache-2.0

// Package audit writes one JSON line per security-relevant action.
//
// By default the audit log is fail-closed: when a write fails (disk full,
// closed pipe), Healthy reports false, and the server refuses new
// connections and modifying operations until a probe write succeeds again.
package audit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event categories for Options.Categories (ROADMAP §6.4).
const (
	CategoryServer   = "server" // always recorded
	CategoryConn     = "conn"
	CategoryAuth     = "auth"
	CategorySession  = "session"
	CategoryTransfer = "transfer" // fs.upload, fs.download
	CategoryModify   = "modify"   // fs.remove, fs.rename, fs.mkdir, fs.rmdir, fs.setstat
	CategoryDenied   = "denied"   // fs.denied
	CategoryList     = "list"     // fs.list, opt-in
	CategoryStat     = "stat"     // fs.stat, opt-in
)

// DefaultCategories are recorded when Options.Categories is nil.
var DefaultCategories = []string{CategoryConn, CategoryAuth, CategorySession, CategoryTransfer, CategoryModify, CategoryDenied}

var allCategories = []string{CategoryServer, CategoryConn, CategoryAuth, CategorySession, CategoryTransfer, CategoryModify, CategoryDenied, CategoryList, CategoryStat}

// Options configure a Logger.
type Options struct {
	// Categories to record; nil means DefaultCategories. "server" is always
	// recorded.
	Categories []string
	// FailOpen keeps the server working when the audit log cannot be
	// written; the events then go to the operational log only.
	FailOpen bool
}

// ParseCategory validates a category name.
func ParseCategory(s string) (string, error) {
	for _, c := range allCategories {
		if s == c {
			return c, nil
		}
	}
	return "", fmt.Errorf("unknown audit category %q (want %s)", s, strings.Join(allCategories, ", "))
}

// CategoryOf returns the category of an event name.
func CategoryOf(event string) string {
	switch {
	case strings.HasPrefix(event, "server."):
		return CategoryServer
	case strings.HasPrefix(event, "conn."):
		return CategoryConn
	case strings.HasPrefix(event, "auth."):
		return CategoryAuth
	case strings.HasPrefix(event, "session."):
		return CategorySession
	}
	switch event {
	case "fs.upload", "fs.download":
		return CategoryTransfer
	case "fs.denied":
		return CategoryDenied
	case "fs.list":
		return CategoryList
	case "fs.stat":
		return CategoryStat
	}
	return CategoryModify
}

// Schema is the version of the event format; within one version fields are
// only ever added.
const Schema = 1

// probeInterval is how often an unhealthy sink is retried.
const probeInterval = 5 * time.Second

// Logger writes audit events. Loggers derived with With share one sink.
type Logger struct {
	l        *slog.Logger
	sink     *sink
	fallback *slog.Logger // operational log, used while the sink fails
	attrs    []any
	enabled  map[string]bool // categories
}

// New writes JSON lines to w with the default options; events that cannot
// be written are also logged to fallback.
func New(w io.Writer, fallback *slog.Logger) *Logger {
	l, _ := NewWithOptions(w, fallback, Options{})
	return l
}

// NewWithOptions is New with options; it fails on an unknown category.
func NewWithOptions(w io.Writer, fallback *slog.Logger, opts Options) (*Logger, error) {
	cats := opts.Categories
	if cats == nil {
		cats = DefaultCategories
	}
	enabled := map[string]bool{CategoryServer: true}
	for _, c := range cats {
		if _, err := ParseCategory(c); err != nil {
			return nil, err
		}
		enabled[c] = true
	}
	s := &sink{w: w, failOpen: opts.FailOpen}
	h := slog.NewJSONHandler(s, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &Logger{l: slog.New(h), sink: s, fallback: fallback, enabled: enabled}, nil
}

// Enabled reports whether events of this name are recorded.
func (l *Logger) Enabled(event string) bool { return l.enabled[CategoryOf(event)] }

// Discard returns a Logger that drops all events.
func Discard() *Logger { return New(io.Discard, slog.New(slog.DiscardHandler)) }

// With returns a Logger that adds attrs (key-value pairs or slog.Attr) to
// every event.
func (l *Logger) With(attrs ...any) *Logger {
	return &Logger{
		l:        l.l.With(attrs...),
		sink:     l.sink,
		fallback: l.fallback,
		attrs:    append(append([]any(nil), l.attrs...), attrs...),
		enabled:  l.enabled,
	}
}

// Event records an audit event such as "fs.upload", unless its category is
// not enabled.
func (l *Logger) Event(event string, attrs ...slog.Attr) {
	if !l.Enabled(event) {
		return
	}
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "audit", 0)
	r.AddAttrs(slog.Int("schema", Schema), slog.String("event", event))
	r.AddAttrs(attrs...)
	// The handler returns this event's own write error; the shared failure
	// flag may already have been cleared by another event's write.
	if err := l.l.Handler().Handle(context.Background(), r); err != nil {
		args := append(append([]any(nil), l.attrs...), slog.String("event", event))
		for _, a := range attrs {
			args = append(args, a)
		}
		l.fallback.Warn("audit event not persisted: audit log unavailable", args...)
	}
}

// Healthy reports whether the audit log accepts writes. While it does not,
// it retries at most every 5 seconds with a server.audit_recovered event.
// A fail-open logger is always healthy.
func (l *Logger) Healthy() bool {
	if l.sink.failOpen || !l.sink.failed.Load() {
		return true
	}
	if !l.sink.probeDue() {
		return false
	}
	l.sink.failed.Store(false)
	l.l.Log(context.Background(), slog.LevelInfo, "audit", "schema", Schema, "event", "server.audit_recovered")
	ok := !l.sink.failed.Load()
	if ok {
		l.fallback.Info("audit log recovered")
	}
	return ok
}

// Probe retries an unhealthy audit log at once instead of at the next
// probe time, for example after its file was reopened. It reports whether
// the log works.
func (l *Logger) Probe() bool {
	l.sink.mu.Lock()
	l.sink.lastProbe = time.Time{}
	l.sink.mu.Unlock()
	return l.Healthy()
}

// sink records write failures of the underlying writer.
type sink struct {
	w        io.Writer
	failOpen bool // a later successful write clears the failure
	failed   atomic.Bool

	mu        sync.Mutex
	lastProbe time.Time
}

func (s *sink) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	switch {
	case err != nil:
		s.failed.Store(true)
	case s.failOpen:
		s.failed.Store(false)
	}
	return n, err
}

func (s *sink) probeDue() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastProbe) < probeInterval {
		return false
	}
	s.lastProbe = time.Now()
	return true
}
