// SPDX-License-Identifier: Apache-2.0

// Package audit writes one JSON line per security-relevant action.
//
// The audit log is fail-closed: when a write fails (disk full, closed pipe),
// Healthy reports false, and the server refuses new connections and
// modifying operations until a probe write succeeds again.
package audit

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

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
}

// New writes JSON lines to w; events that cannot be written are also logged
// to fallback.
func New(w io.Writer, fallback *slog.Logger) *Logger {
	s := &sink{w: w}
	h := slog.NewJSONHandler(s, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &Logger{l: slog.New(h), sink: s, fallback: fallback}
}

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
	}
}

// Event records an audit event such as "fs.upload".
func (l *Logger) Event(event string, attrs ...slog.Attr) {
	args := make([]any, 0, 4+len(attrs))
	args = append(args, "schema", Schema, "event", event)
	for _, a := range attrs {
		args = append(args, a)
	}
	l.l.Log(context.Background(), slog.LevelInfo, "audit", args...)
	if l.sink.failed.Load() {
		args := append(append([]any(nil), l.attrs...), slog.String("event", event))
		for _, a := range attrs {
			args = append(args, a)
		}
		l.fallback.Warn("audit event not persisted: audit log unavailable", args...)
	}
}

// Healthy reports whether the audit log accepts writes. While it does not,
// it retries at most every 5 seconds with a server.audit_recovered event.
func (l *Logger) Healthy() bool {
	if !l.sink.failed.Load() {
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

// sink records write failures of the underlying writer.
type sink struct {
	w      io.Writer
	failed atomic.Bool

	mu        sync.Mutex
	lastProbe time.Time
}

func (s *sink) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.failed.Store(true)
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
