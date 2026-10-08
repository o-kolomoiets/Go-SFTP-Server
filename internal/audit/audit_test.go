// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// buffer is a goroutine-safe writer that can be made to fail.
type buffer struct {
	mu   sync.Mutex
	b    bytes.Buffer
	fail bool
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return 0, syscall.ENOSPC
	}
	return b.b.Write(p)
}

func (b *buffer) setFail(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fail = v
}

func (b *buffer) lines() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(b.b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			panic(err)
		}
		out = append(out, m)
	}
	return out
}

func TestEventFormat(t *testing.T) {
	t.Parallel()

	var buf buffer
	l := New(&buf, slog.New(slog.DiscardHandler)).With("user", "alice")
	l.Event("fs.upload", slog.String("path", "/a\n\x1b[31m.txt"), slog.Int64("bytes", 3))

	lines := buf.lines()
	if len(lines) != 1 {
		t.Fatalf("got %d lines", len(lines))
	}
	got := lines[0]
	for k, want := range map[string]any{
		"msg": "audit", "schema": float64(Schema), "event": "fs.upload",
		"user": "alice", "path": "/a\n\x1b[31m.txt", "bytes": float64(3),
	} {
		if got[k] != want {
			t.Errorf("%s = %#v, want %#v", k, got[k], want)
		}
	}
}

func TestFailClosed(t *testing.T) {
	t.Parallel()

	var buf, fallback buffer
	l := New(&buf, slog.New(slog.NewTextHandler(&fallback, nil)))
	if !l.Healthy() {
		t.Fatal("new logger is unhealthy")
	}

	buf.setFail(true)
	l.Event("fs.upload", slog.String("path", "/x"))
	if l.Healthy() {
		t.Error("Healthy() = true after a failed write")
	}
	if !strings.Contains(fallback.b.String(), "audit log unavailable") {
		t.Errorf("event not mirrored to the fallback log: %q", fallback.b.String())
	}

	// Recovery: force the next probe and let the write succeed.
	buf.setFail(false)
	l.sink.mu.Lock()
	l.sink.lastProbe = l.sink.lastProbe.Add(-2 * probeInterval)
	l.sink.mu.Unlock()
	if !l.Healthy() {
		t.Fatal("Healthy() = false after the sink recovered")
	}
	lines := buf.lines()
	if len(lines) == 0 || lines[len(lines)-1]["event"] != "server.audit_recovered" {
		t.Errorf("no recovery event: %v", lines)
	}
}

func TestShortWriteFails(t *testing.T) {
	t.Parallel()

	s := &sink{w: shortWriter{}}
	if _, err := s.Write([]byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("short write error = %v, want io.ErrShortWrite", err)
	}
	if !s.failed.Load() {
		t.Error("short write not recorded as a failure")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
