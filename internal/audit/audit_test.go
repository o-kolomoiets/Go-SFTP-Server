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

// Probe does not wait for the next probe time.
func TestProbe(t *testing.T) {
	t.Parallel()

	var buf buffer
	l := New(&buf, slog.New(slog.DiscardHandler))
	buf.setFail(true)
	l.Event("fs.upload", slog.String("path", "/x"))
	if l.Healthy() || l.Probe() {
		t.Fatal("healthy while writes fail")
	}
	buf.setFail(false)
	if !l.Probe() {
		t.Fatal("Probe() = false although writes work")
	}
	if lines := buf.lines(); len(lines) == 0 || lines[len(lines)-1]["event"] != "server.audit_recovered" {
		t.Errorf("no recovery event: %v", lines)
	}
}

// Available, Failing and WriteErrors read the state without probing; the
// errors include failed probes.
func TestStateWithoutProbe(t *testing.T) {
	t.Parallel()

	for _, failOpen := range []bool{false, true} {
		var buf buffer
		l, err := NewWithOptions(&buf, slog.New(slog.DiscardHandler), Options{FailOpen: failOpen})
		if err != nil {
			t.Fatal(err)
		}
		if !l.Available() || l.Failing() || l.WriteErrors() != 0 {
			t.Fatalf("fail-open %v: new logger: available %v, failing %v, errors %d", failOpen, l.Available(), l.Failing(), l.WriteErrors())
		}
		buf.setFail(true)
		l.Event("fs.upload", slog.String("path", "/x"))
		l.Event("fs.upload", slog.String("path", "/y"))
		before := len(buf.lines())
		if l.Available() != failOpen || !l.Failing() || l.WriteErrors() != 2 {
			t.Errorf("fail-open %v: after two failed writes: available %v, failing %v, errors %d", failOpen, l.Available(), l.Failing(), l.WriteErrors())
		}
		if !failOpen {
			l.Probe() // fails, and counts
			if l.WriteErrors() != 3 {
				t.Errorf("a failed probe is not counted: %d", l.WriteErrors())
			}
		}
		buf.setFail(false)
		if l.Available() != failOpen || len(buf.lines()) != before {
			t.Errorf("fail-open %v: Available probed or changed state", failOpen)
		}
		if failOpen {
			l.Event("fs.upload", slog.String("path", "/z"))
		} else {
			l.Probe()
		}
		if !l.Available() || l.Failing() {
			t.Errorf("fail-open %v: after recovery: available %v, failing %v", failOpen, l.Available(), l.Failing())
		}
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

func TestCategories(t *testing.T) {
	t.Parallel()

	for event, want := range map[string]string{
		"server.start": CategoryServer, "conn.accept": CategoryConn, "auth.failure": CategoryAuth,
		"session.end": CategorySession, "fs.upload": CategoryTransfer, "fs.download": CategoryTransfer,
		"fs.denied": CategoryDenied, "fs.list": CategoryList, "fs.stat": CategoryStat,
		"fs.rename": CategoryModify, "fs.mkdir": CategoryModify, "fs.setstat": CategoryModify,
	} {
		if got := CategoryOf(event); got != want {
			t.Errorf("CategoryOf(%q) = %q, want %q", event, got, want)
		}
	}

	var b buffer
	l, err := NewWithOptions(&b, slog.New(slog.DiscardHandler), Options{Categories: []string{CategoryAuth, CategoryList}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"server.start", "conn.accept", "auth.success", "fs.upload", "fs.list", "fs.stat"} {
		l.With("conn_id", "x").Event(ev)
	}
	var got []string
	for _, line := range b.lines() {
		got = append(got, line["event"].(string))
	}
	if strings.Join(got, ",") != "server.start,auth.success,fs.list" {
		t.Errorf("recorded %v", got)
	}
	if !l.Enabled("fs.list") || l.Enabled("fs.stat") {
		t.Error("Enabled")
	}

	// Defaults leave out list and stat.
	d := New(io.Discard, slog.New(slog.DiscardHandler))
	if d.Enabled("fs.list") || d.Enabled("fs.stat") || !d.Enabled("fs.denied") {
		t.Error("default categories")
	}
	if _, err := NewWithOptions(io.Discard, nil, Options{Categories: []string{"files"}}); err == nil {
		t.Error("unknown category accepted")
	}
}

func TestFailOpen(t *testing.T) {
	t.Parallel()

	var b buffer
	var fallback bytes.Buffer
	l, err := NewWithOptions(&b, slog.New(slog.NewTextHandler(&fallback, nil)), Options{FailOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	b.setFail(true)
	l.Event("fs.upload", slog.String("path", "/a"))
	if !l.Healthy() {
		t.Error("fail-open logger reports unhealthy")
	}
	if !strings.Contains(fallback.String(), "audit event not persisted") {
		t.Errorf("event not in the fallback log: %q", fallback.String())
	}
	b.setFail(false)
	fallback.Reset()
	l.Event("fs.upload", slog.String("path", "/b"))
	l.Event("fs.upload", slog.String("path", "/c"))
	if strings.Contains(fallback.String(), "/c") {
		t.Error("events still go to the fallback log after recovery")
	}
}

// failOn fails writes that contain a marker and accepts all others.
type failOn struct {
	mu     sync.Mutex
	marker string
	b      bytes.Buffer
}

func (f *failOn) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Contains(p, []byte(f.marker)) {
		return 0, syscall.EIO
	}
	return f.b.Write(p)
}

// Review finding: in fail-open mode an event whose own write failed goes to
// the fallback log even if another write succeeded in between.
func TestFailOpenFallbackPerEvent(t *testing.T) {
	t.Parallel()

	w := &failOn{marker: "/lost"}
	var fallback bytes.Buffer
	var mu sync.Mutex
	l, err := NewWithOptions(w, slog.New(slog.NewTextHandler(lockedWriter{&mu, &fallback}, nil)), Options{FailOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			p := "/ok"
			if i%5 == 0 {
				p = "/lost"
			}
			l.Event("fs.remove", slog.String("path", p))
		})
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(fallback.String(), "/lost"); n != 10 {
		t.Errorf("%d of 10 failed events reached the fallback log", n)
	}
	if strings.Contains(fallback.String(), "/ok") {
		t.Error("persisted events were also sent to the fallback log")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Recover probes at once in either mode; a fail-open log is cleared
// without an event (review finding: its gauge stayed failing).
func TestRecover(t *testing.T) {
	t.Parallel()

	for _, failOpen := range []bool{false, true} {
		var buf buffer
		l, err := NewWithOptions(&buf, slog.New(slog.DiscardHandler), Options{FailOpen: failOpen})
		if err != nil {
			t.Fatal(err)
		}
		if !l.Recover() || len(buf.lines()) != 0 {
			t.Fatalf("fail-open %v: Recover wrote while the log works", failOpen)
		}
		buf.setFail(true)
		l.Event("fs.upload", slog.String("path", "/x"))
		if l.Recover() || !l.Failing() {
			t.Errorf("fail-open %v: Recover succeeded while writes fail", failOpen)
		}
		buf.setFail(false)
		// At once, though a probe just ran.
		if !l.Recover() || l.Failing() || !l.Available() {
			t.Errorf("fail-open %v: Recover did not clear the failure", failOpen)
		}
		if lines := buf.lines(); len(lines) != 1 || lines[0]["event"] != "server.audit_recovered" {
			t.Errorf("fail-open %v: lines %v", failOpen, lines)
		}
		if l.WriteErrors() != 2 {
			t.Errorf("fail-open %v: WriteErrors() = %d, want 2", failOpen, l.WriteErrors())
		}
	}
}

// Render formats an event like the output, with the context, also for a
// category that is not recorded.
func TestRender(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	l, err := NewWithOptions(&out, slog.New(slog.DiscardHandler), Options{Categories: []string{CategoryConn}})
	if err != nil {
		t.Fatal(err)
	}
	l = l.With("conn_id", "c1", slog.String("user", "alice"))
	l.Event("fs.upload", slog.String("path", "/a"))
	if out.Len() != 0 {
		t.Fatalf("a disabled category was written: %s", out.String())
	}
	got := string(l.Render("fs.upload", slog.String("path", "/a"), slog.String("result", "ok")))
	for _, want := range []string{`"msg":"audit"`, `"conn_id":"c1"`, `"user":"alice"`, `"schema":1`, `"event":"fs.upload"`, `"path":"/a"`, `"result":"ok"`} {
		if !strings.Contains(got, want) {
			t.Errorf("Render = %s, missing %s", got, want)
		}
	}
	if !strings.HasSuffix(got, "}\n") {
		t.Errorf("Render does not end the line: %q", got)
	}
}
