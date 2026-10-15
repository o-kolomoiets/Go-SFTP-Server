// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"

	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// logBuf collects log output safely.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func testLog() (*slog.Logger, *logBuf) {
	var b logBuf
	return slog.New(slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})), &b
}

// value reads one series, 0 when absent.
func value(m *obs.Metrics, series string) float64 {
	v, _ := m.Value(series)
	return v
}

func upload(user, final string) *Event {
	return &Event{
		Name: "fs.upload", Mount: "inbox", User: user, ConnID: "c1",
		Path: final, FinalPath: final,
		Line: []byte(`{"event":"fs.upload","final_path":"` + final + `"}` + "\n"),
	}
}

func TestMatches(t *testing.T) {
	t.Parallel()
	s := &Spec{On: []string{"fs.upload"}, Mounts: []string{"inbox"}, Exclude: []string{"*.filepart", "*.partial"}}
	cases := []struct {
		event    string
		uploaded bool
		mount    string
		name     string
		want     bool
	}{
		{"fs.upload", false, "inbox", "report.pdf", true},
		{"fs.upload", false, "inbox", "report.pdf.filepart", false},
		{"fs.upload", false, "inbox", "report.pdf.a1b2.partial", false},
		{"fs.upload", false, "outbox", "report.pdf", false},
		{"fs.rename", true, "inbox", "report.pdf", true},   // completes a temp upload
		{"fs.rename", false, "inbox", "report.pdf", false}, // a plain rename
		{"fs.download", false, "inbox", "report.pdf", false},
	}
	for _, c := range cases {
		if got := s.matches(c.event, c.uploaded, c.mount, c.name); got != c.want {
			t.Errorf("matches(%s, %v, %s, %s) = %v", c.event, c.uploaded, c.mount, c.name, got)
		}
	}
	g := &Spec{On: []string{"fs.upload", "fs.rename"}, Glob: []string{"*.pdf", "*.PDF"}}
	for name, want := range map[string]bool{"a.pdf": true, "A.PDF": true, "a.Pdf": false, "a.pdf.filepart": false} {
		if got := g.matches("fs.upload", false, "x", name); got != want {
			t.Errorf("glob %s = %v", name, got)
		}
	}
	// A hook on both events gets an uploaded rename once (Notify matches
	// each hook once).
	if !g.matches("fs.rename", true, "x", "a.pdf") {
		t.Error("uploaded rename not matched")
	}
}

// signVector was computed with Python's hmac module, independently of
// Sign; docs/hooks.md publishes it.
const signVector = "123e292743c83aa82711008c58844636b1744dd867f0e811a24154cc4f3b2f41"

// The signature is fixed: docs/hooks.md publishes this vector.
func TestSignVector(t *testing.T) {
	t.Parallel()
	secret := []byte("3f9a1c6e2b7d4f8a0c5e9b1d6a3f7c2e8b4d0a6f1c9e5b7a2d8f4c0e6b3a9d1f")
	body := []byte(`{"event":"fs.upload","final_path":"/report.pdf"}` + "\n")
	got := Sign(secret, "0123456789abcdef0123456789abcdef", "1760000000", body)
	const want = "sha256=" + signVector
	if got != want {
		t.Fatalf("Sign = %s, want %s", got, want)
	}
}

// fakeTransport answers requests with a function, without sockets, so
// that retries run under synctest.
type fakeTransport struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
	fn   func(n int, r *http.Request) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.body = append(f.body, b)
	n := len(f.reqs)
	f.mu.Unlock()
	return f.fn(n, r)
}

func (f *fakeTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func reply(status int, header ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Set(header[i], header[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("ok"))}
}

func webhookSpec(name string) Spec {
	return Spec{
		Name: name, On: []string{"fs.upload"}, Concurrency: 1, Queue: DefaultQueue,
		Webhook: &Webhook{URL: "https://receiver.example/hooks/secret-token?k=secret-query", Secret: []byte(strings.Repeat("k", 32)), Timeout: DefaultHookTime},
	}
}

func TestWebhookRetries(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		ft := &fakeTransport{fn: func(n int, _ *http.Request) (*http.Response, error) {
			switch n {
			case 1:
				return reply(http.StatusServiceUnavailable), nil
			case 2:
				return reply(http.StatusTooManyRequests, "Retry-After", "3600"), nil // clamped to 120 s
			default:
				return reply(http.StatusNoContent), nil
			}
		}}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		d.Update([]Spec{webhookSpec("notify")})
		start := time.Now()
		d.Notify(upload("alice", "/report.pdf"))
		synctest.Wait()
		for ft.count() < 3 {
			time.Sleep(time.Second)
			synctest.Wait()
		}
		elapsed := time.Since(start)
		if elapsed < 120*time.Second || elapsed > 125*time.Second {
			t.Errorf("third attempt after %v, want about 1 s + 120 s", elapsed)
		}
		d.Close(time.Now().Add(time.Second))

		ids := map[string]bool{}
		for i, r := range ft.reqs {
			id, ts, sig := r.Header.Get("X-Gosftpd-Delivery"), r.Header.Get("X-Gosftpd-Timestamp"), r.Header.Get("X-Gosftpd-Signature")
			ids[id] = true
			if want := Sign([]byte(strings.Repeat("k", 32)), id, ts, ft.body[i]); sig != want {
				t.Errorf("attempt %d: signature %s, want %s", i+1, sig, want)
			}
			if r.Header.Get("User-Agent") != "gosftpd" || r.Header.Get("X-Gosftpd-Event") != "fs.upload" || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("attempt %d: headers %v", i+1, r.Header)
			}
		}
		if len(ids) != 1 || len(ft.reqs[0].Header.Get("X-Gosftpd-Delivery")) != 32 {
			t.Errorf("delivery IDs %v: want one of 32 hex characters", ids)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="ok",type="webhook"}`); v != 1 {
			t.Errorf("ok = %v", v)
		}
		if v := value(m, `gosftpd_hook_retries_total`); v != 2 {
			t.Errorf("retries = %v", v)
		}
		if strings.Contains(logs.String(), "secret-token") || strings.Contains(logs.String(), "secret-query") {
			t.Errorf("log holds the URL:\n%s", logs)
		}
	})
}

// A reload that rotates the secret while an event waits for a retry: the
// retry is signed with the new secret.
func TestWebhookRetryAfterRotation(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ft := &fakeTransport{fn: func(n int, _ *http.Request) (*http.Response, error) {
			if n == 1 {
				return reply(http.StatusServiceUnavailable), nil
			}
			return reply(http.StatusNoContent), nil
		}}
		d := New(Options{Transport: ft})
		s := webhookSpec("notify")
		d.Update([]Spec{s})
		d.Notify(upload("alice", "/report.pdf"))
		synctest.Wait() // the first attempt failed; the retry waits
		rotated := s
		rotated.Webhook = &Webhook{URL: s.Webhook.URL, Secret: []byte(strings.Repeat("n", 32)), Timeout: s.Webhook.Timeout}
		d.Update([]Spec{rotated})
		time.Sleep(10 * time.Second)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if ft.count() != 2 {
			t.Fatalf("%d attempts, want 2", ft.count())
		}
		for i, secret := range []string{"k", "n"} {
			r := ft.reqs[i]
			id, ts := r.Header.Get("X-Gosftpd-Delivery"), r.Header.Get("X-Gosftpd-Timestamp")
			if want := Sign([]byte(strings.Repeat(secret, 32)), id, ts, ft.body[i]); r.Header.Get("X-Gosftpd-Signature") != want {
				t.Errorf("attempt %d not signed with the secret current when it started", i+1)
			}
		}
	})
}

func TestWebhookPermanentFailure(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		for _, status := range []int{http.StatusNotFound, http.StatusFound} {
			ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
				return reply(status, "Location", "https://elsewhere.example/"), nil
			}}
			d := New(Options{Log: log, Metrics: m, Transport: ft})
			d.Update([]Spec{webhookSpec("notify")})
			d.Notify(upload("alice", "/a.pdf"))
			synctest.Wait()
			d.Close(time.Now().Add(time.Second))
			if ft.count() != 1 {
				t.Errorf("status %d: %d attempts, want 1", status, ft.count())
			}
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="failed",type="webhook"}`); v != 2 {
			t.Errorf("failed = %v", v)
		}
		if !strings.Contains(logs.String(), "status 404") {
			t.Errorf("log:\n%s", logs)
		}
	})
}

func TestWebhookGivesUp(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		}}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		d.Update([]Spec{webhookSpec("notify")})
		d.Notify(upload("alice", "/a.pdf"))
		for range 200 {
			time.Sleep(time.Second)
		}
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if ft.count() != maxAttempts {
			t.Errorf("%d attempts, want %d", ft.count(), maxAttempts)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="failed",type="webhook"}`); v != 1 {
			t.Errorf("failed = %v", v)
		}
		if !strings.Contains(logs.String(), "attempts=5") || strings.Contains(logs.String(), "secret-token") || strings.Contains(logs.String(), "secret-query") {
			t.Errorf("log:\n%s", logs)
		}
	})
}

// A webhook that fails on name resolution logs the name-resolution files
// that Landlock no longer lets gosftpd read; one that fails otherwise does
// not ask.
func TestWebhookNameWarnings(t *testing.T) {
	t.Parallel()
	for name, failure := range map[string]error{
		"name resolution": &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "receiver.example", IsNotFound: true}},
		"refused":         errors.New("dial tcp: connection refused"),
	} {
		synctest.Test(t, func(t *testing.T) {
			log, logs := testLog()
			var asked int
			d := New(Options{
				Log:       log,
				Transport: &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) { return nil, failure }},
				NameWarnings: func() []string {
					asked++
					return []string{"/etc/resolv.conf was replaced after start; webhooks resolve names again after a restart"}
				},
			})
			d.Update([]Spec{webhookSpec("notify")})
			d.Notify(upload("alice", "/a.pdf"))
			for range 200 {
				time.Sleep(time.Second)
			}
			synctest.Wait()
			d.Close(time.Now().Add(time.Second))
			const want = `level=WARN msg=landlock detail="/etc/resolv.conf was replaced after start; webhooks resolve names again after a restart"`
			if dns := name == "name resolution"; dns != (asked == 1) || dns != strings.Contains(logs.String(), want) {
				t.Errorf("%s: asked %d times; log:\n%s", name, asked, logs)
			}
		})
	}
}

// A timeout and a TLS error leave no trace of the URL's path or query in
// the log, at any level.
func TestWebhookErrorsWithoutToken(t *testing.T) {
	t.Parallel()
	for name, fail := range map[string]func(*http.Request) (*http.Response, error){
		"timeout": func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		},
		"tls": func(*http.Request) (*http.Response, error) {
			return nil, x509.UnknownAuthorityError{}
		},
	} {
		synctest.Test(t, func(t *testing.T) {
			m := obs.NewMetrics("test")
			log, logs := testLog()
			d := New(Options{Log: log, Metrics: m, Transport: &fakeTransport{fn: func(_ int, r *http.Request) (*http.Response, error) { return fail(r) }}})
			s := webhookSpec("notify")
			s.Webhook.Timeout = time.Second
			d.Update([]Spec{s})
			d.Notify(upload("alice", "/a.pdf"))
			for range 200 {
				time.Sleep(time.Second)
			}
			synctest.Wait()
			d.Close(time.Now().Add(time.Second))
			if v := value(m, `gosftpd_hook_deliveries_total{result="failed",type="webhook"}`); v != 1 {
				t.Errorf("%s: failed = %v", name, v)
			}
			if out := logs.String(); strings.Contains(out, "secret-token") || strings.Contains(out, "secret-query") {
				t.Errorf("%s: the URL's token is in the log:\n%s", name, out)
			}
		})
	}
}

// A hook removed while its event waits for a retry drops it at once: no
// further attempt, no retry counted, nothing left for shutdown.
func TestRemovedDuringRetry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
			return reply(http.StatusServiceUnavailable, "Retry-After", "120"), nil
		}}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		d.Update([]Spec{webhookSpec("notify")})
		d.Notify(upload("alice", "/report.pdf"))
		synctest.Wait() // the first attempt failed; the retry waits
		d.Update(nil)
		synctest.Wait()
		if n := d.QueueLength(); n != 0 {
			t.Errorf("QueueLength = %d right after the removal", n)
		}
		start := time.Now()
		d.Close(time.Now().Add(30 * time.Second))
		if el := time.Since(start); el != 0 {
			t.Errorf("Close took %v", el)
		}
		if ft.count() != 1 || value(m, `gosftpd_hook_retries_total`) != 0 || value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`) != 1 {
			t.Errorf("attempts %d, retries %v, dropped %v", ft.count(), value(m, `gosftpd_hook_retries_total`),
				value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`))
		}
		if strings.Contains(logs.String(), "reason=shutdown") {
			t.Errorf("an event of a removed hook is offered for replay:\n%s", logs)
		}
	})
}

// Shutdown during a retry wait: the event is dropped and logged for
// replay, and the retry that never happened is not counted.
func TestCloseDuringRetry(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) { return reply(http.StatusServiceUnavailable), nil }}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		d.Update([]Spec{webhookSpec("notify")})
		d.Notify(upload("alice", "/report.pdf"))
		synctest.Wait()
		d.Close(time.Now())
		if ft.count() != 1 || value(m, `gosftpd_hook_retries_total`) != 0 || value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`) != 1 {
			t.Errorf("attempts %d, retries %v", ft.count(), value(m, `gosftpd_hook_retries_total`))
		}
		if !strings.Contains(logs.String(), "path=/report.pdf") {
			t.Errorf("not logged for replay:\n%s", logs)
		}
	})
}

func TestQueueFull(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		block := make(chan struct{})
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
			<-block
			return reply(http.StatusOK), nil
		}}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		s := webhookSpec("notify")
		s.Queue = 3
		d.Update([]Spec{s})
		for i := range 10 {
			user := "alice"
			if i%2 == 1 {
				user = "bob"
			}
			d.Notify(upload(user, fmt.Sprintf("/f%d", i)))
			synctest.Wait()
		}
		// One in flight, three queued, six dropped.
		if n := d.QueueLength(); n != 4 {
			t.Errorf("QueueLength = %d, want 4", n)
		}
		close(block)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 6 {
			t.Errorf("dropped = %v", v)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="ok",type="webhook"}`); v != 4 {
			t.Errorf("ok = %v", v)
		}
		if !strings.Contains(logs.String(), "alice=") || !strings.Contains(logs.String(), "bob=") {
			t.Errorf("drop warning without users:\n%s", logs)
		}
	})
}

// The drops of a burst are warned of when the minute ends, with their
// count per user, without waiting for another drop or for shutdown.
func TestQueueFullWarnsOfTheBurst(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		log, logs := testLog()
		block := make(chan struct{})
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
			<-block
			return reply(http.StatusOK), nil
		}}
		d := New(Options{Log: log, Transport: ft})
		s := webhookSpec("notify")
		s.Queue = 1
		d.Update([]Spec{s})
		d.Notify(upload("alice", "/f0"))
		synctest.Wait() // f0 is in flight; then one is queued and 98 dropped
		for i := 1; i < 100; i++ {
			d.Notify(upload("alice", fmt.Sprintf("/f%d", i)))
		}
		synctest.Wait()
		time.Sleep(61 * time.Second)
		synctest.Wait()
		out := logs.String()
		if !strings.Contains(out, `dropped=1 by_user="alice=1"`) || !strings.Contains(out, `dropped=97 by_user="alice=97"`) {
			t.Errorf("the burst is not warned of within a minute:\n%s", out)
		}
		close(block)
		d.Close(time.Now().Add(time.Second))
	})
}

func TestQueueBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := maxQueueBytes
		maxQueueBytes = 4 << 10
		defer func() { maxQueueBytes = old }()
		m := obs.NewMetrics("test")
		block := make(chan struct{})
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) {
			<-block
			return reply(http.StatusOK), nil
		}}
		d := New(Options{Metrics: m, Transport: ft})
		d.Update([]Spec{webhookSpec("notify")})
		big := upload("alice", "/x")
		big.Line = bytes.Repeat([]byte("a"), 1500)
		for range 6 {
			d.Notify(big)
			synctest.Wait()
		}
		close(block)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		// One in flight, two fit into 4 KiB, three are dropped.
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 3 {
			t.Errorf("dropped = %v", v)
		}
	})
}

func TestDelayAndOrder(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var got []string
		var at []time.Duration
		start := time.Now()
		ft := &fakeTransport{fn: func(_ int, r *http.Request) (*http.Response, error) {
			mu.Lock()
			got = append(got, r.Header.Get("X-Gosftpd-Event"))
			at = append(at, time.Since(start))
			mu.Unlock()
			return reply(http.StatusOK), nil
		}}
		d := New(Options{Transport: ft})
		s := webhookSpec("archive")
		s.On = []string{"fs.upload", "fs.remove"}
		s.Delay = 2 * time.Minute
		d.Update([]Spec{s})
		d.Notify(upload("alice", "/a"))
		time.Sleep(30 * time.Second)
		rm := upload("alice", "/a")
		rm.Name = "fs.remove"
		d.Notify(rm)
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if len(got) != 2 || got[0] != "fs.upload" || got[1] != "fs.remove" {
			t.Fatalf("delivered %v", got)
		}
		if at[0] != 2*time.Minute || at[1] != 2*time.Minute+30*time.Second {
			t.Errorf("delivered at %v, want 2m and 2m30s", at)
		}
	})
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		var mu sync.Mutex
		var urls []string
		ft := &fakeTransport{fn: func(_ int, r *http.Request) (*http.Response, error) {
			mu.Lock()
			urls = append(urls, r.URL.Host+" "+r.Header.Get("X-Gosftpd-Event"))
			mu.Unlock()
			return reply(http.StatusOK), nil
		}}
		d := New(Options{Metrics: m, Transport: ft})
		a := webhookSpec("a")
		a.Delay = time.Minute
		a.Mounts = []string{"inbox", "hr"}
		b := webhookSpec("b")
		b.Delay = time.Minute
		d.Update([]Spec{a, b})
		d.Notify(upload("alice", "/x")) // inbox: a and b
		hr := upload("alice", "/y")
		hr.Mount = "hr"
		d.Notify(hr) // hr: a and b
		synctest.Wait()

		// a narrows its mounts and moves; b is removed; c is new.
		a2 := a
		a2.Mounts = []string{"inbox"}
		a2.Webhook = &Webhook{URL: "https://new.example/x", Secret: a.Webhook.Secret, Timeout: a.Webhook.Timeout}
		c := webhookSpec("c")
		d.Update([]Spec{a2, c})
		d.Notify(upload("bob", "/z")) // a and c
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))

		mu.Lock()
		defer mu.Unlock()
		want := map[string]int{"new.example fs.upload": 2, "receiver.example fs.upload": 1}
		gotCount := map[string]int{}
		for _, u := range urls {
			gotCount[u]++
		}
		if fmt.Sprint(gotCount) != fmt.Sprint(want) {
			t.Errorf("deliveries %v, want %v", gotCount, want)
		}
		// hr for a (filtered again), x and y for b (removed).
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 3 {
			t.Errorf("dropped = %v", v)
		}
	})
}

// A reload that narrows a hook's mounts drops the event its worker holds
// in its delay when the delay ends, not only the queued ones.
func TestUpdateRefiltersHeldEvent(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) { return reply(http.StatusOK), nil }}
		d := New(Options{Metrics: m, Transport: ft})
		s := webhookSpec("notify")
		s.Delay = time.Minute
		s.Mounts = []string{"inbox", "hr"}
		d.Update([]Spec{s})
		hr := upload("alice", "/salaries.pdf")
		hr.Mount = "hr"
		d.Notify(hr) // held by the worker for its delay
		d.Notify(upload("alice", "/x.pdf"))
		synctest.Wait()
		narrowed := s
		narrowed.Mounts = []string{"inbox"}
		d.Update([]Spec{narrowed})
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if ft.count() != 1 || !bytes.Contains(ft.body[0], []byte("/x.pdf")) {
			t.Errorf("%d deliveries, want only /x.pdf", ft.count())
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 1 {
			t.Errorf("dropped = %v", v)
		}
	})
}

// A hook removed while a worker holds an event in its delay drops the
// event at once: a hook left out by a reload never runs again.
func TestRemovedDuringDelay(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		ft := &fakeTransport{fn: func(int, *http.Request) (*http.Response, error) { return reply(http.StatusOK), nil }}
		d := New(Options{Metrics: m, Transport: ft})
		s := webhookSpec("notify")
		s.Delay = time.Hour
		d.Update([]Spec{s})
		d.Notify(upload("alice", "/held")) // held by the worker
		d.Notify(upload("alice", "/queued"))
		synctest.Wait()
		d.Update(nil)
		synctest.Wait()
		if n := d.QueueLength(); n != 0 {
			t.Errorf("QueueLength = %d after removal", n)
		}
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		d.Close(time.Now().Add(time.Second))
		if ft.count() != 0 {
			t.Errorf("%d deliveries after the hook was removed", ft.count())
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 2 {
			t.Errorf("dropped = %v", v)
		}
	})
}

func TestCloseSkipsDelaysAndDropsTheRest(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		m := obs.NewMetrics("test")
		log, logs := testLog()
		block := make(chan struct{})
		ft := &fakeTransport{fn: func(n int, r *http.Request) (*http.Response, error) {
			if n == 1 {
				return reply(http.StatusOK), nil
			}
			select { // the second delivery hangs until the request is cancelled
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-block:
				return reply(http.StatusOK), nil
			}
		}}
		d := New(Options{Log: log, Metrics: m, Transport: ft})
		s := webhookSpec("notify")
		s.Delay = time.Hour
		s.Webhook.Timeout = time.Hour
		d.Update([]Spec{s})
		for i := range 3 {
			d.Notify(upload("alice", fmt.Sprintf("/f%d", i)))
		}
		synctest.Wait()
		start := time.Now()
		d.Close(time.Now().Add(5 * time.Second))
		if el := time.Since(start); el != 5*time.Second {
			t.Errorf("Close took %v, want the 5 s deadline", el)
		}
		close(block)
		if d.Wants("fs.upload", false, "inbox", "x") {
			t.Error("Wants after Close")
		}
		d.Notify(upload("alice", "/late"))
		// f0 delivered at once (delay skipped); f1 hung and its attempt was
		// cancelled at the deadline, f2 was still queued, /late came after
		// Close: all three dropped.
		if v := value(m, `gosftpd_hook_deliveries_total{result="ok",type="webhook"}`); v != 1 {
			t.Errorf("ok = %v", v)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="webhook"}`); v != 3 {
			t.Errorf("dropped = %v", v)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="failed",type="webhook"}`); v != 0 {
			t.Errorf("failed = %v", v)
		}
		if !strings.Contains(logs.String(), "path=/f2") {
			t.Errorf("a dropped event is not logged for replay:\n%s", logs)
		}
	})
}

func TestNilDispatcher(t *testing.T) {
	t.Parallel()
	var d *Dispatcher
	if d.Wants("fs.upload", false, "inbox", "a") {
		t.Error("nil Wants")
	}
	d.Notify(upload("alice", "/a"))
	if d.QueueLength() != 0 {
		t.Error("nil QueueLength")
	}
}
