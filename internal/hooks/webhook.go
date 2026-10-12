// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Webhook delivery (ADR 0010).
const (
	maxAttempts   = 5
	maxRetryAfter = 120 * time.Second
	bodyCap       = 4 << 10 // of a response, read and discarded
)

// backoff is the wait before attempts 2 to 5.
var backoff = [...]time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 120 * time.Second}

// retryDelay returns the wait after a failed attempt, ±20 %.
func retryDelay(attempt int) time.Duration {
	d := backoff[min(attempt, len(backoff))-1]
	return time.Duration(float64(d) * (0.8 + 0.4*mrand.Float64())) //nolint:gosec // jitter, not a secret
}

// Sign returns the X-Gosftpd-Signature value: lowercase hex of HMAC-SHA256
// with the secret over DELIVERY "." TIMESTAMP "." BODY.
func Sign(secret []byte, delivery, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(delivery))
	m.Write([]byte{'.'})
	m.Write([]byte(timestamp))
	m.Write([]byte{'.'})
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func newClient(opts Options) *http.Client {
	tr := opts.Transport
	if tr == nil {
		roots := opts.RootCAs
		if roots == nil {
			// Loaded now: Go would read them at the first handshake,
			// after a sandbox may have hidden them.
			roots, _ = x509.SystemCertPool()
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		tr = t
	}
	return &http.Client{
		Transport: tr,
		// A redirect is a failure: the receiver is configured, not found.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// newDeliveryID returns 32 lowercase hex characters.
func newDeliveryID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// runWebhook posts one event with retries: at least once while gosftpd
// runs.
func (r *runner) runWebhook(s *Spec, it *item) string {
	e := it.ev
	u, err := url.Parse(s.Webhook.URL)
	if err != nil { // checked by the configuration
		return resultFailed
	}
	target := u.Scheme + "://" + u.Host
	log := r.d.log.With("hook", r.name, "event", e.Name, "user", e.User, "url", target)
	id := newDeliveryID()
	for attempt := 1; ; attempt++ {
		if r.isRemoved() { // a reload removed the hook: no new attempt
			return resultDropped
		}
		if attempt > 1 {
			r.d.metrics.HookRetry()
		}
		s = r.spec.Load() // a reload may change the URL or the secret between attempts
		status, retryAfter, reason := r.attempt(s, it, id)
		if status/100 == 2 {
			log.Debug("webhook delivered", "status", status, "attempts", attempt, "delivery", id)
			return resultOK
		}
		if r.d.killed.Load() { // the attempt was cancelled at shutdown
			r.logDropped(it, "shutdown")
			return resultDropped
		}
		retry := status == 0 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
		if !retry || attempt == maxAttempts {
			log.Warn("webhook failed", "reason", reason, "attempts", attempt, "delivery", id)
			return resultFailed
		}
		log.Debug("webhook attempt failed", "reason", reason, "attempt", attempt, "delivery", id)
		wait := r.d.retryDelay(attempt)
		if retryAfter > 0 {
			wait = min(retryAfter, maxRetryAfter)
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-r.gone: // a reload removed the hook meanwhile
			t.Stop()
			return resultDropped
		case <-r.d.killCtx.Done():
			t.Stop()
			r.logDropped(it, "shutdown")
			return resultDropped
		}
	}
}

// attempt posts once. It returns the status (0 for no response), the
// wait the receiver asked for, and a reason for the log that never holds
// the URL's path or query, which may be a token.
func (r *runner) attempt(s *Spec, it *item, id string) (status int, retryAfter time.Duration, reason string) {
	ctx, cancel := context.WithTimeout(r.d.killCtx, s.Webhook.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Webhook.URL, bytes.NewReader(it.ev.Line))
	if err != nil {
		return 0, 0, "invalid request"
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "gosftpd")
	req.Header.Set("X-Gosftpd-Event", it.ev.Name)
	req.Header.Set("X-Gosftpd-Delivery", id)
	req.Header.Set("X-Gosftpd-Timestamp", ts)
	req.Header.Set("X-Gosftpd-Signature", Sign(s.Webhook.Secret, id, ts, it.ev.Line))
	resp, err := r.d.client.Do(req)
	if err != nil {
		return 0, 0, scrub(err, req.URL)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyCap))
	_ = resp.Body.Close()
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), "status " + strconv.Itoa(resp.StatusCode)
}

// scrub returns the cause of a failed request without the URL: net/http
// puts the whole URL into its errors. As a second guard, any trace of the
// path or query left in the cause is removed.
func scrub(err error, u *url.URL) string {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	msg := err.Error()
	for _, secret := range []string{u.RawQuery, u.EscapedPath(), u.Path} {
		if secret != "" && secret != "/" {
			msg = strings.ReplaceAll(msg, secret, "…")
		}
	}
	return msg
}

// parseRetryAfter reads seconds or an HTTP date; 0 when absent or past.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(min(n, int(maxRetryAfter/time.Second))) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}
