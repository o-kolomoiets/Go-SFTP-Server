// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// delivery is a webhook request as a receiver saw it.
type delivery struct {
	event, id string
	body      map[string]any
}

// receiver is a webhook receiver that checks every signature itself, over
// the raw body, as docs/hooks.md tells receivers to.
type receiver struct {
	t      *testing.T
	secret []byte
	srv    *httptest.Server
	mu     sync.Mutex
	got    []delivery
}

var deliveryID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func newReceiver(t *testing.T, secret string) *receiver {
	t.Helper()
	r := &receiver{t: t, secret: []byte(secret)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("receiver: %v", err)
			return
		}
		id, ts := req.Header.Get("X-Gosftpd-Delivery"), req.Header.Get("X-Gosftpd-Timestamp")
		m := hmac.New(sha256.New, r.secret)
		m.Write([]byte(id + "." + ts + "."))
		m.Write(raw)
		want := "sha256=" + hex.EncodeToString(m.Sum(nil))
		if !hmac.Equal([]byte(req.Header.Get("X-Gosftpd-Signature")), []byte(want)) {
			t.Errorf("bad signature on %s", raw)
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		if !deliveryID.MatchString(id) || req.Header.Get("User-Agent") != "gosftpd" || req.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers %v", req.Header)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("body %q: %v", raw, err)
		}
		r.mu.Lock()
		r.got = append(r.got, delivery{event: req.Header.Get("X-Gosftpd-Event"), id: id, body: body})
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// wait returns the deliveries once there are n, and fails on more.
func (r *receiver) wait(n int) []delivery {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.mu.Lock()
		got := append([]delivery(nil), r.got...)
		r.mu.Unlock()
		if len(got) >= n || time.Now().After(deadline) {
			time.Sleep(200 * time.Millisecond) // anything beyond n arrives too
			r.mu.Lock()
			got = append([]delivery(nil), r.got...)
			r.mu.Unlock()
			if len(got) != n {
				for _, d := range got {
					r.t.Logf("delivery %s %v", d.event, d.body)
				}
				r.t.Fatalf("%d deliveries, want %d", len(got), n)
			}
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func put(t *testing.T, c *sftp.Client, name, data string) {
	t.Helper()
	f, err := c.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestServeWebhook: deliveries carry the final name and the mount, a
// temp-file upload gives one delivery, and every signature checks out.
func TestServeWebhook(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	for _, d := range []string{"inbox", "atomic"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "3f9a1c6e2b7d4f8a0c5e9b1d6a3f7c2e8b4d0a6f1c9e5b7a2d8f4c0e6b3a9d1f"
	if err := os.WriteFile(filepath.Join(dir, "hook.secret"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rcv := newReceiver(t, secret)
	partner, admin := newSigner(t), newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.inbox]
path = "`+filepath.ToSlash(filepath.Join(dir, "inbox"))+`"
[mounts.atomic]
path = "`+filepath.ToSlash(filepath.Join(dir, "atomic"))+`"
atomic_uploads = true
[users.partner]
authorized_keys = ["`+authorizedKey(partner)+`"]
access = { inbox = "upload" }
[users.admin]
authorized_keys = ["`+authorizedKey(admin)+`"]
access = { inbox = "full", atomic = "full" }
[[hooks]]
name = "notify"
on = ["fs.upload"]
exclude = ["*.filepart", "*.partial"]
webhook = { url = "`+rcv.srv.URL+`/hooks/secret-token", secret_file = "hook.secret" }
`)
	ts := startServe(t, "--config", path)

	conn, err := ts.login("partner", partner)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	put(t, c, "/report.pdf", "first")
	put(t, c, "/report.pdf", "second") // on_conflict = "rename"
	put(t, c, "/big.pdf.filepart", "big")
	if err := c.PosixRename("/big.pdf.filepart", "/big.pdf"); err != nil {
		t.Fatal(err)
	}
	if err := c.PosixRename("/big.pdf", "/big-2.pdf"); err != nil { // a later rename: not an upload
		t.Fatal(err)
	}

	aconn, err := ts.login("admin", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer aconn.Close()
	ac, err := sftp.NewClient(aconn)
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	put(t, ac, "/atomic/a.pdf", "atomic")

	got := rcv.wait(4)
	want := []struct{ event, path, final, mount string }{
		{"fs.upload", "/report.pdf", "/report.pdf", "inbox"},
		{"fs.upload", "/report.pdf", "/report (1).pdf", "inbox"},
		{"fs.rename", "/big.pdf.filepart", "/big.pdf", "inbox"},
		{"fs.upload", "/atomic/a.pdf", "/atomic/a.pdf", "atomic"},
	}
	ids := map[string]bool{}
	for i, w := range want {
		b := got[i].body
		if got[i].event != w.event || b["event"] != w.event || b["path"] != w.path || b["final_path"] != w.final || b["mount"] != w.mount || b["result"] != "ok" {
			t.Errorf("delivery %d = %s %v, want %+v", i, got[i].event, b, w)
		}
		ids[got[i].id] = true
	}
	if got[2].body["uploaded"] != true {
		t.Errorf("the rename that completes the upload is not marked: %v", got[2].body)
	}
	if got[0].body["user"] != "partner" || got[0].body["conn_id"] == nil || got[0].body["schema"] != float64(1) {
		t.Errorf("payload without the session context: %v", got[0].body)
	}
	if len(ids) != 4 {
		t.Errorf("delivery IDs repeat: %v", ids)
	}
	if strings.Contains(ts.stderr.String(), "secret-token") {
		t.Errorf("the URL's token is in the log:\n%s", ts.stderr.String())
	}
}
