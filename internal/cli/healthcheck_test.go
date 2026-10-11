// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// fakeServer accepts connections on 127.0.0.1 and answers each with
// answer; it returns the address.
func fakeServer(t *testing.T, answer func(net.Conn)) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { ln.Close(); <-done })
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			answer(c)
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func send(s string) func(net.Conn) {
	return func(c net.Conn) { _, _ = c.Write([]byte(s)) }
}

// healthcheck runs gosftpd healthcheck and checks that a failure prints
// exactly one line on stderr.
func healthcheck(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	code, stdout, stderr := execute(t, append([]string{"healthcheck"}, args...)...)
	if code != exitOK && strings.Count(stderr, "\n") != 1 {
		t.Errorf("%q: stderr is not one line: %q", args, stderr)
	}
	if code != exitOK && code != exitFailure {
		t.Errorf("%q: exit %d, want 0 or 1", args, code)
	}
	return code, stdout, stderr
}

func TestHealthcheckSSH(t *testing.T) {
	isolate(t)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	hang := make(chan struct{})
	defer close(hang) // before the servers' cleanups wait for their handlers
	for _, tt := range []struct {
		name   string
		answer func(net.Conn)
		args   []string
		ok     bool
		out    string
	}{
		{"banner", send("SSH-2.0-gosftpd\r\n"), nil, true, "sent an SSH banner"},
		{"banner in pieces", func(c net.Conn) {
			for _, p := range []string{"SS", "H-2", ".0-x\r\n"} {
				_, _ = c.Write([]byte(p))
			}
		}, nil, true, "sent an SSH banner"},
		{"lines before the banner", send("hello\r\nworld\r\nSSH-2.0-x\r\n"), nil, true, "sent an SSH banner"},
		{"closed: alive", func(net.Conn) {}, nil, true, "refuses new connections"},
		{"closed: not ready", func(net.Conn) {}, []string{"--ready"}, false, "refuses new connections"},
		{"silent", func(net.Conn) { <-hang }, []string{"--timeout", "200ms"}, false, "no SSH banner within 200ms"},
		{"SSH 1", send("SSH-1.5-old\r\n"), nil, false, `answered "SSH-1.5-old`},
		{"HTTP", send("HTTP/1.1 400 Bad Request\r\n\r\n"), nil, false, "without an SSH banner"},
		{"too long", send(strings.Repeat("x", 300)), nil, false, "first 255 bytes"},
	} {
		addr := fakeServer(t, tt.answer)
		code, stdout, stderr := healthcheck(t, append([]string{"--address", addr}, tt.args...)...)
		if (code == exitOK) != tt.ok || !strings.Contains(stdout+stderr, tt.out) {
			t.Errorf("%s: exit %d: %q %q", tt.name, code, stdout, stderr)
		}
	}
}

func TestHealthcheckAddress(t *testing.T) {
	isolate(t)
	t.Chdir(t.TempDir())
	addr := fakeServer(t, send("SSH-2.0-x\r\n"))
	_, port, _ := net.SplitHostPort(addr)

	// A wildcard address is checked on loopback.
	for _, a := range []string{":" + port, "0.0.0.0:" + port, "[::]:" + port} {
		if code, _, stderr := healthcheck(t, "--address", a); code != exitOK {
			t.Errorf("--address %s: %s", a, stderr)
		}
	}
	// Precedence: --address, $GOSFTPD_LISTEN, server.listen, :2022.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, cfg, "[server]\nlisten = [\"127.0.0.1:"+port+"\", \"127.0.0.1:1\"]\nunknown = 1\n[bogus]\nx = 1\n")
	getenv := func(env map[string]string) func(string) string { return func(k string) string { return env[k] } }
	for _, tt := range []struct {
		o    healthOptions
		env  map[string]string
		want string
	}{
		{healthOptions{address: "127.0.0.1:7", config: cfg}, map[string]string{config.EnvListen: "127.0.0.1:8"}, "127.0.0.1:7"},
		{healthOptions{config: cfg}, map[string]string{config.EnvListen: "127.0.0.1:8,127.0.0.1:9"}, "127.0.0.1:8"},
		{healthOptions{config: cfg}, nil, "127.0.0.1:" + port},
		{healthOptions{}, map[string]string{config.EnvConfig: cfg}, "127.0.0.1:" + port},
		{healthOptions{}, nil, ":2022"},
	} {
		got, err := healthAddress(tt.o, getenv(tt.env))
		if err != nil || got != tt.want {
			t.Errorf("healthAddress(%+v, %v) = %q, %v; want %q", tt.o, tt.env, got, err, tt.want)
		}
	}
	if code, stdout, _ := healthcheck(t, "--config", cfg); code != exitOK || !strings.Contains(stdout, addr) {
		t.Errorf("--config: exit %d: %s", code, stdout)
	}
	// A file that is not TOML cannot name the address.
	writeFile(t, cfg, "[server\n")
	if code, _, stderr := healthcheck(t, "--config", cfg); code != exitFailure || !strings.Contains(stderr, "pass --address") {
		t.Errorf("broken file: exit %d: %s", code, stderr)
	}
	for _, a := range []string{"127.0.0.1:0", "127.0.0.1", "127.0.0.1:70000", "x:y"} {
		if code, _, stderr := healthcheck(t, "--address", a); code != exitFailure || !strings.Contains(stderr, "port from 1 to 65535") {
			t.Errorf("--address %s: exit %d: %s", a, code, stderr)
		}
	}
	if code, _, stderr := healthcheck(t, "--config", filepath.Join(dir, "missing.toml")); code != exitFailure || !strings.Contains(stderr, "--config") {
		t.Errorf("missing --config: exit %d: %s", code, stderr)
	}
}

func TestHealthcheckURL(t *testing.T) {
	isolate(t)
	// The check never goes through a proxy.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready\n")) })
	mux.HandleFunc("/starting", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("starting\n"))
	})
	mux.Handle("/moved", http.RedirectHandler("/readyz", http.StatusFound))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if code, stdout, stderr := healthcheck(t, "--url", srv.URL+"/readyz"); code != exitOK || !strings.Contains(stdout, "200 OK") {
		t.Errorf("200: exit %d: %s %s", code, stdout, stderr)
	}
	if code, _, stderr := healthcheck(t, "--url", srv.URL+"/starting"); code != exitFailure || !strings.Contains(stderr, "503 Service Unavailable: starting") {
		t.Errorf("503: exit %d: %s", code, stderr)
	}
	// A redirect is not followed.
	if code, _, stderr := healthcheck(t, "--url", srv.URL+"/moved"); code != exitFailure || !strings.Contains(stderr, "302") {
		t.Errorf("302: exit %d: %s", code, stderr)
	}
}

// Every usage error exits with 1: Docker reserves 2 for HEALTHCHECK.
func TestHealthcheckUsage(t *testing.T) {
	isolate(t)
	for _, args := range [][]string{
		{"--bogus"},
		{"extra"},
		{"--timeout", "0s"},
		{"--timeout", "soon"},
		{"--url", "http://127.0.0.1:1/readyz", "--ready"},
		{"--url", "http://127.0.0.1:1/readyz", "--address", "127.0.0.1:22"},
		{"--url", "ftp://example/"},
		{"--url", "/readyz"},
	} {
		if code, _, stderr := healthcheck(t, args...); code != exitFailure || stderr == "" || strings.HasPrefix(stderr, "Error:") {
			t.Errorf("%q: exit %d: %q", args, code, stderr)
		}
	}
	if code, stdout, _ := healthcheck(t, "--help"); code != exitOK || !strings.Contains(stdout, "Docker reserves 2") {
		t.Errorf("--help: exit %d", code)
	}
}

func TestBanner(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]bannerState{
		"":                        bannerMore,
		"S":                       bannerMore,
		"SSH-2.0":                 bannerMore,
		"SSH-2.0-":                bannerFound,
		"SSH-2.0-gosftpd\r\n":     bannerFound,
		"motd\r\n":                bannerMore,
		"motd\r\nSSH-2.0-x":       bannerFound,
		"SSH-1.99-x\r\n":          bannerWrong,
		"SSH-1":                   bannerWrong,
		"motd\r\nSSH-2.1-x":       bannerWrong,
		"motd\r\nnot SSH-2.0-x\n": bannerMore,
	} {
		if got := banner([]byte(in)); got != want {
			t.Errorf("banner(%q) = %d, want %d", in, got, want)
		}
	}
}
