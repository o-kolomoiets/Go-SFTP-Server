// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
)

// proxyHeader is the v2 header of the client src that connected to
// 192.0.2.1:22.
func proxyHeader(t *testing.T, src string) []byte {
	t.Helper()
	b, err := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP(src), Port: 51000}, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}).Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// loginWith connects to addr, sends header first if any, and logs in.
func loginWith(t *testing.T, addr string, header []byte, user string, key ssh.Signer) error {
	t.Helper()
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if header != nil {
		if _, err := c.Write(header); err != nil {
			return err
		}
	}
	conn, chans, reqs, err := ssh.NewClientConn(c, addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	return ssh.NewClient(conn, chans, reqs).Close()
}

// proxyConfig returns a configuration that serves one mount to alice,
// with server settings extra.
func proxyConfig(t *testing.T, dir, extra string, alice ssh.Signer) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	return `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
` + extra + `
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
`
}

// server.trusted_proxies through serve: recorded in server.start and
// server.reload, reloadable, an invalid value fails the reload.
func TestServeTrustedProxies(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	alice := newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, proxyConfig(t, dir, `trusted_proxies = ["127.0.0.1"]`, alice))
	ts := startServe(t, "--config", path)
	stdout := ts.stdout.String

	start := events(t, stdout(), "server.start")
	if len(start) != 1 || start[0]["trusted_proxies"] != "127.0.0.1/32" {
		t.Fatalf("server.start = %v", start)
	}
	// From the trusted 127.0.0.1 a connection begins with a header.
	if err := loginWith(t, ts.addr, nil, "alice", alice); err == nil {
		t.Error("a trusted peer logged in without a header")
	}
	if err := loginWith(t, ts.addr, proxyHeader(t, "203.0.113.7"), "alice", alice); err != nil {
		t.Fatalf("login with a header: %v", err)
	}
	waitForAudit(t, stdout, `"remote_addr":"203.0.113.7:51000","local_addr":"192.0.2.1:22","proxy_addr":"127.0.0.1:`)

	writeFile(t, path, proxyConfig(t, dir, `trusted_proxies = ["10.0.0.5", "2001:db8::/64"]`, alice))
	ev := ts.reload(t, stdout)
	if ev["result"] != "ok" || ev["trusted_proxies"] != "10.0.0.5/32,2001:db8::/64" || ev["restart_required"] != nil {
		t.Errorf("server.reload = %v", ev)
	}
	if err := loginWith(t, ts.addr, nil, "alice", alice); err != nil {
		t.Errorf("a direct login after 127.0.0.1 was no longer trusted: %v", err)
	}
	if err := loginWith(t, ts.addr, proxyHeader(t, "203.0.113.7"), "alice", alice); err == nil {
		t.Error("a header from a peer that is no longer trusted was accepted")
	}

	writeFile(t, path, proxyConfig(t, dir, `trusted_proxies = ["0.0.0.0/0"]`, alice))
	if ev := ts.reload(t, stdout); ev["result"] != "error" || ev["reason"] != "config" {
		t.Errorf("server.reload of /0 = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), `server.trusted_proxies: \"0.0.0.0/0\" holds every address`) {
		t.Errorf("the failed reload does not say why:\n%s", ts.stderr.String())
	}
	writeFile(t, path, proxyConfig(t, dir, "", alice))
	if ev := ts.reload(t, stdout); ev["result"] != "ok" || ev["trusted_proxies"] != nil {
		t.Errorf("server.reload without trusted proxies = %v", ev)
	}
}

// waitForAudit waits until the audit output has want.
func waitForAudit(t *testing.T, audit func() string, want string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(audit(), want); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the audit log lacks %s:\n%s", want, audit())
		}
	}
}
