// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
)

// serveDetailsFields are the fields of the line of serve --print-details,
// in their order (ADR 0013): first those it shares with --ephemeral.
var serveDetailsFields = []string{"host", "port", "host_key_fingerprint", "known_hosts", "pid", "version", "listen", "host_keys", "addresses"}

// detailsConfig writes a configuration in dir that serves dir/data to
// alice, with [server] settings server and [audit] settings audit, and
// returns its path. Unless server names host_keys, the host key is
// generated as dir/state/host_key; unless audit is given, the audit log
// goes to dir/audit/audit.jsonl.
func detailsConfig(t *testing.T, dir, server, audit string, alice ssh.Signer) string {
	t.Helper()
	for _, d := range []string{"data", "audit", "state"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(server, "host_keys") {
		server = "host_keys = [\"state/host_key\"]\nhost_key_auto_generate = true\n" + server
	}
	if audit == "" {
		audit = `output = "audit/audit.jsonl"`
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
`+server+`
[audit]
`+audit+`
[mounts.data]
path = "`+filepath.ToSlash(filepath.Join(dir, "data"))+`"
[users.alice]
authorized_keys = ["`+authorizedKey(alice)+`"]
access = { data = "full" }
`)
	return path
}

// auditFile returns a function that reads the audit log at path.
func auditFile(t *testing.T, path string) func() string {
	t.Helper()
	return func() string {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return string(data)
	}
}

// stubInterfaces makes the network interfaces hold addrs, or fail with
// err.
func stubInterfaces(t *testing.T, err error, addrs ...string) {
	t.Helper()
	var list []net.Addr
	for _, a := range addrs {
		ip, ipNet, perr := net.ParseCIDR(a)
		if perr != nil {
			t.Fatal(perr)
		}
		ipNet.IP = ip
		list = append(list, ipNet)
	}
	saved := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) { return list, err }
	t.Cleanup(func() { interfaceAddrs = saved })
}

// startWith runs the command line args, which serves, as startRun does,
// with stdin, if not nil, as its stdin. With --print-details it waits for
// the details line, and otherwise for the banner's listen address.
func startWith(t *testing.T, stdin *os.File, args ...string) *testServer {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	hup := make(chan os.Signal, 1)
	ctx = context.WithValue(ctx, hupKey{}, (<-chan os.Signal)(hup))
	if stdin != nil {
		ctx = context.WithValue(ctx, stdinKey{}, stdin)
	}
	ts := &testServer{stdout: &lockedBuffer{}, stderr: &lockedBuffer{}, hup: hup, cancel: cancel, done: make(chan int, 1)}
	go func() { ts.done <- run(ctx, args, ts.stdout, ts.stderr) }()
	t.Cleanup(func() { ts.stop(t) })

	details := slices.Contains(args, "--print-details")
	addrRE := regexp.MustCompile(`listen:\s+(127\.0\.0\.1:\d+|\[::1\]:\d+)`)
	deadline := time.Now().Add(10 * time.Second)
	for ts.addr == "" {
		switch {
		case details && strings.Contains(ts.stdout.String(), "\n"):
			d := decodeServeDetails(t, ts.stdout.String())
			ts.addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(d.Port))
		case !details:
			if m := addrRE.FindStringSubmatch(ts.stderr.String()); m != nil {
				ts.addr = m[1]
			}
		}
		select {
		case code := <-ts.done:
			ts.cancel, ts.done = nil, nil // stop must not wait for it again
			t.Fatalf("serve exited with %d:\nstdout: %s\nstderr:\n%s", code, ts.stdout.String(), ts.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve does not serve:\nstdout: %s\nstderr:\n%s", ts.stdout.String(), ts.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ts
}

// exited waits until serve exits by itself and returns its exit code.
func (ts *testServer) exited(t *testing.T) int {
	t.Helper()
	select {
	case code := <-ts.done:
		ts.cancel()
		ts.cancel, ts.done = nil, nil // stop must not wait for it again
		return code
	case <-time.After(time.Minute):
		t.Fatalf("serve does not stop:\n%s", ts.stderr.String())
	}
	return 0
}

// decodeServeDetails checks that out is exactly one line, a JSON object
// with the fields of serveDetailsFields in that order, port and pid
// numbers, listen, host_keys and addresses arrays and the others strings,
// and decodes it.
func decodeServeDetails(t *testing.T, out string) serveDetails {
	t.Helper()
	line, rest, _ := strings.Cut(out, "\n")
	if rest != "" {
		t.Fatalf("more than one line on stdout:\n%s", out)
	}
	keys := objectKeys(t, line, func(key string, v any) bool {
		switch key {
		case "port", "pid":
			_, ok := v.(json.Number)
			return ok
		case "listen", "host_keys", "addresses":
			_, ok := v.([]any)
			return ok
		}
		_, ok := v.(string)
		return ok
	})
	if !slices.Equal(keys, serveDetailsFields) {
		t.Errorf("fields %v, want %v", keys, serveDetailsFields)
	}
	var d serveDetails
	if err := json.Unmarshal([]byte(line), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// objectKeys returns the keys of the JSON object line in their order,
// checking each value with ok.
func objectKeys(t *testing.T, line string, ok func(key string, v any) bool) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not a JSON object: %q", line)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		key, _ := tok.(string)
		keys = append(keys, key)
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if !ok(key, v) {
			t.Errorf("%s = %#v: wrong type", key, v)
		}
	}
	return keys
}

// decodeFailure checks that out is exactly one line, the JSON object of a
// failed start, and decodes it.
func decodeFailure(t *testing.T, out string) startFailure {
	t.Helper()
	line, rest, _ := strings.Cut(out, "\n")
	if rest != "" {
		t.Fatalf("more than one line on stdout:\n%s", out)
	}
	keys := objectKeys(t, line, func(_ string, v any) bool { _, ok := v.(string); return ok })
	if want := []string{"error", "kind", "address"}; !slices.Equal(keys, want) {
		t.Errorf("fields %v, want %v", keys, want)
	}
	var f startFailure
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// publicKey reads the public key of the private key file path.
func publicKey(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	s, err := hostkey.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}

// knownHostsCallback checks host keys against the known_hosts line.
func knownHostsCallback(t *testing.T, line string) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeFile(t, path, line+"\n")
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

// detailsLogin logs in to addr as alice, checking the host key with cb;
// algos, if given, are the host key algorithms to accept.
func detailsLogin(t *testing.T, addr string, alice ssh.Signer, cb ssh.HostKeyCallback, algos ...string) (*sftpConn, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(alice)}, HostKeyCallback: cb, HostKeyAlgorithms: algos, Timeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sc := &sftpConn{Client: c, conn: conn}
	t.Cleanup(sc.Close)
	return sc, nil
}

// TestServePrintDetails: the line describes the first listener and the
// first host key, lists every listener, every host key and the addresses
// of the interfaces, and is all there is on stdout; the banner is not
// printed, so with --log-format json every line on stderr is JSON. Not
// parallel: it replaces interfaceAddrs.
func TestServePrintDetails(t *testing.T) {
	isolate(t)
	stubInterfaces(t, nil, "192.0.2.10/24", "127.0.0.1/8", "fe80::1/64", "2001:db8::10/64", "192.0.2.10/24", "169.254.7.7/16", "fd00::5/8")
	dir := t.TempDir()
	alice := newSigner(t)
	// Two host keys, generated here: host_key_auto_generate makes ed25519
	// keys only, and a configuration has one key per type at most.
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0", "127.0.0.1:0"]
host_keys = ["state/host_key", "state/host_key_ecdsa"]`, "", alice)
	if _, err := hostkey.Generate(filepath.Join(dir, "state", "host_key")); err != nil {
		t.Fatal(err)
	}
	if _, err := hostkey.GenerateType(filepath.Join(dir, "state", "host_key_ecdsa"), hostkey.TypeECDSA); err != nil {
		t.Fatal(err)
	}
	ed := publicKey(t, filepath.Join(dir, "state", "host_key"))
	ec := publicKey(t, filepath.Join(dir, "state", "host_key_ecdsa"))

	ts := startWith(t, nil, "serve", "--allow-root", "--print-details", "--config", path, "--log-format", "json")
	d := decodeServeDetails(t, ts.stdout.String())
	if d.Host != "127.0.0.1" || len(d.Listen) != 2 || d.Listen[0] != net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) ||
		d.Listen[1] == d.Listen[0] || !strings.HasPrefix(d.Listen[1], "127.0.0.1:") {
		t.Errorf("host %q, port %d, listen %q", d.Host, d.Port, d.Listen)
	}
	want := []hostKeyDetails{{"ssh-ed25519", ssh.FingerprintSHA256(ed)}, {"ecdsa-sha2-nistp256", ssh.FingerprintSHA256(ec)}}
	if !slices.Equal(d.HostKeys, want) {
		t.Errorf("host_keys %+v, want %+v", d.HostKeys, want)
	}
	if d.HostKeyFingerprint != want[0].Fingerprint || d.KnownHosts != hostkey.KnownHostsLine(d.Host, d.Port, ed) {
		t.Errorf("host_key_fingerprint %q, known_hosts %q", d.HostKeyFingerprint, d.KnownHosts)
	}
	if d.PID != os.Getpid() || d.Version != version.Get().Version {
		t.Errorf("pid %d, version %q", d.PID, d.Version)
	}
	if want := []string{"192.0.2.10", "2001:db8::10", "fd00::5"}; !slices.Equal(d.Addresses, want) {
		t.Errorf("addresses %q, want %q", d.Addresses, want)
	}

	// The line is enough to connect to the first listener, as OpenSSH
	// does: it asks for the key type that known_hosts has.
	for _, addr := range d.Listen {
		c, err := detailsLogin(t, addr, alice, knownHostsCallback(t, d.KnownHosts), ssh.KeyAlgoED25519)
		if addr == d.Listen[0] && err != nil {
			t.Fatalf("login with the known_hosts line: %v", err)
		}
		if addr != d.Listen[0] && (err == nil || !strings.Contains(err.Error(), "knownhosts: key is unknown")) {
			t.Errorf("%s is not in the known_hosts line, which names the first listener only: %v", addr, err)
		}
		if err == nil {
			if err := putFile(c, "/a.txt", "a"); err != nil {
				t.Fatal(err)
			}
			c.Close()
		}
	}
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, ts.stderr.String())
	}
	if again := decodeServeDetails(t, ts.stdout.String()); !slices.Equal(again.Listen, d.Listen) {
		t.Errorf("stdout changed: %+v", again)
	}
	logs := ts.stderr.String()
	for l := range strings.SplitSeq(logs, "\n") {
		if l != "" && !json.Valid([]byte(l)) {
			t.Errorf("not a JSON line on stderr: %q", l)
		}
	}
	if strings.Contains(logs, "connect: ") || strings.Contains(logs, "listen: ") {
		t.Errorf("the banner was printed:\n%s", logs)
	}
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))()
	for _, ev := range []string{"server.start", "fs.upload", "server.stop"} {
		if len(events(t, audit, ev)) != 1 {
			t.Errorf("no %s in the audit log:\n%s", ev, audit)
		}
	}
	if evs := events(t, audit, "server.start"); len(evs) == 1 && evs[0]["listen"] != strings.Join(d.Listen, ",") {
		t.Errorf("server.start = %v, listen %q", evs[0], d.Listen)
	}
}

// TestServePrintDetailsUnspecified: for an unspecified listen address,
// host is this machine's name, as in the banner, and known_hosts names it
// and every address of the interfaces. Not parallel: it replaces
// interfaceAddrs.
func TestServePrintDetailsUnspecified(t *testing.T) {
	isolate(t)
	stubInterfaces(t, nil, "192.0.2.10/24", "2001:db8::10/64", "::1/128")
	dir := t.TempDir()
	alice := newSigner(t)
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", alice)
	ts := startWith(t, nil, "serve", "--allow-root", "--print-details", "--config", path, "--listen", ":0")
	d := decodeServeDetails(t, ts.stdout.String())

	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "localhost"
	}
	host, port, err := net.SplitHostPort(d.Listen[0])
	if d.Host != name || len(d.Listen) != 1 || err != nil || !net.ParseIP(host).IsUnspecified() || port != strconv.Itoa(d.Port) {
		t.Errorf("host %q, port %d, listen %q; this machine is %q", d.Host, d.Port, d.Listen, name)
	}
	if want := []string{"192.0.2.10", "2001:db8::10"}; !slices.Equal(d.Addresses, want) {
		t.Errorf("addresses %q, want %q", d.Addresses, want)
	}
	pub := publicKey(t, filepath.Join(dir, "state", "host_key"))
	p := strconv.Itoa(d.Port)
	if want := knownhosts.Normalize(net.JoinHostPort(name, p)) + ",[192.0.2.10]:" + p + ",[2001:db8::10]:" + p + " " + marshalKey(pub); d.KnownHosts != want {
		t.Errorf("known_hosts %q, want %q", d.KnownHosts, want)
	}
	cb := knownHostsCallback(t, d.KnownHosts)
	for _, h := range []string{name, "192.0.2.10", "2001:db8::10"} {
		if err := cb(net.JoinHostPort(h, p), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.Port}, pub); err != nil {
			t.Errorf("known_hosts does not hold %s: %v", h, err)
		}
	}
	if err := cb(net.JoinHostPort("203.0.113.9", p), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.Port}, pub); err == nil {
		t.Error("known_hosts holds an address of no interface")
	}
	fp := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if got := ssh.FingerprintSHA256(key); got != d.HostKeyFingerprint {
			return fmt.Errorf("host key %s, the line says %s", got, d.HostKeyFingerprint)
		}
		return nil
	}
	if _, err := detailsLogin(t, net.JoinHostPort("127.0.0.1", p), alice, fp); err != nil {
		t.Errorf("login through the unspecified address: %v", err)
	}
}

// marshalKey returns pub as an authorized_keys line has it.
func marshalKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// TestServePrintDetailsNoInterfaces: when the interfaces cannot be listed,
// addresses is empty, not null, known_hosts names the host alone, and the
// log says why. Not parallel: it replaces interfaceAddrs.
func TestServePrintDetailsNoInterfaces(t *testing.T) {
	isolate(t)
	stubInterfaces(t, errors.New("route ip+net: netlinkrib: permission denied"))
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	ts := startWith(t, nil, "serve", "--allow-root", "--print-details", "--config", path, "--listen", ":0")
	d := decodeServeDetails(t, ts.stdout.String())
	if !strings.Contains(ts.stdout.String(), `"addresses":[]`) || len(d.Addresses) != 0 ||
		!strings.HasPrefix(d.KnownHosts, knownhosts.Normalize(net.JoinHostPort(d.Host, strconv.Itoa(d.Port)))+" ssh-ed25519 ") {
		t.Errorf("stdout %s", ts.stdout.String())
	}
	waitLog(t, ts.stderr.String, `msg="cannot list the addresses of the network interfaces; the connection details name none" err="route ip+net: netlinkrib: permission denied"`)
}

// TestServePrintDetailsFailures: a start that fails prints one JSON line
// on stdout with the error, as stderr has it, its kind and, for kind
// listen, the address; the exit status is the one without the flag. Not
// parallel: it replaces startSandbox.
func TestServePrintDetailsFailures(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	defer func() { startSandbox = noSandbox }()
	dir := t.TempDir()
	alice := newSigner(t)
	inUse, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inUse.Close()
	busy := inUse.Addr().String()
	config := func(name, server, audit string) string {
		d := filepath.Join(dir, name)
		return detailsConfig(t, d, `listen = ["127.0.0.1:0"]`+"\n"+server, audit, alice)
	}
	good := config("good", "", "")
	sandboxFails := func(context.Context, sandbox.Options) (sandbox.Result, error) {
		return sandbox.Result{}, errors.New("landlock: failed: self-check: / can still be opened")
	}
	sandboxRequired := func(context.Context, sandbox.Options) (sandbox.Result, error) {
		return sandbox.Result{}, &sandbox.RequiredError{}
	}
	for _, tt := range []struct {
		name    string
		args    []string
		sandbox func(context.Context, sandbox.Options) (sandbox.Result, error)
		code    int
		kind    string
		addr    string
		error   string // a part of it
	}{
		{"port in use", []string{"--config", good, "--listen", busy}, nil, exitFailure, failListen, busy, busy},
		{"metrics port", []string{"--config", config("metrics", "[metrics]\nlisten = \"192.0.2.1:9090\"", "")}, nil, exitFailure, failListen, "192.0.2.1:9090", "metrics.listen: "},
		{"invalid configuration", []string{"--config", config("invalid", `handshake_timeout = "1ms"`, "")}, nil, exitUsage, failConfig, "", "server.handshake_timeout: must be between 1s and 10m0s"},
		{"no configuration", []string{"--config", filepath.Join(dir, "missing.toml")}, nil, exitUsage, failConfig, "", "missing.toml"},
		{"usage", []string{"--config", good, "--dir", dir}, nil, exitUsage, failConfig, "", "--dir and --config cannot be used together"},
		{"ephemeral", []string{"--ephemeral"}, nil, exitUsage, failConfig, "", "--print-details and --ephemeral cannot be used together: --ephemeral prints its own line of connection details"},
		{"audit flag", []string{"--config", good, "--audit-output", "stdout"}, nil, exitUsage, failConfig, "", "--audit-output stdout cannot be used with --print-details, whose stdout carries only the connection details; name a file for the audit log"},
		{"audit default", []string{"--config", config("default", "", "events = [\"session\"]")}, nil, exitUsage, failConfig, "", `--print-details needs the audit log in a file: its stdout carries only the connection details, and audit.output is "stdout" by default; set audit.output, or pass --audit-output FILE`},
		{"audit default without a file", []string{"--dir", filepath.Join(dir, "good", "data"), "--authorized-keys", filepath.Join(dir, "keys")}, nil, exitUsage, failConfig, "", `audit.output is "stdout" by default`},
		{"audit file", []string{"--config", config("stdout", "", `output = "stdout"`)}, nil, exitUsage, failConfig, "", `audit.output = "stdout" in ` + filepath.Join(dir, "stdout", "gosftpd.toml") + ` cannot be used with --print-details`},
		{"sandbox failure", []string{"--config", good}, sandboxFails, exitFailure, failSandbox, "", "landlock: failed: self-check: / can still be opened"},
		{"sandbox required", []string{"--config", good}, sandboxRequired, exitUsage, failSandbox, "", `server.landlock is "required"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writeFile(t, filepath.Join(dir, "keys"), authorizedKey(alice)+"\n")
			startSandbox = noSandbox
			if tt.sandbox != nil {
				startSandbox = tt.sandbox
			}
			args := append([]string{"serve", "--allow-root", "--print-details"}, tt.args...)
			var stdout, stderr lockedBuffer
			code := run(t.Context(), args, &stdout, &stderr)
			f := decodeFailure(t, stdout.String())
			if code != tt.code || f.Kind != tt.kind || f.Address != tt.addr || !strings.Contains(f.Error, tt.error) {
				t.Errorf("exit %d, want %d; line %+v", code, tt.code, f)
			}
			if !strings.Contains(stderr.String(), "Error: "+f.Error+"\n") {
				t.Errorf("stderr does not have the error of the line:\n%s", stderr.String())
			}
			if strings.Contains(stderr.String(), `"event":"server.start"`) {
				t.Errorf("stderr:\n%s", stderr.String())
			}
		})
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v", tmp, got)
	}
	// Without --print-details, the same failures print nothing on stdout.
	startSandbox = noSandbox
	code, out, errOut := execute(t, "serve", "--allow-root", "--config", good, "--listen", busy)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "Error: listen tcp "+busy) {
		t.Errorf("without --print-details: exit %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
}

// TestServePrintDetailsStdoutFails: when the line cannot be written,
// serve stops at once with exit status 1, as --ephemeral does, and prints
// no failure line: serving had started.
func TestServePrintDetailsStdoutFails(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	var stderr lockedBuffer
	code := run(t.Context(), []string{"serve", "--allow-root", "--print-details", "--config", path}, failingWriter{}, &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "Error: writing the connection details: broken pipe\n") {
		t.Errorf("exit %d:\n%s", code, stderr.String())
	}
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))()
	if len(events(t, audit, "server.start")) != 1 || len(events(t, audit, "server.stop")) != 1 {
		t.Errorf("audit log:\n%s", audit)
	}
}

// TestServePrintDetailsReload: with --print-details a reload refuses an
// audit log on stdout and keeps the running one; stdout keeps the one
// line.
func TestServePrintDetailsReload(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	alice := newSigner(t)
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", alice)
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))
	ts := startWith(t, nil, "serve", "--allow-root", "--print-details", "--config", path)
	line := ts.stdout.String()

	writeFile(t, path, strings.Replace(readHost(t, path), `output = "audit/audit.jsonl"`, `output = "stdout"`, 1))
	if ev := ts.reload(t, audit); ev["result"] != "error" || ev["reason"] != reloadConfig {
		t.Errorf("server.reload = %v", ev)
	}
	if want := logged(`audit.output = "stdout" in ` + path + ` cannot be used with --print-details`); !strings.Contains(ts.stderr.String(), want) {
		t.Errorf("the failed reload does not say why:\n%s", ts.stderr.String())
	}
	writeFile(t, path, strings.Replace(readHost(t, path), `output = "stdout"`, `output = "audit/audit.jsonl"`, 1))
	if ev := ts.reload(t, audit); ev["result"] != "ok" {
		t.Errorf("server.reload = %v", ev)
	}
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if ts.stdout.String() != line {
		t.Errorf("stdout %q, was %q", ts.stdout.String(), line)
	}
	if len(events(t, audit(), "server.stop")) != 1 {
		t.Errorf("audit log:\n%s", audit())
	}
}

// TestFailureKind: the kind of a failed start, also through wrapping.
func TestFailureKind(t *testing.T) {
	t.Parallel()
	listen := listenError{":2022", errors.New("listen tcp :2022: bind: address already in use")}
	for _, tt := range []struct {
		err        error
		kind, addr string
	}{
		{listen, failListen, ":2022"},
		{fmt.Errorf("start: %w", listen), failListen, ":2022"},
		{sandboxError{configError{&sandbox.RequiredError{}}}, failSandbox, ""},
		{sandboxError{errors.New("landlock: failed: x")}, failSandbox, ""},
		{configError{errors.New("x")}, failConfig, ""},
		{usageError{errors.New("x")}, failConfig, ""},
		{errors.Join(errors.New("x"), configError{errors.New("y")}), failConfig, ""},
		{errors.New("x"), failOther, ""},
	} {
		if kind, addr := failureKind(tt.err); kind != tt.kind || addr != tt.addr {
			t.Errorf("%#v: %s %q, want %s %q", tt.err, kind, addr, tt.kind, tt.addr)
		}
	}
	// The wrappers keep the text and the exit status.
	if listen.Error() != listen.err.Error() || errors.As(listen, new(configError)) {
		t.Errorf("listenError %v", listen)
	}
	if err := (sandboxError{configError{errors.New("x")}}); err.Error() != "x" || !errors.As(err, new(configError)) {
		t.Errorf("sandboxError %v", err)
	}
}

// TestKnownHostsLine: the hosts of one line, each as known_hosts names
// it: in brackets with a port other than 22.
func TestKnownHostsLine(t *testing.T) {
	t.Parallel()
	pub := newSigner(t).PublicKey()
	key := marshalKey(pub)
	for port, want := range map[int]string{
		2022: "[vm]:2022,[192.0.2.10]:2022,[2001:db8::10]:2022 " + key,
		22:   "vm,192.0.2.10,2001:db8::10 " + key,
	} {
		if got := knownHostsLine([]string{"vm", "192.0.2.10", "2001:db8::10", "vm"}, port, pub); got != want {
			t.Errorf("port %d: %q, want %q", port, got, want)
		}
	}
	if got, want := knownHostsLine([]string{"192.0.2.10"}, 2022, pub), hostkey.KnownHostsLine("192.0.2.10", 2022, pub); got != want {
		t.Errorf("one host: %q, want %q", got, want)
	}
}

// TestRemoteAddresses: the addresses another machine can connect to.
func TestRemoteAddresses(t *testing.T) {
	t.Parallel()
	var addrs []net.Addr
	for _, s := range []string{"192.0.2.10", "10.0.0.1", "127.0.0.1", "::1", "fe80::1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::", "2001:db8::10", "192.0.2.10"} {
		addrs = append(addrs, &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(8, 32)})
	}
	addrs = append(addrs, &net.IPAddr{IP: net.ParseIP("198.51.100.1")}, &net.UnixAddr{Name: "/run/x", Net: "unix"})
	if got, want := remoteAddresses(addrs), []string{"192.0.2.10", "10.0.0.1", "2001:db8::10", "198.51.100.1"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
	if got := remoteAddresses(nil); got == nil || len(got) != 0 {
		t.Errorf("no addresses: %#v", got)
	}
}

// TestServeDetailsLine: the field names and their order.
func TestServeDetailsLine(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(serveDetails{
		Host: "vm", Port: 2022, HostKeyFingerprint: "SHA256:fp", KnownHosts: "[vm]:2022,[192.0.2.10]:2022 ssh-ed25519 AAAA", PID: 4242, Version: "v0.6.0",
		Listen: []string{"[::]:2022"}, HostKeys: []hostKeyDetails{{"ssh-ed25519", "SHA256:fp"}}, Addresses: []string{"192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"host":"vm","port":2022,"host_key_fingerprint":"SHA256:fp","known_hosts":"[vm]:2022,[192.0.2.10]:2022 ssh-ed25519 AAAA","pid":4242,"version":"v0.6.0",` +
		`"listen":["[::]:2022"],"host_keys":[{"type":"ssh-ed25519","fingerprint":"SHA256:fp"}],"addresses":["192.0.2.10"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	if b, err = json.Marshal(startFailure{Error: "x", Kind: failConfig}); err != nil || string(b) != `{"error":"x","kind":"config","address":""}` {
		t.Errorf("%s, %v", b, err)
	}
}

// TestServeDetailsHelp: serve --help shows both flags.
func TestServeDetailsHelp(t *testing.T) {
	t.Parallel()
	code, out, _ := execute(t, "serve", "--help")
	for _, want := range []string{
		"--print-details[=true|false]",
		"print the connection details as one JSON line on stdout once serving starts, or the error of a failed start, instead of the banner; the audit log must go to a file",
		"--stop-on-stdin-eof[=true|false]",
		"stop as on SIGTERM when stdin, a pipe or a socket, reaches end of file; what is written to it is discarded",
		"With --print-details, gosftpd prints the connection details",
	} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("exit %d; no %q in:\n%s", code, want, out)
		}
	}
	// Atmoz mode's form has neither.
	if code, out, _ := execute(t, "--help"); code != exitOK || strings.Contains(out, "--print-details") || strings.Contains(out, "--stop-on-stdin-eof") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// TestSameAsStdout: an audit log path that names stdout is refused with
// --print-details, as "stdout" is; a stdout thrown away is not stdout.
func TestSameAsStdout(t *testing.T) {
	dir := t.TempDir()
	file, other := filepath.Join(dir, "out"), filepath.Join(dir, "other")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	writeFile(t, other, "")
	saved := os.Stdout
	t.Cleanup(func() { os.Stdout = saved })

	os.Stdout = f
	if !sameAsStdout(file) || sameAsStdout(other) || sameAsStdout("stdout") || sameAsStdout(filepath.Join(dir, "missing")) {
		t.Errorf("stdout to %s: file %v, other %v", file, sameAsStdout(file), sameAsStdout(other))
	}
	if code, _, stderr := execute(t, "serve", "--allow-root", "--print-details", "--dir", dir, "--audit-output", file); code != exitUsage || !strings.Contains(stderr, "is stdout, which with --print-details") {
		t.Errorf("--audit-output %s: exit %d\n%s", file, code, stderr)
	}

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { null.Close() })
	os.Stdout = null
	if sameAsStdout(os.DevNull) {
		t.Error("a stdout thrown away counts as the audit log's file")
	}
}
