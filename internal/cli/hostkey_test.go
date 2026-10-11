// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// hostKeyOf connects and returns the host key the server used, and the
// keys it announced to an OpenSSH client.
func (ts *testServer) hostKeyOf(t *testing.T, user string, key ssh.Signer, algos ...string) (ssh.PublicKey, [][]byte) {
	t.Helper()
	var used ssh.PublicKey
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(t.Context(), "tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback:   func(_ string, _ net.Addr, k ssh.PublicKey) error { used = k; return nil },
		HostKeyAlgorithms: algos,
		ClientVersion:     "SSH-2.0-OpenSSH_9.6",
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, ts.addr, cfg)
	if err != nil {
		nc.Close()
		t.Fatalf("login: %v\n%s", err, ts.stderr.String())
	}
	defer conn.Close()
	go ssh.DiscardRequests(nil)
	go func() {
		for range chans {
		}
	}()
	// The announcement comes before any channel is served.
	ch, creqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(creqs)
	ch.Close()
	var announced [][]byte
	select {
	case req := <-reqs:
		payload := req.Payload
		for len(payload) > 0 {
			var s struct {
				Key  []byte
				Rest []byte `ssh:"rest"`
			}
			if err := ssh.Unmarshal(payload, &s); err != nil {
				t.Fatal(err)
			}
			announced, payload = append(announced, s.Key), s.Rest
		}
	default:
	}
	return used, announced
}

// sameKeys reports whether two public keys are equal.
func sameKeys(a, b ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), b.Marshal()) }

func announces(keys [][]byte, k ssh.PublicKey) bool {
	for _, b := range keys {
		if bytes.Equal(b, k.Marshal()) {
			return true
		}
	}
	return false
}

// signHostCert certifies the key of key file p in p-cert.pub.
func signHostCert(t *testing.T, ca ssh.Signer, p string) {
	t.Helper()
	k, err := hostkey.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{
		Key:             k.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "gosftpd",
		ValidPrincipals: []string{"127.0.0.1"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(400 * 24 * time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostkey.Cert(p), string(ssh.MarshalAuthorizedKey(c)))
}

// TestServeHostKeyRotation runs a rotation against a running server: the
// next key is announced after a reload, becomes the host key after
// --finish, the previous key stays announced until --retire, and a host
// key that cannot be read keeps the running keys without blocking the
// reload. Host certificates follow their keys.
func TestServeHostKeyRotation(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	alice, bob := newSigner(t), newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	key := filepath.Join(dir, "state", "host_key")
	conf := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
host_certificates = true
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
`
	writeFile(t, path, conf)
	ts := startServe(t, "--config", path)
	if !strings.Contains(ts.stderr.String(), "has no certificate") {
		t.Errorf("no warning about the missing certificate:\n%s", ts.stderr.String())
	}
	first, announced := ts.hostKeyOf(t, "alice", alice)
	if len(announced) != 1 || !announces(announced, first) {
		t.Fatalf("announced %d keys before the rotation", len(announced))
	}

	code, out, errOut := execute(t, "hostkey", "rotate", "--config", path, "--known-hosts", "127.0.0.1:2022")
	if code != exitOK || !strings.Contains(out, "created the next host key "+hostkey.Next(key)) || !strings.Contains(out, "[127.0.0.1]:2022 ssh-ed25519 ") {
		t.Fatalf("rotate: exit %d\n%s%s", code, out, errOut)
	}
	next, err := hostkey.Load(hostkey.Next(key))
	if err != nil {
		t.Fatal(err)
	}
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v", ev)
	}
	used, announced := ts.hostKeyOf(t, "alice", alice)
	if !sameKeys(used, first) || len(announced) != 2 || !announces(announced, next.PublicKey()) {
		t.Errorf("during the transition: used %s, announced %d keys", ssh.FingerprintSHA256(used), len(announced))
	}
	if !strings.Contains(ts.stderr.String(), "role=next") {
		t.Errorf("the new key set is not logged:\n%s", ts.stderr.String())
	}

	// hostkey show and user add list the next key.
	code, out, _ = execute(t, "hostkey", "show", "--config", path)
	if code != exitOK || !strings.Contains(out, hostkey.Next(key)+" (next key") {
		t.Errorf("hostkey show: exit %d\n%s", code, out)
	}

	// A certificate for the next key; the CA for the current one later.
	ca := newSigner(t)
	signHostCert(t, ca, hostkey.Next(key))
	code, out, errOut = execute(t, "hostkey", "rotate", "--finish", "--config", path)
	if code != exitOK || !strings.Contains(out, "the next key replaced") {
		t.Fatalf("rotate --finish: exit %d\n%s%s", code, out, errOut)
	}
	ts.reload(t, ts.stdout.String)
	used, announced = ts.hostKeyOf(t, "alice", alice, ssh.KeyAlgoED25519)
	if !sameKeys(used, next.PublicKey()) || len(announced) != 2 || !announces(announced, first) {
		t.Errorf("after --finish: used %s, announced %d keys", ssh.FingerprintSHA256(used), len(announced))
	}
	// The certificate moved with its key and is served.
	used, _ = ts.hostKeyOf(t, "alice", alice, ssh.CertAlgoED25519v01)
	if cert, ok := used.(*ssh.Certificate); !ok || !sameKeys(cert.Key, next.PublicKey()) {
		t.Errorf("certificate host key: %T", used)
	}

	// A host key that cannot be used keeps the running keys; the rest of
	// the reload (here: a new user) applies.
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, key, "not a key")
	writeFile(t, path, conf+`[users.bob]
authorized_keys = ["`+authorizedKey(bob)+`"]
access = { data = "read" }
`)
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Errorf("server.reload with a broken host key = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), "the running host keys stay") {
		t.Errorf("no warning about the broken host key:\n%s", ts.stderr.String())
	}
	if used, _ := ts.hostKeyOf(t, "bob", bob, ssh.KeyAlgoED25519); !sameKeys(used, next.PublicKey()) {
		t.Errorf("after a broken host key: used %s", ssh.FingerprintSHA256(used))
	}
	writeFile(t, key, string(data))

	code, out, errOut = execute(t, "hostkey", "rotate", "--retire", "--config", path)
	if code != exitOK {
		t.Fatalf("rotate --retire: exit %d\n%s%s", code, out, errOut)
	}
	ts.reload(t, ts.stdout.String)
	if _, announced := ts.hostKeyOf(t, "alice", alice); len(announced) != 1 || !announces(announced, next.PublicKey()) {
		t.Errorf("after --retire: announced %d keys", len(announced))
	}
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit code %d", code)
	}
}

func TestHostkeyRotateCommand(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	ed := filepath.Join(dir, "ssh_host_ed25519_key")
	rsa := filepath.Join(dir, "ssh_host_rsa_key")
	if _, err := hostkey.Generate(ed); err != nil {
		t.Fatal(err)
	}
	if _, err := hostkey.GenerateType(rsa, hostkey.TypeRSA); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
host_keys = ["ssh_host_ed25519_key", "ssh_host_rsa_key"]
[mounts.m]
path = "`+filepath.ToSlash(filepath.Join(dir, "m"))+`"
`)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", path}, "choose one with --host-key"},
		{[]string{"--config", path, "--host-key", filepath.Join(dir, "other")}, "not one of the host keys"},
		{[]string{"--config", path, "--host-key", ed, "--type", "rsa"}, "already of type rsa"},
		{[]string{"--host-key", ed, "--finish", "--retire"}, "cannot be combined"},
		{[]string{"--host-key", ed, "--finish", "--type", "rsa"}, "--type only applies"},
		{[]string{"--host-key", ed, "--finish"}, "start a rotation"},
		{[]string{"--host-key", ed, "--state-dir", dir, "--config", path}, "cannot be used together"},
	} {
		code, out, errOut := execute(t, append([]string{"hostkey", "rotate"}, tc.args...)...)
		if code != exitUsage || !strings.Contains(errOut, tc.want) {
			t.Errorf("rotate %v: exit %d, %q; want %q\n%s", tc.args, code, errOut, tc.want, out)
		}
	}

	// A rotation to another type, then aborted.
	code, out, errOut := execute(t, "hostkey", "rotate", "--config", path, "--host-key", ed, "--type", "ecdsa")
	if code != exitOK || !strings.Contains(out, "ECDSA-SHA2-NISTP256 SHA256:") || !strings.Contains(out, "--finish --host-key "+commandArg(ed)) {
		t.Fatalf("rotate --type ecdsa: exit %d\n%s%s", code, out, errOut)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--host-key", ed); code != exitUsage || !strings.Contains(errOut, "in progress") {
		t.Errorf("second rotate: exit %d, %s", code, errOut)
	}
	// The RSA key cannot become ECDSA too: the next key has that type.
	if code, _, errOut := execute(t, "hostkey", "rotate", "--config", path, "--host-key", rsa, "--type", "ecdsa"); code != exitUsage || !strings.Contains(errOut, "already of type ecdsa") {
		t.Errorf("a second rotation to ecdsa: exit %d, %s", code, errOut)
	}
	// config validate --check-fs reads the next key too.
	if code, _, errOut := execute(t, "config", "validate", "--check-fs", "--config", path); code != exitOK {
		t.Errorf("validate during a rotation: exit %d, %s", code, errOut)
	}
	writeFile(t, hostkey.Next(ed), "broken")
	if code, _, errOut := execute(t, "config", "validate", "--check-fs", "--config", path); code != exitUsage || !strings.Contains(errOut, hostkey.Next(ed)) {
		t.Errorf("validate with a broken next key: exit %d, %s", code, errOut)
	}
	code, _, errOut = execute(t, "hostkey", "show", "--host-key", ed)
	if code != exitOK || !strings.Contains(errOut, "warning: ") {
		t.Errorf("show with a broken next key: exit %d, %s", code, errOut)
	}
	if code, out, errOut := execute(t, "hostkey", "rotate", "--abort", "--host-key", ed); code != exitOK || !strings.Contains(out, "deleted the next key") {
		t.Errorf("rotate --abort: exit %d\n%s%s", code, out, errOut)
	}
	if exists(hostkey.Next(ed)) {
		t.Error("P.next survived --abort")
	}
}

// The printed commands survive any path, and say what to do when the
// announcement is off.
func TestHostkeyRotateOutput(t *testing.T) {
	isolate(t)
	dir := filepath.Join(t.TempDir(), "a%sb")
	key := filepath.Join(dir, "key")
	if _, err := hostkey.Generate(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "m"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
host_keys = ["key"]
announce_host_keys = false
[mounts.m]
path = "`+filepath.ToSlash(filepath.Join(dir, "m"))+`"
`)
	code, out, errOut := execute(t, "hostkey", "rotate", "--config", path)
	if code != exitOK || strings.Contains(out, "%!") || !strings.Contains(out, "--finish --host-key "+commandArg(key)) {
		t.Fatalf("rotate: exit %d\n%s%s", code, out, errOut)
	}
	if !strings.Contains(out, "announce_host_keys is off") || strings.Contains(out, "conn.hostkeys_proved") {
		t.Errorf("rotate with the announcement off:\n%s", out)
	}
	code, out, errOut = execute(t, "hostkey", "rotate", "--finish", "--config", path)
	if code != exitOK || strings.Contains(out, "%!") || !strings.Contains(out, "--retire --host-key "+commandArg(key)) {
		t.Errorf("rotate --finish: exit %d\n%s%s", code, out, errOut)
	}
}

// A next key that does not belong to the owner of the host key (or root) is
// not made the host key: gosftpd might not read it.
func TestHostkeyRotateFinishOwner(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root to give a file another owner")
	}
	isolate(t)
	key := filepath.Join(t.TempDir(), "key")
	if _, err := hostkey.Generate(key); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--host-key", key); code != exitOK {
		t.Fatalf("rotate: %s", errOut)
	}
	if err := os.Chown(hostkey.Next(key), 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "hostkey", "rotate", "--finish", "--host-key", key); code != exitUsage || !strings.Contains(errOut, "belongs to uid 4242") {
		t.Errorf("finish with a foreign next key: exit %d, %s", code, errOut)
	}
	if exists(hostkey.Old(key)) {
		t.Error("the refused finish changed files")
	}
}

// A reload keeps the running host keys when the new ones cannot be used,
// and then checks those against new mounts; it uses changed paths; it
// leaves out a broken next certificate but keeps announcing the next key.
func TestServeReloadHostKeyFiles(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	for _, d := range []string{"data", "keys1", "keys2"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	alice := newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	conf := func(keys, extra string) string {
		return `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["` + keys + `"]
host_key_auto_generate = true
host_certificates = true
[mounts.data]
path = "` + filepath.ToSlash(filepath.Join(dir, "data")) + `"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
` + extra
	}
	writeFile(t, path, conf("keys1/host_key", ""))
	ts := startServe(t, "--config", path)
	first, err := hostkey.Load(filepath.Join(dir, "keys1", "host_key"))
	if err != nil {
		t.Fatal(err)
	}

	// The new key does not exist and a new mount covers the running one:
	// the reload is refused rather than serve the key in use.
	writeFile(t, path, conf("keys2/host_key", `[mounts.keys]
path = "`+filepath.ToSlash(filepath.Join(dir, "keys1"))+`"
read_only = true
`))
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "error" {
		t.Errorf("server.reload with a mount over the running key = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), "covers the host key") {
		t.Errorf("the refusal does not name the host key:\n%s", ts.stderr.String())
	}

	// A changed path is used.
	second, err := hostkey.Generate(filepath.Join(dir, "keys2", "host_key"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, conf("keys2/host_key", ""))
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v", ev)
	}
	if used, _ := ts.hostKeyOf(t, "alice", alice, ssh.KeyAlgoED25519); !sameKeys(used, second.PublicKey()) || sameKeys(used, first.PublicKey()) {
		t.Errorf("after a changed path: used %s", ssh.FingerprintSHA256(used))
	}

	// A broken certificate of the next key is left out; the key is still
	// announced.
	p := filepath.Join(dir, "keys2", "host_key")
	next, err := hostkey.StartRotation(p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostkey.Cert(hostkey.Next(p)), "not a certificate")
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Fatalf("server.reload with a broken next certificate = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), "left out") {
		t.Errorf("no warning about the broken certificate:\n%s", ts.stderr.String())
	}
	if _, announced := ts.hostKeyOf(t, "alice", alice); !announces(announced, next.PublicKey()) {
		t.Error("the next key is not announced")
	}
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit code %d", code)
	}
}

// A reload says when --host-key hides server.host_keys of the file.
func TestServeReloadHostKeyFlag(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	flagKey := filepath.Join(dir, "flag_key")
	if _, err := hostkey.Generate(flagKey); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["file_key"]
[mounts.data]
path = "`+filepath.ToSlash(filepath.Join(dir, "data"))+`"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { data = "full" }
`)
	ts := startServe(t, "--config", path, "--host-key", flagKey)
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Errorf("server.reload = %v", ev)
	}
	if !strings.Contains(ts.stderr.String(), "server.host_keys in "+path+" has no effect: --host-key overrides it") {
		t.Errorf("no warning about the hidden setting:\n%s", ts.stderr.String())
	}
}

// loadHostKeys: at start every problem is an error; on reload a broken
// next key or certificate is left out with a warning, while a broken host
// key is still an error (the running keys stay).
func TestLoadHostKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if _, err := hostkey.Generate(p); err != nil {
		t.Fatal(err)
	}
	if _, err := hostkey.StartRotation(p, "", nil); err != nil {
		t.Fatal(err)
	}
	ca := newSigner(t)
	signHostCert(t, ca, p)
	keys, warns, err := loadHostKeys([]string{p}, hostKeyOptions{certs: true})
	if err != nil || len(keys) != 1 || keys[0].next == nil || keys[0].cur.served == nil {
		t.Fatalf("loadHostKeys() = %+v, %v, %v", keys, warns, err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "next host key") {
		t.Errorf("warnings = %q, want one about the next key's certificate", warns)
	}

	// A next key equal to the host key.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostkey.Next(p), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadHostKeys([]string{p}, hostKeyOptions{}); err == nil || !strings.Contains(err.Error(), "same key") {
		t.Errorf("start with P.next = P: %v", err)
	}
	keys, warns, err = loadHostKeys([]string{p}, hostKeyOptions{lenient: true})
	if err != nil || keys[0].next != nil || len(warns) != 1 || !strings.Contains(warns[0], "left out") {
		t.Errorf("reload with P.next = P: next %v, %q, %v", keys[0].next, warns, err)
	}

	// A certificate of another key.
	other := filepath.Join(dir, "other")
	if _, err := hostkey.Generate(other); err != nil {
		t.Fatal(err)
	}
	signHostCert(t, ca, other)
	if err := os.Rename(hostkey.Cert(other), hostkey.Cert(p)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadHostKeys([]string{p}, hostKeyOptions{certs: true}); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("start with a foreign certificate: %v", err)
	}
	keys, _, err = loadHostKeys([]string{p}, hostKeyOptions{certs: true, lenient: true})
	if err != nil || keys[0].cur.served != nil {
		t.Errorf("reload with a foreign certificate: served %v, %v", keys[0].cur.served, err)
	}

	// A next key of the type of another host key.
	if err := os.Remove(hostkey.Next(p)); err != nil {
		t.Fatal(err)
	}
	ec := filepath.Join(dir, "ecdsa")
	if _, err := hostkey.GenerateType(ec, hostkey.TypeECDSA); err != nil {
		t.Fatal(err)
	}
	if _, err := hostkey.StartRotation(p, hostkey.TypeECDSA, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadHostKeys([]string{p, ec}, hostKeyOptions{}); err == nil || !strings.Contains(err.Error(), "only one would be used") {
		t.Errorf("a next key of another key's type: %v", err)
	}
	if err := hostkey.AbortRotation(p); err != nil {
		t.Fatal(err)
	}

	// Two host keys of one type; a missing host key.
	if _, _, err := loadHostKeys([]string{p, other}, hostKeyOptions{lenient: true}); err == nil || !strings.Contains(err.Error(), "both of type") {
		t.Errorf("two ed25519 keys: %v", err)
	}
	if _, _, err := loadHostKeys([]string{filepath.Join(dir, "missing")}, hostKeyOptions{lenient: true}); err == nil {
		t.Error("a missing host key loaded")
	}
	// inspect: a key serve would generate is skipped; .pub stands in for a
	// private key this user cannot read.
	keys, _, err = loadHostKeys([]string{filepath.Join(dir, "later")}, hostKeyOptions{inspect: true, generate: true})
	if err != nil || len(keys) != 0 {
		t.Errorf("inspect a key to generate: %v, %v", keys, err)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := os.Chmod(other, 0o000); err != nil {
			t.Fatal(err)
		}
		keys, _, err = loadHostKeys([]string{other}, hostKeyOptions{inspect: true})
		if err != nil || !keys[0].cur.fromPub {
			t.Errorf("inspect an unreadable key: %v, %v", keys, err)
		}
	}
}

// The certificate watcher logs a problem when it starts, after a reload,
// when the state changes, and not again within a day.
func TestWatchHostCerts(t *testing.T) {
	t.Parallel()

	ca, key := newSigner(t), newSigner(t)
	c := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"h"},
		ValidAfter:      uint64(time.Now().Add(-300 * 24 * time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(10 * 24 * time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	buf := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	count := func() int { return strings.Count(buf.String(), "expires soon") }
	ctx, cancel := context.WithCancel(t.Context())
	reloaded := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		watchHostCerts(ctx, func() []hostCert { return []hostCert{{"k-cert.pub", c}} }, reloaded, log, time.Millisecond)
		close(done)
	}()
	waitFor(t, func() bool { return count() == 1 })
	time.Sleep(20 * time.Millisecond)
	if n := count(); n != 1 {
		t.Errorf("logged %d times without a reload", n)
	}
	reloaded <- struct{}{}
	waitFor(t, func() bool { return count() == 2 })
	cancel()
	<-done

	buf = &lockedBuffer{}
	logCertNotice(t.Context(), slog.New(slog.NewTextHandler(buf, nil)), hostCert{"p", c}, hostkey.CertValid)
	if buf.String() != "" {
		t.Errorf("a valid certificate is logged: %q", buf.String())
	}

	// A certificate that expires while the watcher runs is reported then,
	// as an error.
	short := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{"h"},
		ValidAfter:      uint64(time.Now().Add(-10 * time.Second).Unix()),
		ValidBefore:     uint64(time.Now().Add(2 * time.Second).Unix()),
	}
	if err := short.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	log = slog.New(slog.NewTextHandler(buf, nil))
	go func() {
		watchHostCerts(ctx, func() []hostCert { return []hostCert{{"s-cert.pub", short}} }, nil, log, 10*time.Millisecond)
		close(done)
	}()
	waitFor(t, func() bool { return strings.Contains(buf.String(), "level=ERROR msg=\"host certificate expired") })
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
