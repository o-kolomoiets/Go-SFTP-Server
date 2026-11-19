// SPDX-License-Identifier: Apache-2.0

//go:build unix

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testBin is gosftpd built from this repository, the parent module: the
// GUI runs the gosftpd of its own release.
var testBin string

func TestMain(m *testing.M) {
	if os.Getenv("SUPERVISOR_CHILD") != "" { // TestKilledGUI's GUI: given its gosftpd
		os.Exit(m.Run())
	}
	code := func() int {
		dir, err := os.MkdirTemp("", "gosftpd-gui-test-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		testBin = filepath.Join(dir, "gosftpd")
		build := exec.CommandContext(context.Background(), "go", "build", "-o", testBin, "./cmd/gosftpd")
		build.Dir = filepath.Join("..", "..", "..") // the repository's root
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "building gosftpd: %v\n%s", err, out)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

// newGosftpd returns a Gosftpd on a new state directory, and a folder to
// share. gosftpd refuses to run as root.
func newGosftpd(t *testing.T) (Gosftpd, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("gosftpd refuses to run as root")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOSFTPD_LISTEN", ":1") // must not reach gosftpd (childEnv)
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	return Gosftpd{Bin: testBin, Layout: Layout{Dir: filepath.Join(dir, "gosftpd-gui")}}, share
}

// testVersion is what gosftpd version --json says of testBin: "dev", or
// a pseudo-version when the build stamped this checkout's commit.
func testVersion(t *testing.T, g Gosftpd) string {
	t.Helper()
	v, err := g.Version(t.Context())
	if err != nil || v == "" {
		t.Fatalf("Version = %q, %v", v, err)
	}
	return v
}

func TestVersion(t *testing.T) {
	g, _ := newGosftpd(t)
	ctx := t.Context()
	v := testVersion(t, g)
	if err := g.CheckVersion(ctx, v); err != nil {
		t.Error(err)
	}
	var ve *VersionError
	if err := g.CheckVersion(ctx, "v9.9.9"); !errors.As(err, &ve) || ve.Found != v || !strings.Contains(err.Error(), "needs gosftpd v9.9.9") {
		t.Errorf("CheckVersion(v9.9.9) = %v", err)
	}
}

func TestAdmin(t *testing.T) {
	g, share := newGosftpd(t)
	a := Admin{G: g}
	ctx := t.Context()
	photos := filepath.Join(filepath.Dir(share), "photos")
	if err := os.Mkdir(photos, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Write(ctx, Settings{Folders: []Folder{{Name: "Inbox", Path: share}, {Name: "Photos", Path: photos, ReadOnly: true}}}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(g.Layout.Dir); err != nil || fi.Mode().Perm() != 0o700 || !g.Layout.Exists() {
		t.Fatalf("state directory: %v, %v", fi, err)
	}
	s, reset, err := a.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{Folders: []Folder{{Name: "Inbox", Path: share}, {Name: "Photos", Path: photos, ReadOnly: true}}, Listen: []string{":2022"}, OnConflict: "rename"}
	if !settingsEqual(s, want) || reset != nil {
		t.Errorf("Read = %+v (reset %q), want %+v", s, reset, want)
	}

	// The first person with a password turns password logins on.
	if _, err := a.AddWithPassword(ctx, "alice", "a\nb", map[string]string{"Inbox": "upload"}); err == nil {
		t.Error("a password with a line break was accepted")
	}
	if _, err := a.AddWithPassword(ctx, "alice", "secret one", map[string]string{"Inbox": "upload", "Photos": "read"}); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := a.Read(ctx); !s.PasswordLogins {
		t.Error("password logins are off after the first password")
	}
	if _, err := a.AddWithKey(ctx, "bob", testKey(t), map[string]string{"Photos": "read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddWithKey(ctx, "carol", testKey(t), nil); !errors.Is(err, errNoAccess) {
		t.Errorf("a person without a folder: %v", err)
	}
	people := peopleByName(t, a)
	if p := people["alice"]; !p.Password || p.Keys != 0 || !maps.Equal(p.Access, map[string]string{"Inbox": "upload", "Photos": "read"}) {
		t.Errorf("alice: %+v", p)
	}
	if p := people["bob"]; p.Password || p.Keys != 1 {
		t.Errorf("bob: %+v", p)
	}
	// Only the hash is stored.
	if data, err := os.ReadFile(filepath.Join(g.Layout.UsersDir(), "alice.toml")); err != nil || strings.Contains(string(data), "secret one") || !strings.Contains(string(data), "$argon2id$") {
		t.Errorf("alice.toml: %v\n%s", err, data)
	}

	// A gosftpd error comes back as gosftpd wrote it.
	_, err = a.SetAccess(ctx, "bob", map[string]string{"Nope": "read"})
	var ce *CommandError
	if !errors.As(err, &ce) || ce.Code != 2 || !strings.Contains(err.Error(), `unknown mount "Nope"`) {
		t.Errorf("SetAccess with an unknown folder: %v", err)
	}

	// Removing a folder takes it from everyone first.
	if _, err := a.SetFolders(ctx, []Folder{{Name: "Inbox", Path: share}}); err != nil {
		t.Fatal(err)
	}
	people = peopleByName(t, a)
	if !maps.Equal(people["alice"].Access, map[string]string{"Inbox": "upload"}) || len(people["bob"].Access) != 0 {
		t.Errorf("after removing Photos: alice %v, bob %v", people["alice"].Access, people["bob"].Access)
	}
	if _, err := a.SetFolders(ctx, nil); err == nil {
		t.Error("removing the last folder was accepted")
	}

	// Disabling keeps password logins on; removing the last person with a
	// password turns them off.
	if _, err := a.Disable(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := a.Read(ctx); !s.PasswordLogins {
		t.Error("password logins are off while a disabled person has a password")
	}
	if _, err := a.Enable(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetPassword(ctx, "bob", "bobs pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Remove(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := a.Read(ctx); !s.PasswordLogins {
		t.Error("password logins are off while bob has a password")
	}
	if _, err := a.Remove(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if s, _, _ := a.Read(ctx); s.PasswordLogins {
		t.Error("password logins are on with nobody who has a password")
	}
}

func settingsEqual(a, b Settings) bool {
	return slices.Equal(a.Folders, b.Folders) && slices.Equal(a.Listen, b.Listen) && a.OnConflict == b.OnConflict && a.PasswordLogins == b.PasswordLogins
}

func peopleByName(t *testing.T, a Admin) map[string]Person {
	t.Helper()
	ps, err := a.People(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Person{}
	for _, p := range ps {
		out[p.Name] = p
	}
	return out
}

var keyMu sync.Mutex

// testKey returns a new authorized_keys line.
func testKey(t *testing.T) string {
	t.Helper()
	_, pub := newKeyPair(t)
	return pub
}

// newKeyPair makes an ed25519 key pair with ssh-keygen and returns the
// private key's file and the authorized_keys line.
func newKeyPair(t *testing.T) (file, pub string) {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	file = filepath.Join(t.TempDir(), "id_ed25519")
	if out, err := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", file).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen: %v %s", err, out)
	}
	data, err := os.ReadFile(file + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return file, strings.TrimSpace(string(data))
}

// shareWithKey writes a configuration that listens on listen and shares
// share with partner, who logs in with a new key, and returns its file.
func shareWithKey(t *testing.T, g Gosftpd, share, listen string) (key string) {
	t.Helper()
	a := Admin{G: g}
	if _, err := a.Write(t.Context(), Settings{Folders: []Folder{{Name: "Inbox", Path: share}}, Listen: []string{listen}}); err != nil {
		t.Fatal(err)
	}
	key, pub := newKeyPair(t)
	if _, err := a.AddWithKey(t.Context(), "partner", pub, map[string]string{"Inbox": "upload"}); err != nil {
		t.Fatal(err)
	}
	return key
}

func start(t *testing.T, g Gosftpd) (*Server, *[]LogRecord) {
	t.Helper()
	var mu sync.Mutex
	var logs []LogRecord
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	s, err := g.Start(ctx, func(r LogRecord) { mu.Lock(); logs = append(logs, r); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Kill(); <-s.Done() })
	return s, &logs
}

// sftpBatch runs OpenSSH sftp with the batch commands as partner.
func sftpBatch(t *testing.T, d Details, key, batch string) string {
	t.Helper()
	if _, err := exec.LookPath("sftp"); err != nil {
		t.Skip("no OpenSSH sftp")
	}
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(d.KnownHosts+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sftp", "-b", "-", "-i", key, "-P", strconv.Itoa(d.Port),
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known,
		"-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "partner@"+d.Host)
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sftp: %v\n%s", err, out)
	}
	return string(out)
}

func TestServe(t *testing.T) {
	g, share := newGosftpd(t)
	key := shareWithKey(t, g, share, "127.0.0.1:0")
	s, _ := start(t, g)
	d := s.Details
	if d.Host != "127.0.0.1" || d.Port == 0 || d.Version != testVersion(t, g) || len(d.HostKeys) != 1 || !strings.HasPrefix(d.HostKeyFingerprint, "SHA256:") || d.PID != s.cmd.Process.Pid {
		t.Fatalf("details: %+v", d)
	}
	// known_hosts checks the host key: StrictHostKeyChecking=yes.
	file := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(file, make([]byte, 48000), 0o600); err != nil {
		t.Fatal(err)
	}
	sftpBatch(t, d, key, "put "+file+"\nput "+file+"\n")

	// The audit log says what happened.
	f := NewFollower(g.Layout.AuditLog())
	var a Activity
	waitFor(t, func() bool {
		ev, _, err := f.Poll()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ev {
			a.Apply(e)
		}
		return len(a.Transfers) == 2
	})
	if !a.Running || a.Transfers[0].FinalPath != "/report (1).pdf" || a.Transfers[0].Conflict != "renamed" || a.Transfers[0].User != "partner" {
		t.Errorf("activity: %+v", a)
	}
	if runtime.GOOS == "linux" && a.Landlock == "" {
		t.Error("server.start has no landlock field")
	}

	// A reload reports its result.
	if _, err := (Admin{G: g}).SetAccess(t.Context(), "partner", map[string]string{"Inbox": "read"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r, err := s.Reload(ctx, g.Layout.AuditLog())
	if err != nil || !r.OK {
		t.Errorf("Reload = %+v, %v", r, err)
	}

	// A restart: the old gosftpd has exited before the new one serves.
	old := s
	s, err = g.Restart(ctx, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Kill(); <-s.Done() })
	select {
	case <-old.Done():
	default:
		t.Error("the old gosftpd still runs after Restart")
	}
	if s.Details.PID == old.Details.PID || s.Details.HostKeyFingerprint != old.Details.HostKeyFingerprint {
		t.Errorf("after Restart: %+v, before %+v", s.Details, old.Details)
	}

	// Closing gosftpd's stdin stops it, as when the GUI exits: it drains
	// and writes server.stop.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("gosftpd still runs after its stdin was closed")
	}
	if err := s.Err(); err != nil {
		t.Errorf("exit: %v", err)
	}
	ev, _, _ := f.Poll()
	if !slices.ContainsFunc(ev, func(e Event) bool { return e.Name == "server.stop" }) {
		t.Errorf("no server.stop after the reload: %q", names(ev))
	}
	if _, err := s.Reload(ctx, g.Layout.AuditLog()); !errors.Is(err, ErrNotRunning) {
		t.Errorf("Reload after the exit: %v", err)
	}
}

func TestServeStop(t *testing.T) {
	g, share := newGosftpd(t)
	shareWithKey(t, g, share, "127.0.0.1:0")
	s, logs := start(t, g)
	s.Stop()
	s.Stop() // a second Stop sends nothing more
	select {
	case <-s.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("gosftpd still runs after Stop")
	}
	if err := s.Err(); err != nil {
		t.Errorf("exit: %v", err)
	}
	if !slices.ContainsFunc(*logs, func(r LogRecord) bool { return r.Msg == "shutting down" }) {
		t.Errorf("no JSON log record \"shutting down\": %+v", *logs)
	}
}

func TestServeStopNow(t *testing.T) {
	g, share := newGosftpd(t)
	shareWithKey(t, g, share, "127.0.0.1:0")
	s, _ := start(t, g)
	done := make(chan struct{})
	go func() { s.StopNow(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("StopNow did not return")
	}
	select {
	case <-s.Done():
	default:
		t.Error("gosftpd runs after StopNow")
	}
}

func TestServePortInUse(t *testing.T) {
	g, share := newGosftpd(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	shareWithKey(t, g, share, ln.Addr().String())
	_, err = g.Start(t.Context(), nil)
	var se *StartError
	if !errors.As(err, &se) || se.Kind != "listen" || se.Address != ln.Addr().String() || se.Code != 1 || !strings.Contains(se.Message, "address already in use") {
		t.Errorf("Start = %#v", err)
	}
}

func TestServeConfigMissing(t *testing.T) {
	g, _ := newGosftpd(t)
	if err := g.Layout.Ensure(); err != nil {
		t.Fatal(err)
	}
	_, err := g.Start(t.Context(), nil)
	var se *StartError
	if !errors.As(err, &se) || se.Kind != "config" || se.Code != 2 || !strings.Contains(se.Stderr, "Error: ") {
		t.Errorf("Start = %#v", err)
	}
}

// TestKilledGUI: a GUI killed abruptly leaves no gosftpd running. The
// child process runs a Server and is killed with SIGKILL.
func TestKilledGUI(t *testing.T) {
	if os.Getenv("SUPERVISOR_CHILD") != "" {
		g := Gosftpd{Bin: os.Getenv("SUPERVISOR_BIN"), Layout: Layout{Dir: os.Getenv("SUPERVISOR_DIR")}}
		s, err := g.Start(context.Background(), nil)
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("pid", s.Details.PID)
		select {}
	}
	g, share := newGosftpd(t)
	shareWithKey(t, g, share, "127.0.0.1:0")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestKilledGUI$")
	cmd.Env = append(os.Environ(), "SUPERVISOR_CHILD=1", "SUPERVISOR_BIN="+testBin, "SUPERVISOR_DIR="+g.Layout.Dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Fscanf(out, "pid %d\n", &pid); err != nil || pid == 0 {
		_ = cmd.Process.Kill()
		t.Fatalf("child: %v", err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	waitFor(t, func() bool { return !servesLayout(pid, g.Layout) })
	f := NewFollower(g.Layout.AuditLog())
	ev, _, _ := f.Poll()
	if !slices.ContainsFunc(ev, func(e Event) bool { return e.Name == "server.stop" }) {
		t.Errorf("no server.stop after the GUI was killed: %q", names(ev))
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
