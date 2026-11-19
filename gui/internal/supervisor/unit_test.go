// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestChildEnv(t *testing.T) {
	got := childEnv([]string{"HOME=/h", "GOSFTPD_LISTEN=:1", "GOSFTPD_LOG_FORMAT=text", "NOTIFY_SOCKET=/run/x", "PATH=/bin", "XGOSFTPD_Y=1"})
	want := []string{"HOME=/h", "PATH=/bin", "XGOSFTPD_Y=1"}
	if !slices.Equal(got, want) {
		t.Errorf("childEnv = %q, want %q", got, want)
	}
}

func TestGosftpdCandidates(t *testing.T) {
	if got := gosftpdCandidates("darwin", "/Applications/gosftpd-gui.app/Contents/MacOS/gosftpd-gui"); !slices.Equal(got, []string{"/Applications/gosftpd-gui.app/Contents/MacOS/gosftpd"}) {
		t.Errorf("darwin: %q", got)
	}
	// Never next to /usr/bin/gosftpd-gui, where the server package's
	// gosftpd may be, nor PATH.
	got := gosftpdCandidates("linux", "/usr/bin/gosftpd-gui")
	if !slices.Equal(got, []string{"/usr/libexec/gosftpd-gui/gosftpd", "/usr/lib/gosftpd-gui/gosftpd"}) {
		t.Errorf("linux: %q", got)
	}

	dir := t.TempDir()
	notExec, exe := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(notExec, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if p, err := findGosftpd([]string{filepath.Join(dir, "missing"), notExec, dir, exe}); err != nil || p != exe {
		t.Errorf("findGosftpd = %q, %v; want %q", p, err, exe)
	}
	if _, err := findGosftpd([]string{notExec}); !errors.Is(err, ErrNoGosftpd) {
		t.Errorf("findGosftpd: %v, want ErrNoGosftpd", err)
	}
}

func TestLayout(t *testing.T) {
	l := Layout{Dir: filepath.Join(t.TempDir(), "state")}
	if l.Exists() {
		t.Error("Exists before the configuration is written")
	}
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(l.Dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state directory: %v, %v", fi, err)
	}
	if l.AuditLog() != filepath.Join(l.Dir, "audit", "audit.jsonl") || l.Config() != filepath.Join(l.Dir, "config.toml") {
		t.Errorf("paths: %s %s", l.AuditLog(), l.Config())
	}
}

func TestRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if d, err := RuntimeDir(); err != nil || d != "/run/user/1000" {
		t.Errorf("with XDG_RUNTIME_DIR: %q, %v", d, err)
	}
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	d, err := RuntimeDir()
	if err != nil || filepath.Dir(d) != tmp {
		t.Fatalf("without: %q, %v", d, err)
	}
	if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v, %v", d, fi, err)
	}
	// A directory of the wrong mode there is refused.
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := RuntimeDir(); err == nil {
		t.Error("a directory with mode 0755 was accepted")
	}
}

func TestPasswords(t *testing.T) {
	for _, p := range []string{"", "a\nb", "a\rb", "tab\there", "\x00"} {
		if CheckPassword(p) == nil {
			t.Errorf("CheckPassword(%q) accepted", p)
		}
	}
	if err := CheckPassword("correct horse ☃"); err != nil {
		t.Error(err)
	}
	re := regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`)
	a, b := GeneratePassword(), GeneratePassword()
	if !re.MatchString(a) || a == b {
		t.Errorf("GeneratePassword: %q, %q", a, b)
	}
}

func TestAccessArgs(t *testing.T) {
	if got := accessArgs(map[string]string{"photos": "read", "inbox": "upload"}); !slices.Equal(got, []string{"--access", "inbox=upload", "--access", "photos=read"}) {
		t.Errorf("accessArgs = %q", got)
	}
	if got := accessArgs(nil); !slices.Equal(got, []string{"--no-access"}) {
		t.Errorf("accessArgs(nil) = %q", got)
	}
}

func TestParseLogLine(t *testing.T) {
	r := parseLogLine([]byte(`{"time":"2026-11-19T10:00:00.5Z","level":"WARN","msg":"landlock","detail":"x"}`))
	if r.Level != "WARN" || r.Msg != "landlock" || r.Attrs["detail"] != "x" || r.Time.IsZero() || r.Text != "" || len(r.Attrs) != 1 {
		t.Errorf("JSON line: %+v", r)
	}
	if r := parseLogLine([]byte("Error: listen tcp :2022: bind: address already in use")); r.Text == "" || r.Msg != "" {
		t.Errorf("text line: %+v", r)
	}
}

func TestSFTPCommand(t *testing.T) {
	for _, tt := range []struct {
		d    Details
		want string
	}{
		{Details{Host: "vm", Port: 2022}, "sftp -P 2022 partner@vm"},
		{Details{Host: "vm", Port: 22}, "sftp partner@vm"},
		{Details{Host: "2001:db8::1", Port: 2022}, "sftp -P 2022 partner@[2001:db8::1]"},
	} {
		if got := tt.d.SFTPCommand("partner"); got != tt.want {
			t.Errorf("%+v: %q, want %q", tt.d, got, tt.want)
		}
	}
}

func appendLine(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func names(events []Event) []string {
	var out []string
	for _, e := range events {
		out = append(out, e.Name)
	}
	return out
}

func TestFollower(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f := NewFollower(path)
	if ev, reset, err := f.Poll(); err != nil || ev != nil || reset {
		t.Fatalf("missing file: %v %v %v", ev, reset, err)
	}
	appendLine(t, path, `{"event":"server.start","landlock":"v5"}`+"\n"+`{"event":"session.start","conn_id":"c1","session_id":"s1","user":"partner"}`+"\n"+`{"event":"fs.up`)
	ev, reset, err := f.Poll()
	if err != nil || reset || !slices.Equal(names(ev), []string{"server.start", "session.start"}) || ev[0].Landlock != "v5" || ev[1].User != "partner" {
		t.Fatalf("first poll: %+v %v %v", ev, reset, err)
	}
	// The rest of a line being written, and a line that is not an event.
	appendLine(t, path, `load","path":"/r.pdf","final_path":"/r (1).pdf","conflict":"renamed","bytes":48000}`+"\nnot json\n")
	ev, _, _ = f.Poll()
	if len(ev) != 1 || ev[0].Name != "fs.upload" || ev[0].FinalPath != "/r (1).pdf" || ev[0].Bytes != 48000 {
		t.Fatalf("second poll: %+v", ev)
	}
	if ev, _, _ := f.Poll(); ev != nil {
		t.Errorf("nothing new: %+v", ev)
	}

	// Truncated ("Clear activity" by hand, copytruncate): from the start.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"event":"server.stop"}`+"\n")
	if ev, reset, _ := f.Poll(); !reset || !slices.Equal(names(ev), []string{"server.stop"}) {
		t.Errorf("after truncation: %+v, reset %v", ev, reset)
	}
	// Replaced by another file (rotation by rename), even a longer one.
	other := path + ".new"
	appendLine(t, other, strings.Repeat(`{"event":"conn.reject"}`+"\n", 5))
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if ev, reset, _ := f.Poll(); !reset || len(ev) != 5 {
		t.Errorf("after rotation: %d events, reset %v", len(ev), reset)
	}
	// Deleted.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, reset, _ := f.Poll(); !reset {
		t.Error("deletion: no reset")
	}
}

func TestFollowerSkip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f := NewFollower(path)
	if err := f.Skip(); err != nil || f.Offset() != 0 {
		t.Fatalf("missing file: offset %d, %v", f.Offset(), err)
	}
	appendLine(t, path, `{"event":"server.start"}`+"\n"+`{"event":"server.stop"}`+"\n")
	if err := f.Skip(); err != nil {
		t.Fatal(err)
	}
	appendLine(t, path, `{"event":"server.start","landlock":"off"}`+"\n")
	if ev, reset, err := f.Poll(); err != nil || reset || !slices.Equal(names(ev), []string{"server.start"}) {
		t.Errorf("after Skip: %+v, reset %v, %v", ev, reset, err)
	}
}

func TestActivity(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	var a Activity
	for _, e := range []Event{
		{Name: "server.start", Landlock: "v5"},
		{Name: "session.start", ConnID: "c1", SessionID: "s1", User: "bob", Time: t0.Add(time.Second)},
		{Name: "session.start", ConnID: "c2", SessionID: "s1", User: "alice", Time: t0},
		{Name: "fs.upload", User: "bob", FinalPath: "/a"},
		{Name: "fs.list", User: "bob"}, // not a transfer
		{Name: "fs.download", User: "alice", Path: "/b"},
	} {
		a.Apply(e)
	}
	if !a.Running || a.Landlock != "v5" {
		t.Errorf("state: %+v", a)
	}
	if c := a.Connected(); len(c) != 2 || c[0].User != "alice" || c[1].User != "bob" {
		t.Errorf("connected: %+v", c)
	}
	if len(a.Transfers) != 2 || a.Transfers[0].Name != "fs.download" {
		t.Errorf("transfers, newest first: %+v", a.Transfers)
	}
	a.Apply(Event{Name: "session.end", ConnID: "c1", SessionID: "s1"})
	a.Apply(Event{Name: "conn.close", ConnID: "c2"})
	if len(a.Sessions) != 0 {
		t.Errorf("after session.end and conn.close: %+v", a.Sessions)
	}

	// A stop cut short writes no session.end: the next server.start, or
	// the exit, clears the sessions.
	a.Apply(Event{Name: "session.start", ConnID: "c3", SessionID: "s1"})
	a.Apply(Event{Name: "server.start"})
	if len(a.Sessions) != 0 {
		t.Error("server.start kept a session of the server before")
	}
	a.Apply(Event{Name: "session.start", ConnID: "c4", SessionID: "s1"})
	a.Exited()
	if a.Running || len(a.Sessions) != 0 {
		t.Errorf("after the exit: %+v", a)
	}

	for range MaxTransfers + 10 {
		a.Apply(Event{Name: "fs.upload"})
	}
	if len(a.Transfers) != MaxTransfers {
		t.Errorf("%d transfers kept", len(a.Transfers))
	}
	a.Reset()
	if len(a.Transfers) != 0 {
		t.Error("Reset kept the transfers")
	}
}

func TestReloadResult(t *testing.T) {
	r := Event{Name: "server.reload", Result: "ok", RestartRequired: "mounts.photos.path, mounts.inbox.read_only"}.reloadResult()
	if !r.OK || !slices.Equal(r.RestartRequired, []string{"mounts.photos.path", "mounts.inbox.read_only"}) {
		t.Errorf("%+v", r)
	}
	if r := (Event{Name: "server.reload", Result: "error", Reason: "config"}).reloadResult(); r.OK || r.Reason != "config" || r.RestartRequired != nil {
		t.Errorf("%+v", r)
	}
	var e Event
	if err := json.Unmarshal([]byte(`{"event":"server.reload","result":"ok","disconnected":2}`), &e); err != nil || e.reloadResult().Disconnected != 2 {
		t.Errorf("disconnected: %+v %v", e, err)
	}
}
