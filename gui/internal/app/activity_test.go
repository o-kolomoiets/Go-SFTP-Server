// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

func TestDescribe(t *testing.T) {
	for _, tc := range []struct {
		e      supervisor.Event
		what   string
		file   string
		failed bool
	}{
		{supervisor.Event{Name: "fs.upload", Path: "/r.pdf", FinalPath: "/r.pdf", Bytes: 7, Result: "ok"}, "Uploaded", "/r.pdf", false},
		{supervisor.Event{Name: "fs.upload", Path: "/r.pdf", FinalPath: "/r (1).pdf", Conflict: "renamed", Result: "ok"}, "Uploaded under another name: /r.pdf existed", "/r (1).pdf", false},
		{supervisor.Event{Name: "fs.upload", Path: "/r.pdf", Conflict: "overwritten", Result: "ok"}, "Uploaded, replacing the file", "/r.pdf", false},
		{supervisor.Event{Name: "fs.upload", Path: "/r.pdf", Result: "eof"}, "Uploaded (failed: eof)", "/r.pdf", true},
		{supervisor.Event{Name: "fs.download", Path: "/d.txt", Result: "ok"}, "Downloaded", "/d.txt", false},
		{supervisor.Event{Name: "fs.rename", Path: "/a.tmp", TargetPath: "/a", FinalPath: "/a", Result: "ok"}, "Renamed", "/a.tmp → /a", false},
		{supervisor.Event{Name: "fs.remove", Path: "/x", Result: "ok"}, "Deleted", "/x", false},
		{supervisor.Event{Name: "fs.denied", Op: "write", Path: "/docs/x", Reason: "read_only"}, "Refused to write: read only", "/docs/x", true},
		{supervisor.Event{Name: "fs.denied", Op: "fs.remove", Path: "/photo.jpg", Reason: "permission_denied"}, "Refused to delete: permission denied", "/photo.jpg", true},
		{supervisor.Event{Name: "fs.denied", Op: "chown", Path: "/x", Reason: "unsupported"}, "Refused (chown): unsupported", "/x", true},
		{supervisor.Event{Name: "fs.denied", Reason: "mount_unavailable", Mount: "Inbox"}, "Refused: mount unavailable", "Inbox", true},
	} {
		en := Describe(tc.e)
		if en.What != tc.what || en.File != tc.file || en.Failed != tc.failed {
			t.Errorf("Describe(%+v) = %+v, want %q %q %v", tc.e, en, tc.what, tc.file, tc.failed)
		}
	}
}

func TestFilter(t *testing.T) {
	es := []Entry{
		{User: "alice", What: "Uploaded", File: "/Inbox/report.pdf"},
		{User: "bob", What: "Downloaded", File: "/Docs/plan.odt"},
		{User: "bob", What: "Refused to write: read only", File: "/Docs/x", Failed: true},
	}
	for text, want := range map[string]int{"": 3, "BOB": 2, "report": 1, "refused": 1, "/docs": 2, "nobody": 0} {
		if got := Filter(es, text); len(got) != want {
			t.Errorf("Filter(%q) = %d entries, want %d", text, len(got), want)
		}
	}
}

func TestPlainRecord(t *testing.T) {
	if got := PlainRecord(supervisor.LogRecord{Level: "WARN", Msg: "mount unavailable", Attrs: map[string]any{"err": "x"}}); !strings.HasPrefix(got, "A shared folder cannot be opened") {
		t.Errorf("mount unavailable: %q", got)
	}
	if got := PlainRecord(supervisor.LogRecord{Level: "WARN", Msg: "banning source after repeated login failures", Attrs: map[string]any{"source": "192.0.2.7"}}); !strings.HasSuffix(got, "repeated failed logins: 192.0.2.7.") {
		t.Errorf("ban: %q", got)
	}
	if got := PlainRecord(supervisor.LogRecord{Level: "WARN", Msg: "something new", Attrs: map[string]any{"k": "v"}}); got != "WARN something new k=v" {
		t.Errorf("unknown: %q", got)
	}
}

func TestPrefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "gosftpd-gui.conf")
	if p, err := LoadPrefs(path); err != nil || p != (Prefs{}) {
		t.Fatalf("no file: %+v, %v", p, err)
	}
	if err := SavePrefs(path, Prefs{ActivityFrom: 42, ActivityLog: "1:2"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v, %v", fi, err)
	}
	if p, err := LoadPrefs(path); err != nil || p.ActivityFrom != 42 || p.ActivityLog != "1:2" {
		t.Errorf("read back: %+v, %v", p, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrefs(path); err == nil {
		t.Error("a broken file was read")
	}
}

// The activity lists the transfers, and Clear activity hides them, also
// for the next GUI: the audit log is not changed.
func TestActivity(t *testing.T) {
	a, inbox, _ := newApp(t)
	a.PrefsPath = filepath.Join(t.TempDir(), "gosftpd-gui.conf")
	ctx := t.Context()
	if s, err := a.Activity(); err != nil || s.Sharing || len(s.Entries) != 0 {
		t.Fatalf("before the first share: %+v, %v", s, err)
	}
	key, pub := gosftpdtest.KeyPair(t)
	if _, err := a.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	d, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.StopNow(); <-a.Done(); _ = a.Exited() })
	file := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(file, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	upload := func(name string) {
		t.Helper()
		gosftpdtest.SFTP(t, reachable(t, d), d.Port, d.KnownHosts, "partner", key, "put "+file+" /"+name+"\n")
	}
	entries := func() []Entry {
		t.Helper()
		s, err := a.Activity()
		if err != nil {
			t.Fatal(err)
		}
		return s.Entries
	}
	upload("one.pdf")
	waitFor(t, "the upload in the activity", func() bool {
		es := entries()
		return len(es) == 1 && es[0].What == "Uploaded" && es[0].User == "partner" && es[0].File == "/one.pdf" && es[0].Bytes == 6
	})
	if s, _ := a.Activity(); !s.Sharing || s.Landlock == "" {
		t.Errorf("snapshot while sharing: %+v", s)
	}

	size := func() int64 {
		fi, err := os.Stat(a.G.Layout.AuditLog())
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	before := size()
	if err := a.ClearActivity(); err != nil {
		t.Fatal(err)
	}
	if len(entries()) != 0 || size() != before {
		t.Errorf("after Clear activity: %d entries, log %d bytes (was %d)", len(entries()), size(), before)
	}
	upload("two.pdf")
	waitFor(t, "the second upload", func() bool { es := entries(); return len(es) == 1 && es[0].File == "/two.pdf" })

	// The next GUI starts where Clear activity left the view.
	next := &App{G: a.G, PrefsPath: a.PrefsPath}
	if s, err := next.Activity(); err != nil || len(s.Entries) != 1 || s.Entries[0].File != "/two.pdf" {
		t.Errorf("the next GUI: %+v, %v", s.Entries, err)
	}
	// A log rotated by rename, which a reload makes gosftpd open anew
	// (docs/audit-log.md), is shown from its start.
	if err := os.Rename(a.G.Layout.AuditLog(), a.G.Layout.AuditLog()+".1"); err != nil {
		t.Fatal(err)
	}
	if c, err := a.SetOnConflict(ctx, "rename"); err != nil || !c.Reloaded {
		t.Fatalf("reload: %+v, %v", c, err)
	}
	upload("three.pdf")
	rotated := &App{G: a.G, PrefsPath: a.PrefsPath}
	waitFor(t, "the rotated log", func() bool {
		s, _ := rotated.Activity()
		return len(s.Entries) > 0 && s.Entries[0].File == "/three.pdf"
	})
}
