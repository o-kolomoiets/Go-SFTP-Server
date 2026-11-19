// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// people returns the people of the configuration by name.
func people(t *testing.T, a *App) map[string]supervisor.Person {
	t.Helper()
	cur, err := a.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]supervisor.Person{}
	for _, p := range cur.People {
		out[p.Name] = p
	}
	return out
}

// Changes made while sharing are read by gosftpd at once.
func TestManageWhileSharing(t *testing.T) {
	a, inbox, docs := newApp(t)
	ctx := t.Context()
	key, pub := gosftpdtest.KeyPair(t)
	if _, err := a.Apply(ctx, Current{}, Form{
		Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}, {Name: "Docs", Path: docs, ReadOnly: true}},
		Port:    gosftpdtest.FreePort(t),
		Person:  NewPerson{Name: "partner", Key: pub},
	}); err != nil {
		t.Fatal(err)
	}
	d, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a.Sharing() {
			a.StopNow()
			<-a.Done()
			_ = a.Exited()
		}
	})
	reloaded := func(what string, c Change, err error) {
		t.Helper()
		if err != nil || !c.Reloaded || c.ReloadFailed != "" {
			t.Fatalf("%s: %+v, %v", what, c, err)
		}
	}

	// A person with a password: password logins go on.
	c, err := a.AddPerson(ctx, NewPerson{Name: "bob", Password: "correct horse"}, map[string]string{"Inbox": "upload"})
	reloaded("add bob", c, err)
	if p := people(t, a)["bob"]; !p.Password || p.Access["Inbox"] != "upload" {
		t.Errorf("bob = %+v", p)
	}
	if _, err := a.AddPerson(ctx, NewPerson{Name: "carol"}, map[string]string{"Inbox": "upload"}); err == nil {
		t.Error("a person with neither a password nor a key was added")
	}
	if _, err := a.AddPerson(ctx, NewPerson{Name: "bob", Key: pub}, map[string]string{"Inbox": "upload"}); err == nil {
		t.Error("a second bob was added")
	}

	c, err = a.SetAccess(ctx, "bob", map[string]string{"Inbox": "readwrite", "Docs": "read"})
	reloaded("bob's access", c, err)
	if p := people(t, a)["bob"]; p.Access["Inbox"] != "readwrite" || p.Access["Docs"] != "read" {
		t.Errorf("bob's access = %v", p.Access)
	}
	c, err = a.SetPassword(ctx, "partner", "another one")
	reloaded("partner's password", c, err)
	if p := people(t, a)["partner"]; !p.Password || p.Keys != 1 {
		t.Errorf("partner = %+v", p)
	}

	// Disabling a person ends their connections.
	gosftpdtest.Session(t, reachable(t, d), d.Port, d.KnownHosts, "partner", key)
	waitFor(t, "partner to be connected", func() bool {
		s, err := a.Poll()
		return err == nil && slices.Contains(Names(s), "partner")
	})
	c, err = a.Disable(ctx, "partner")
	reloaded("disable partner", c, err)
	if c.Disconnected != 1 || people(t, a)["partner"].Status != "disabled" {
		t.Errorf("disable partner: %+v, %+v", c, people(t, a)["partner"])
	}
	c, err = a.Enable(ctx, "partner")
	reloaded("enable partner", c, err)

	c, err = a.SetOnConflict(ctx, "reject")
	reloaded("on_conflict", c, err)
	if cur, _ := a.Load(ctx); cur.Settings.OnConflict != "reject" {
		t.Errorf("on_conflict = %q", cur.Settings.OnConflict)
	}
	if _, err := a.SetOnConflict(ctx, "keep"); err == nil {
		t.Error("on_conflict \"keep\" was accepted")
	}

	// Docs goes: the people lose it.
	c, err = a.SetFolders(ctx, []supervisor.Folder{{Name: "Inbox", Path: inbox}})
	reloaded("remove Docs", c, err)
	for name, p := range people(t, a) {
		if _, ok := p.Access["Docs"]; ok {
			t.Errorf("%s still has Docs: %v", name, p.Access)
		}
	}
	if _, err := a.SetFolders(ctx, nil); err == nil {
		t.Error("the last folder was removed")
	}

	// A new folder: under Landlock it needs a restart (ADR 0011).
	photos := filepath.Join(filepath.Dir(inbox), "Photos")
	if err := os.Mkdir(photos, 0o755); err != nil {
		t.Fatal(err)
	}
	c, err = a.SetFolders(ctx, []supervisor.Folder{{Name: "Inbox", Path: inbox}, {Name: "Photos", Path: photos}})
	if err != nil || c.ReloadFailed != "" {
		t.Fatalf("add Photos: %+v, %v", c, err)
	}
	landlock := a.Landlock()
	if strings.HasPrefix(landlock, "v") != (len(c.RestartRequired) > 0) {
		t.Errorf("landlock %q, restart required %q", landlock, c.RestartRequired)
	}

	// Removing bob, who had the only password, turns password logins
	// off, and partner's own password keeps them on.
	c, err = a.Remove(ctx, "bob")
	reloaded("remove bob", c, err)
	if cur, _ := a.Load(ctx); !cur.Settings.PasswordLogins {
		t.Error("password logins went off while partner has a password")
	}
}

// A restart serves again, and the exit of the server it replaced is not
// reported.
func TestRestart(t *testing.T) {
	a, inbox, _ := newApp(t)
	ctx := t.Context()
	_, pub := gosftpdtest.KeyPair(t)
	if _, err := a.Restart(ctx); !errors.Is(err, ErrNotSharing) {
		t.Errorf("Restart while not sharing = %v", err)
	}
	if _, err := a.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	d1, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDone := a.Done()
	d2, err := a.Restart(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.StopNow(); <-a.Done(); _ = a.Exited() })
	<-oldDone
	if d2.PID == d1.PID || d2.Port != d1.Port || d2.HostKeyFingerprint != d1.HostKeyFingerprint {
		t.Errorf("before %+v, after %+v", d1, d2)
	}
	if err := a.Exited(); err != nil || !a.Sharing() {
		t.Errorf("Exited after a restart = %v, sharing %v", err, a.Sharing())
	}
}

func TestLogSince(t *testing.T) {
	a := &App{}
	for _, r := range []supervisor.LogRecord{
		{Level: "WARN", Msg: "first"},
		{Level: "INFO", Msg: "not kept"},
		{Level: "ERROR", Msg: "reload failed", Attrs: map[string]any{"err": "boom"}},
	} {
		a.log(r)
	}
	if got := a.logSince(t.Context(), 1); got != "ERROR reload failed err=boom" {
		t.Errorf("logSince(1) = %q", got)
	}
	if got := a.LogTail(); len(got) != 2 {
		t.Errorf("LogTail = %q", got)
	}
}

// A change that fails half-way is still read by gosftpd, or the window
// learns that gosftpd refused it: never a file that says one thing and a
// server that does another, unseen.
func TestHalfDoneChange(t *testing.T) {
	a, inbox, docs := newApp(t)
	ctx := t.Context()
	if _, err := a.Apply(ctx, Current{}, Form{
		Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}, {Name: "Docs", Path: docs}},
		Port:    gosftpdtest.FreePort(t),
		Person:  NewPerson{Name: "bob", Password: "correct horse"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.StopNow(); <-a.Done(); _ = a.Exited() })
	if err := os.Rename(docs, docs+".gone"); err != nil {
		t.Fatal(err)
	}
	// Removing bob, who has the only password, then fails to turn
	// password logins off: init refuses the missing Docs.
	c, err := a.Remove(ctx, "bob")
	if err == nil {
		t.Fatal("Remove succeeded with a folder missing")
	}
	if !c.Reloaded && c.ReloadFailed == "" {
		t.Errorf("no reload after a half-done change: %+v", c)
	}
	t.Logf("change: %+v, err: %v", c, err)
}
