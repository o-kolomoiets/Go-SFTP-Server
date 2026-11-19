// SPDX-License-Identifier: Apache-2.0

//go:build unix

package qtui

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mappu/miqt/qt6/mainthread"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

func TestIncludes(t *testing.T) {
	for _, tc := range []struct {
		before, after map[string]string
		narrows       bool
	}{
		{map[string]string{"A": "read"}, map[string]string{"A": "read", "B": "upload"}, false},
		{map[string]string{"A": "read"}, map[string]string{"A": "readwrite"}, false},
		{map[string]string{"A": "upload"}, map[string]string{"A": "full"}, false},
		{map[string]string{"A": "readwrite"}, map[string]string{"A": "read"}, true},
		{map[string]string{"A": "read"}, map[string]string{"A": "upload"}, true},
		{map[string]string{"A": "read"}, map[string]string{}, true},
		{map[string]string{"A": "list,read"}, map[string]string{"A": "full"}, true}, // set by hand: any change counts
	} {
		if got := narrows(tc.before, tc.after); got != tc.narrows {
			t.Errorf("narrows(%v, %v) = %v", tc.before, tc.after, got)
		}
	}
}

// person returns the row of the person named name, nil if none.
func person(w *Window, name string) *personRow {
	for _, r := range w.peopleRows {
		if r.p.Name == name {
			return r
		}
	}
	return nil
}

// People and folders change while sharing, read by gosftpd at once; a
// person connected keeps the old access until Restart now.
func TestManageWhileSharing(t *testing.T) {
	w, a, share := newWindow(t, Options{})
	key, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	mainthread.Wait(func() {
		w.confirm = func(string, string) bool { return true }
		w.AddFolder(share)
		w.name.SetText("partner")
		w.useKey.SetChecked(true)
		w.key.SetText(pub)
		w.port.SetValue(port)
		w.start.Click()
	})
	waitFor(t, "sharing", func() bool { return w.state == sharing })
	idle := func(what string) {
		t.Helper()
		waitFor(t, what, func() bool { return !w.busy && w.state == sharing })
	}
	status := func() string { return on(func() string { return w.status.Text() }) }

	// Add a person while sharing: the form's Add person.
	mainthread.Wait(func() {
		if !w.addPersonB.IsVisible() || !w.addPersonB.IsEnabled() || !w.name.IsEnabled() {
			t.Error("Add person is not usable while sharing")
		}
		w.name.SetText("bob")
		w.usePassword.SetChecked(true)
		w.password.SetText("correct horse")
		w.addPersonB.Click()
	})
	idle("bob to be added")
	mainthread.Wait(func() {
		r := person(w, "bob")
		if r == nil || r.p.Access["Inbox"] != "upload" || !r.p.Password {
			t.Fatalf("bob: %+v (status %q)", r, w.status.Text())
		}
		if r.access.AccessibleName() != "Access of bob" || r.remove.AccessibleName() != "Remove bob" {
			t.Errorf("accessible names: %q, %q", r.access.AccessibleName(), r.remove.AccessibleName())
		}
		if w.name.Text() != "" || w.password.Text() != "" {
			t.Error("the form keeps the person added")
		}
		// The details show bob: disabling him shows partner instead.
		w.user = "bob"
		w.toggle(r.p)
	})
	idle("bob to be disabled")
	if got := on(func() string { return w.fields["user"].Text() }); got != "partner" {
		t.Errorf("the details show %q after bob was disabled", got)
	}
	if s := status(); !strings.Contains(s, "bob may no longer log in") {
		t.Errorf("status after Disable: %q", s)
	}
	mainthread.Wait(func() {
		if r := person(w, "bob"); r == nil || r.p.Status != "disabled" || r.toggle.Text() != "Enable" {
			t.Errorf("bob after Disable: %+v", r)
		}
		w.removePerson(person(w, "bob").p)
	})
	idle("bob to be removed")
	if on(func() bool { return person(w, "bob") != nil }) {
		t.Error("bob is still listed")
	}

	// on_conflict, at once.
	mainthread.Wait(func() {
		w.onConflict.SetCurrentIndex(1)
		w.setOnConflict(1)
	})
	idle("on_conflict")
	if got := on(func() string { return w.cur.Settings.OnConflict }); got != "reject" {
		t.Errorf("on_conflict = %q", got)
	}

	// partner connects, and loses upload to Inbox: they keep it until
	// Restart now, which the window offers.
	d := supervisor.Details{
		Host:       on(func() string { return w.fields["host"].Text() }),
		KnownHosts: on(func() string { return w.fields["known_hosts"].Text() }),
	}
	d.Port, _ = strconv.Atoi(on(func() string { return w.fields["port"].Text() }))
	if _, err := net.DefaultResolver.LookupHost(t.Context(), d.Host); err != nil {
		t.Skipf("the host name %q does not resolve: %v", d.Host, err)
	}
	end := gosftpdtest.Session(t, d.Host, d.Port, d.KnownHosts, "partner", key)
	waitFor(t, "partner to be connected", func() bool { return slices.Contains(w.who, "partner") })
	mainthread.Wait(func() { w.applyAccess(person(w, "partner").p, map[string]string{"Inbox": "read"}) })
	idle("partner's access")
	if s := status(); !strings.Contains(s, "partner keeps the old access") || !on(func() bool { return w.restartNow.IsVisible() }) {
		t.Errorf("status after narrowing a connected person's access: %q, Restart now visible %v", s, on(func() bool { return w.restartNow.IsVisible() }))
	}
	command := on(func() string { return w.fields["command"].Text() })
	// The session ends first: a stop waits up to 30 s for it.
	end()
	mainthread.Wait(func() { w.restartNow.Click() })
	waitFor(t, "the restart", func() bool { return w.state == sharing && !w.restartNow.IsVisible() })
	if s := status(); s != "The server started again with the changes." {
		t.Errorf("status after Restart now: %q", s)
	}
	if !a.Sharing() || on(func() string { return w.fields["command"].Text() }) != command {
		t.Error("not sharing, or other details, after the restart")
	}

	// A second folder while sharing, then Docs read-only.
	docs := filepath.Join(filepath.Dir(share), "Docs")
	if err := os.Mkdir(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	mainthread.Wait(func() { w.AddFolder(docs) })
	waitFor(t, "Docs to be shared", func() bool { return !w.busy && w.state == sharing && len(w.folders) == 2 })
	mainthread.Wait(func() {
		r := w.folders[0] // Docs, by name
		if r.folder.Name != "Docs" {
			t.Fatalf("folders: %q", folderNames(w))
		}
		r.access.SetCurrentIndex(accessRead)
		w.folderAccessChanged(r)
	})
	waitFor(t, "Docs to be read-only", func() bool { return !w.busy && w.state == sharing })
	mainthread.Wait(func() {
		if !w.cur.Settings.Folders[0].ReadOnly {
			t.Errorf("Docs: %+v (status %q)", w.cur.Settings.Folders[0], w.status.Text())
		}
	})
}

func TestPathsMove(t *testing.T) {
	for _, tc := range []struct {
		before, after map[string]string
		want          string // "" for no move
	}{
		{map[string]string{"Inbox": "upload"}, map[string]string{"Inbox": "upload", "Docs": "read"}, "/Inbox/report.pdf"},
		{map[string]string{"Inbox": "upload", "Docs": "read"}, map[string]string{"Docs": "read"}, "/Docs/report.pdf becomes /report.pdf"},
		{map[string]string{"Inbox": "upload"}, map[string]string{"Inbox": "read"}, ""},
		{map[string]string{"Inbox": "upload", "Docs": "read"}, map[string]string{"Inbox": "read", "Docs": "full"}, ""},
		{map[string]string{}, map[string]string{"Inbox": "upload"}, ""},
		{map[string]string{"Inbox": "upload"}, map[string]string{}, ""},
	} {
		got := pathsMove("partner", tc.before, tc.after)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("pathsMove(%v, %v) = %q, want %q", tc.before, tc.after, got, tc.want)
		}
	}
}

// A change that ends after gosftpd stopped leaves the stop's message,
// and offers no restart.
func TestChangedAfterExit(t *testing.T) {
	w, _, _ := newWindow(t, Options{})
	mainthread.Wait(func() {
		w.state = idle
		w.setStatus("Error: gosftpd stopped unexpectedly: signal: killed")
		w.changed("Uploads to an existing file: refuse the upload.", nil, app.Change{Reloaded: true, RestartRequired: []string{"mounts.Docs.path"}}, nil, true)
		if s := w.status.Text(); s != "Error: gosftpd stopped unexpectedly: signal: killed" || w.offerRestart || w.state != idle {
			t.Errorf("status %q, offer restart %v, state %d", s, w.offerRestart, w.state)
		}
		if !strings.Contains(w.more.ToPlainText(), "applies when sharing starts again") {
			t.Errorf("details: %q", w.more.ToPlainText())
		}
	})
}

// Restart now does nothing when gosftpd exited while its question was
// open.
func TestRestartAfterQuestion(t *testing.T) {
	w, _, _ := newWindow(t, Options{})
	mainthread.Wait(func() {
		w.state, w.who = sharing, []string{"partner"}
		w.confirm = func(string, string) bool { w.state = idle; return true }
		w.restart(true)
		if w.state != idle {
			t.Errorf("state %d after the question", w.state)
		}
	})
}

// Closing the window during a change closes it once the change is done,
// not half-way through.
func TestCloseDuringChange(t *testing.T) {
	w, _, share := newWindow(t, Options{})
	_, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	mainthread.Wait(func() {
		w.AddFolder(share)
		w.name.SetText("partner")
		w.useKey.SetChecked(true)
		w.key.SetText(pub)
		w.port.SetValue(port)
		w.start.Click()
	})
	waitFor(t, "sharing", func() bool { return w.state == sharing })
	mainthread.Wait(func() { w.stop.Click() })
	waitFor(t, "the stop", func() bool { return w.state == idle })
	quits := 0
	mainthread.Wait(func() {
		w.quit = func() { quits++ }
		w.setOnConflict(2)
		if !w.busy || w.win.Close() {
			t.Error("the window closed during a change")
		}
	})
	waitFor(t, "the change and the quit", func() bool { return !w.busy && quits > 0 })
	if got := on(func() string { return w.cur.Settings.OnConflict }); got != "overwrite" {
		t.Errorf("on_conflict = %q", got)
	}
}
