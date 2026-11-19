// SPDX-License-Identifier: Apache-2.0

//go:build unix

package qtui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

var testBin string

func init() { runtime.LockOSThread() } // Qt's main thread is the process's

// TestMain runs the tests while the main thread runs Qt's event loop, on
// the offscreen platform: the tests change widgets through mainthread.
func TestMain(m *testing.M) {
	bin, clean, err := gosftpdtest.Build(filepath.Join("..", "..", ".."))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testBin = bin
	_ = os.Setenv("QT_QPA_PLATFORM", "offscreen")
	qt.NewQApplication([]string{os.Args[0]})
	qt.QGuiApplication_SetQuitOnLastWindowClosed(false)
	done := make(chan int, 1)
	go func() {
		done <- m.Run()
		mainthread.Start(qt.QCoreApplication_Quit)
	}()
	qt.QApplication_Exec()
	code := <-done
	clean()
	os.Exit(code)
}

// on runs f on the Qt main thread and returns its result.
func on[T any](f func() T) T { return mainthread.Wait2(f) }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !on(ok); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newWindow(t *testing.T, opts Options) (*Window, *app.App, string) {
	t.Helper()
	gosftpdtest.SkipRoot(t)
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	share := filepath.Join(dir, "Inbox")
	if err := os.Mkdir(share, 0o755); err != nil {
		t.Fatal(err)
	}
	a := &app.App{G: supervisor.Gosftpd{Bin: testBin, Layout: supervisor.Layout{Dir: filepath.Join(dir, "state")}}}
	w := on(func() *Window { w := New(a, opts); w.Show(); return w })
	t.Cleanup(func() {
		if a.Sharing() {
			a.StopNow()
			<-a.Done()
		}
		mainthread.Wait(func() { w.win.Hide(); w.win.DeleteLater() })
	})
	waitFor(t, "the configuration to be read", func() bool { return w.state == idle })
	return w, a, share
}

// Every input control and every Copy button has an accessible name
// (ADR 0013, "Look and behaviour").
func TestAccessibleNames(t *testing.T) {
	w, _, share := newWindow(t, Options{})
	mainthread.Wait(func() {
		w.AddFolder(share)
		controls := map[string]*qt.QWidget{
			"name": w.name.QWidget, "password": w.password.QWidget, "generate": w.generate.QWidget,
			"key": w.key.QWidget, "port": w.port.QWidget,
			"access": w.folders[0].access.QWidget, "remove": w.folders[0].remove.QWidget,
		}
		for k, f := range w.fields {
			controls[k] = f.QWidget
		}
		for what, c := range controls {
			if c.AccessibleName() == "" {
				t.Errorf("%s has no accessible name", what)
			}
		}
		if got := w.folders[0].access.AccessibleName(); got != "Access to Inbox" {
			t.Errorf("access combo box: %q", got)
		}
	})
}

func TestShareAndStop(t *testing.T) {
	w, a, share := newWindow(t, Options{})

	// Start with nothing filled in: refused, with the reason.
	mainthread.Wait(func() { w.start.Click() })
	if s := on(func() string { return w.status.Text() }); !strings.Contains(s, "choose a folder") || on(func() state { return w.state }) != idle {
		t.Fatalf("an empty form: %q", s)
	}

	_, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	mainthread.Wait(func() {
		w.AddFolder(share)
		w.AddFolder(share) // once only
		w.name.SetText("partner")
		w.useKey.SetChecked(true)
		w.key.SetText(pub)
		w.port.SetValue(port)
		w.start.Click()
	})
	waitFor(t, "sharing", func() bool {
		return w.state == sharing || w.state == idle && strings.HasPrefix(w.status.Text(), "Error")
	})
	if s := on(func() string { return w.status.Text() }); on(func() state { return w.state }) != sharing {
		t.Fatalf("not sharing: %s\n%s", s, on(func() string { return w.more.ToPlainText() }))
	}
	mainthread.Wait(func() {
		if len(w.folders) != 1 {
			t.Errorf("%d folders listed, want 1", len(w.folders))
		}
		for _, k := range []string{"host", "port", "user", "fingerprint", "known_hosts", "command"} {
			if w.fields[k].Text() == "" {
				t.Errorf("connection detail %s is empty", k)
			}
		}
		if got := w.fields["user"].Text(); got != "partner" {
			t.Errorf("user = %q", got)
		}
		if !strings.HasPrefix(w.fields["fingerprint"].Text(), "SHA256:") || !strings.Contains(w.fields["command"].Text(), "partner@") {
			t.Errorf("details: %q, %q", w.fields["fingerprint"].Text(), w.fields["command"].Text())
		}
		if w.name.Text() != "" || w.key.Text() != "" || w.name.IsEnabled() || !w.stop.IsEnabled() || w.start.IsEnabled() {
			t.Error("the form is not cleared and locked while sharing")
		}
		if !strings.Contains(w.people.Text(), "partner (public key)") {
			t.Errorf("people: %q", w.people.Text())
		}
		// Not the warning of the init that ran before partner was added.
		if more := w.more.ToPlainText(); strings.Contains(more, "no users") {
			t.Errorf("a stale warning after the start: %q", more)
		}
	})
	if !a.Sharing() {
		t.Fatal("the app does not share")
	}

	mainthread.Wait(func() { w.stop.Click() })
	waitFor(t, "the stop", func() bool { return w.state == idle })
	if s := on(func() string { return w.status.Text() }); s != "Sharing stopped." {
		t.Errorf("status after Stop: %q", s)
	}
	if on(func() bool { return w.details.IsVisible() || !w.start.IsEnabled() }) {
		t.Error("details shown or Start disabled after the stop")
	}
}

// A second window on the same state directory shows what was shared and
// starts sharing at launch with --start-sharing.
func TestStartSharingAtLaunch(t *testing.T) {
	w, a, share := newWindow(t, Options{})
	_, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	mainthread.Wait(func() {
		w.AddFolder(share)
		w.folders[0].access.SetCurrentIndex(accessRead)
		w.name.SetText("partner")
		w.useKey.SetChecked(true)
		w.key.SetText(pub)
		w.port.SetValue(port)
		w.start.Click()
	})
	waitFor(t, "sharing", func() bool { return w.state == sharing })
	mainthread.Wait(func() { w.stop.Click() })
	waitFor(t, "the stop", func() bool { return w.state == idle })

	again := on(func() *Window { w := New(a, Options{StartSharing: true}); w.Show(); return w })
	t.Cleanup(func() { mainthread.Wait(func() { again.win.Hide(); again.win.DeleteLater() }) })
	waitFor(t, "sharing at launch", func() bool { return again.state == sharing })
	mainthread.Wait(func() {
		if len(again.folders) != 1 || again.folders[0].access.CurrentIndex() != accessRead || again.port.Value() != port {
			t.Errorf("the second window shows %d folders, port %d", len(again.folders), again.port.Value())
		}
		if again.fields["user"].Text() != "partner" {
			t.Errorf("user = %q", again.fields["user"].Text())
		}
	})
	mainthread.Wait(func() { again.stopSharing(true) })
	waitFor(t, "the stop", func() bool { return again.state == idle })
	if s := on(func() string { return again.status.Text() }); s != "Sharing stopped." {
		t.Errorf("status after Stop now: %q", s)
	}

	// A shared folder removed and added again keeps its name; another
	// folder never takes the name of one in the configuration.
	other := filepath.Join(t.TempDir(), "Inbox")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	mainthread.Wait(func() {
		again.folders[0].remove.Click()
		again.AddFolder(other)
		again.AddFolder(share)
		var names []string
		for _, r := range again.folders {
			names = append(names, r.folder.Name)
		}
		if strings.Join(names, ",") != "Inbox 2,Inbox" || again.folders[1].access.CurrentIndex() != accessRead {
			t.Errorf("folders after remove and add: %q", names)
		}
	})
}

// A configuration that cannot be read leaves the window unable to change
// it.
func TestUnreadable(t *testing.T) {
	gosftpdtest.SkipRoot(t)
	t.Setenv("HOME", t.TempDir())
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.toml"), []byte("no_such_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app.App{G: supervisor.Gosftpd{Bin: testBin, Layout: supervisor.Layout{Dir: state}}}
	w := on(func() *Window { w := New(a, Options{StartSharing: true}); w.Show(); return w })
	t.Cleanup(func() { mainthread.Wait(func() { w.win.Hide(); w.win.DeleteLater() }) })
	waitFor(t, "the configuration to be read", func() bool { return w.state != loading })
	mainthread.Wait(func() {
		if w.state != broken || w.start.IsEnabled() || w.addFolder.IsEnabled() || w.name.IsEnabled() {
			t.Errorf("state %d, Start enabled %v", w.state, w.start.IsEnabled())
		}
		if !strings.HasPrefix(w.status.Text(), "Error: Could not read the configuration") || w.more.ToPlainText() == "" {
			t.Errorf("status %q, details %q", w.status.Text(), w.more.ToPlainText())
		}
	})
	if a.Sharing() {
		t.Error("sharing with --start-sharing over an unreadable configuration")
	}
}
