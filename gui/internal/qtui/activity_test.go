// SPDX-License-Identifier: Apache-2.0

//go:build unix

package qtui

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mappu/miqt/qt6/mainthread"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

func TestStateText(t *testing.T) {
	since := time.Date(2026, 11, 19, 10, 42, 0, 0, time.Local)
	for _, tc := range []struct {
		s    app.Snapshot
		want string
	}{
		{app.Snapshot{}, "Not sharing."},
		{app.Snapshot{Sharing: true, Landlock: "v5"}, "Sharing. Landlock (v5) limits gosftpd"},
		{app.Snapshot{Sharing: true, Landlock: "unavailable"}, "without Landlock: this system does not offer it"},
		{app.Snapshot{Sharing: true, Connected: []supervisor.Session{{User: "alice", Since: since}}}, "Sharing. Connected: alice since 10:42."},
	} {
		if got := stateText(tc.s); !strings.Contains(got, tc.want) {
			t.Errorf("stateText(%+v) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestSizeAndWhen(t *testing.T) {
	for _, tc := range []struct {
		n    int64
		what string
		want string
	}{
		{0, "Deleted", ""},
		{0, "Uploaded", "0 B"},
		{999, "Downloaded", "999 B"},
		{48000, "Uploaded", "48.0 kB"},
		{3_500_000_000, "Uploaded", "3.5 GB"},
	} {
		if got := size(tc.n, tc.what); got != tc.want {
			t.Errorf("size(%d, %q) = %q, want %q", tc.n, tc.what, got, tc.want)
		}
	}
	now := time.Date(2026, 11, 19, 18, 0, 0, 0, time.Local)
	if got := when(now.Add(-time.Hour), now); got != "17:00:00" {
		t.Errorf("today: %q", got)
	}
	if got := when(now.Add(-48*time.Hour), now); got != "17 Nov 18:00" {
		t.Errorf("before: %q", got)
	}
}

// Uploads appear in the activity, the filter narrows them, and Clear
// activity hides them.
func TestActivityView(t *testing.T) {
	w, a, share := newWindow(t, Options{})
	key, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	mainthread.Wait(func() {
		a.PrefsPath = filepath.Join(t.TempDir(), "gosftpd-gui.conf")
		if w.actFilter.AccessibleName() == "" || w.actTable.AccessibleName() == "" || w.actTable.TabKeyNavigation() {
			t.Error("the activity's controls: no accessible name, or Tab moves inside the table")
		}
		if !w.actEmpty.IsVisible() || w.actTable.IsVisible() || w.actState.Text() != "Not sharing." {
			t.Errorf("before the first share: state %q", w.actState.Text())
		}
		w.AddFolder(share)
		w.name.SetText("partner")
		w.useKey.SetChecked(true)
		w.key.SetText(pub)
		w.port.SetValue(port)
		w.start.Click()
	})
	waitFor(t, "sharing", func() bool { return w.state == sharing && strings.HasPrefix(w.actState.Text(), "Sharing") })
	host := on(func() string { return w.fields["host"].Text() })
	if _, err := net.DefaultResolver.LookupHost(t.Context(), host); err != nil {
		t.Skipf("the host name %q does not resolve: %v", host, err)
	}
	known := on(func() string { return w.fields["known_hosts"].Text() })
	file := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(file, make([]byte, 48000), 0o600); err != nil {
		t.Fatal(err)
	}
	gosftpdtest.SFTP(t, host, port, known, "partner", key, "put "+file+" /one.pdf\nput "+file+" /two.pdf\n")
	waitFor(t, "two uploads in the table", func() bool { return w.actTable.IsVisible() && w.actTable.RowCount() == 2 })
	mainthread.Wait(func() {
		row := []string{}
		for c := range activityColumns {
			row = append(row, w.actTable.Item(0, c).Text())
		}
		if row[1] != "partner" || row[2] != "Uploaded" || row[3] != "48.0 kB" || row[4] != "/two.pdf" {
			t.Errorf("newest row: %q", row)
		}
		w.actFilter.SetText("one")
		if w.actTable.RowCount() != 1 || w.actTable.Item(0, 4).Text() != "/one.pdf" {
			t.Errorf("filter one: %d rows", w.actTable.RowCount())
		}
		w.actFilter.SetText("nothing like it")
		if w.actTable.IsVisible() || w.actEmpty.Text() != "Nothing matches the filter." {
			t.Errorf("filter nothing: table visible %v, %q", w.actTable.IsVisible(), w.actEmpty.Text())
		}
		w.actFilter.SetText("")
		w.actClear.Click()
		if w.actTable.IsVisible() || !strings.HasPrefix(w.status.Text(), "Cleared the activity view") {
			t.Errorf("after Clear activity: table visible %v, status %q", w.actTable.IsVisible(), w.status.Text())
		}
	})
	if p, err := app.LoadPrefs(on(func() string { return a.PrefsPath })); err != nil || p.ActivityFrom == 0 {
		t.Errorf("preferences after Clear activity: %+v, %v", p, err)
	}
	gosftpdtest.SFTP(t, host, port, known, "partner", key, "put "+file+" /three.pdf\n")
	waitFor(t, "the third upload alone", func() bool {
		return w.actTable.IsVisible() && w.actTable.RowCount() == 1 && w.actTable.Item(0, 4).Text() == "/three.pdf"
	})
	mainthread.Wait(func() { w.stop.Click() })
	waitFor(t, "the stop", func() bool { return w.state == idle && w.actState.Text() == "Not sharing." })
	if n := on(func() int { return w.actTable.RowCount() }); n != 1 {
		t.Errorf("after the stop the table lists %d entries, want the upload still", n)
	}
}
