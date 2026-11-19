// SPDX-License-Identifier: Apache-2.0

//go:build unix

package qtui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	qt "github.com/mappu/miqt/qt6"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
)

// The Activity section (M5b-05, ADR 0013 "Activity"): the server's
// state, who is connected, the latest finished transfers and changes of
// the audit log with a filter, and gosftpd's warnings in plain words.

// activityColumns are the columns of the activity table.
var activityColumns = []string{"Time", "Person", "What", "Size", "File"}

func (w *Window) buildActivity() *qt.QGroupBox {
	box := qt.NewQGroupBox3("Activity")
	l := qt.NewQVBoxLayout2()
	box.SetLayout(l.QLayout)
	w.actState = qt.NewQLabel2()
	w.actState.SetWordWrap(true)
	l.AddWidget(w.actState.QWidget)

	row := qt.NewQHBoxLayout2()
	w.actFilter = qt.NewQLineEdit2()
	w.actFilter.SetAccessibleName("Filter activity")
	w.actFilter.SetPlaceholderText("Filter by person, file or what happened")
	w.actFilter.OnTextChanged(func(string) { w.showActivity(true) })
	w.actClear = qt.NewQPushButton3("Clear activity")
	w.actClear.SetAccessibleDescription("Hides what is listed now. The activity log keeps every entry")
	w.actClear.OnClicked(w.clearActivity)
	row.AddWidget(w.actFilter.QWidget)
	row.AddWidget(w.actClear.QWidget)
	l.AddLayout(row.QLayout)

	w.actTable = qt.NewQTableWidget3(0, len(activityColumns))
	w.actTable.SetHorizontalHeaderLabels(activityColumns)
	w.actTable.SetAccessibleName("Latest transfers and changes")
	w.actTable.SetEditTriggers(qt.QAbstractItemView__NoEditTriggers)
	w.actTable.SetSelectionBehavior(qt.QAbstractItemView__SelectRows)
	// Tab moves on to the next control, not from cell to cell.
	w.actTable.SetTabKeyNavigation(false)
	w.actTable.VerticalHeader().SetVisible(false)
	w.actTable.HorizontalHeader().SetSectionResizeMode(qt.QHeaderView__ResizeToContents)
	w.actTable.HorizontalHeader().SetStretchLastSection(true)
	w.actTable.SetMinimumHeight(160)
	l.AddWidget(w.actTable.QWidget)
	w.actEmpty = qt.NewQLabel3("Nothing yet: uploads, downloads and changes appear here once they finish.")
	w.actEmpty.SetWordWrap(true)
	l.AddWidget(w.actEmpty.QWidget)

	warnLabel := qt.NewQLabel3("Warnings:")
	l.AddWidget(warnLabel.QWidget)
	w.actWarnings = qt.NewQPlainTextEdit2()
	w.actWarnings.SetReadOnly(true)
	w.actWarnings.SetAccessibleName("Warnings")
	w.actWarnings.SetMaximumHeight(100)
	l.AddWidget(w.actWarnings.QWidget)
	w.actWarnLabel = warnLabel
	w.showActivity(true)
	return box
}

// pollActivity reads what gosftpd wrote to the audit log since the last
// time: who is connected, and the activity.
func (w *Window) pollActivity() {
	snap, err := w.app.Activity()
	if err != nil {
		w.actState.SetText("The activity log cannot be read: " + err.Error())
		return
	}
	w.snap = snap
	who := app.Names(snap.Connected)
	if !slices.Equal(who, w.who) {
		w.who = who
		text := "Nobody is connected."
		if len(who) > 0 {
			text = "Connected now: " + strings.Join(who, ", ") + "."
		}
		w.connected.SetText(text)
		announce(w.connected.QObject)
	}
	w.showActivity(false)
}

// showActivity shows the last snapshot; force redraws the table even
// when its entries did not change (a new filter).
func (w *Window) showActivity(force bool) {
	s := w.snap
	state := stateText(s)
	if state != w.actState.Text() {
		w.actState.SetText(state)
		announce(w.actState.QObject)
	}
	entries := app.Filter(s.Entries, w.actFilter.Text())
	key := entriesKey(entries)
	if force || key != w.actShown {
		w.actShown = key
		w.actTable.SetRowCount(len(entries))
		now := time.Now()
		for i, e := range entries {
			cells := []string{when(e.Time, now), e.User, e.What, size(e.Bytes, e.What), e.File}
			for j, c := range cells {
				item := qt.NewQTableWidgetItem2(c)
				item.SetToolTip(c)
				w.actTable.SetItem(i, j, item)
			}
		}
	}
	w.actTable.SetVisible(len(entries) > 0)
	switch {
	case len(s.Entries) == 0:
		w.actEmpty.SetText("Nothing yet: uploads, downloads and changes appear here once they finish.")
	case len(entries) == 0:
		w.actEmpty.SetText("Nothing matches the filter.")
	}
	w.actEmpty.SetVisible(len(entries) == 0)
	warnings := s.Warnings
	if len(warnings) > 10 {
		warnings = warnings[len(warnings)-10:]
	}
	text := strings.Join(warnings, "\n")
	if text != w.actWarnings.ToPlainText() {
		w.actWarnings.SetPlainText(text)
	}
	w.actWarnings.SetVisible(text != "")
	w.actWarnLabel.SetVisible(text != "")
}

// clearActivity hides what is listed: Clear activity.
func (w *Window) clearActivity() {
	if err := w.app.ClearActivity(); err != nil {
		w.fail("Could not keep where the activity was cleared", err.Error())
		return
	}
	w.pollActivity()
	w.showActivity(true)
	w.setStatus("Cleared the activity view. The activity log keeps every entry.")
}

// stateText is the server's state in plain words.
func stateText(s app.Snapshot) string {
	if !s.Sharing {
		return "Not sharing."
	}
	var b strings.Builder
	switch s.Landlock {
	case "":
		b.WriteString("Sharing.")
	case "off":
		b.WriteString("Sharing, without Landlock: it is turned off in the configuration.")
	case "unavailable":
		b.WriteString("Sharing, without Landlock: this system does not offer it.")
	case "blocked":
		b.WriteString("Sharing, without Landlock: a security filter of this system blocks it.")
	case "not_applied":
		b.WriteString("Sharing, without Landlock: it cannot be applied to this configuration.")
	default:
		fmt.Fprintf(&b, "Sharing. Landlock (%s) limits gosftpd to the shared folders and its own files.", s.Landlock)
	}
	if len(s.Connected) > 0 {
		var who []string
		for _, c := range s.Connected {
			who = append(who, fmt.Sprintf("%s since %s", c.User, c.Since.Local().Format("15:04")))
		}
		b.WriteString(" Connected: " + strings.Join(who, ", ") + ".")
	}
	return b.String()
}

// when is the time of an entry: the time of day today, else the date too.
func when(t, now time.Time) string {
	t = t.Local()
	if y, m, d := t.Date(); y == now.Year() && m == now.Month() && d == now.Day() {
		return t.Format("15:04:05")
	}
	return t.Format("2 Jan 15:04")
}

// size is the size of a transfer in plain units, "" for other entries.
func size(n int64, what string) string {
	if n == 0 && !strings.HasPrefix(what, "Uploaded") && !strings.HasPrefix(what, "Downloaded") {
		return ""
	}
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	f, suffix := float64(n), []string{"kB", "MB", "GB", "TB"}
	i := -1
	for f >= unit && i < len(suffix)-1 {
		f /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", f, suffix[i])
}

// entriesKey tells two lists of entries apart, to redraw the table only
// when they change.
func entriesKey(es []app.Entry) string {
	if len(es) == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s %s %s", len(es), es[0].Time, es[0].File, es[len(es)-1].Time)
}
