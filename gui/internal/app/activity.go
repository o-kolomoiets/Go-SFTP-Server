// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// The activity view (M5b-05, ADR 0013 "Activity"): what the audit log
// says, read from where Clear activity left it, and the warnings of the
// operational log in plain words.

// Entry is a finished transfer or change of the audit log, as the
// activity view lists it.
type Entry struct {
	Time   time.Time
	User   string
	What   string // what happened, in plain words
	File   string // the path the person saw; for a rename, from → to
	Bytes  int64  // uploads and downloads
	Failed bool   // a refusal, or a result other than ok
}

// Describe puts an audit event of a transfer or change in plain words.
func Describe(e supervisor.Event) Entry {
	en := Entry{Time: e.Time, User: e.User, File: e.Path}
	switch e.Name {
	case "fs.upload":
		en.Bytes = e.Bytes
		if e.FinalPath != "" {
			en.File = e.FinalPath
		}
		switch e.Conflict {
		case "renamed":
			en.What = "Uploaded under another name: " + e.Path + " existed"
		case "overwritten":
			en.What = "Uploaded, replacing the file"
		case "versioned":
			en.What = "Uploaded, the old file kept as a version"
		default:
			en.What = "Uploaded"
		}
	case "fs.download":
		en.What, en.Bytes = "Downloaded", e.Bytes
	case "fs.rename":
		to := e.FinalPath
		if to == "" {
			to = e.TargetPath
		}
		en.What, en.File = "Renamed", e.Path+" → "+to
	case "fs.remove":
		en.What = "Deleted"
	case "fs.mkdir":
		en.What = "Created a folder"
	case "fs.rmdir":
		en.What = "Removed a folder"
	case "fs.setstat":
		en.What = "Changed times or permissions"
	case "fs.denied":
		en.What, en.Failed = "Refused", true
		if verb, ok := opVerbs[strings.TrimPrefix(e.Op, "fs.")]; ok {
			en.What = "Refused to " + verb
		} else if e.Op != "" {
			en.What += " (" + e.Op + ")"
		}
		if e.Reason != "" {
			en.What += ": " + strings.ReplaceAll(e.Reason, "_", " ")
		}
		if en.File == "" {
			en.File = e.Mount
		}
	default:
		en.What = e.Name
	}
	if e.Result != "" && e.Result != "ok" && e.Name != "fs.denied" {
		en.What += " (failed: " + strings.ReplaceAll(e.Result, "_", " ") + ")"
		en.Failed = true
	}
	return en
}

// opVerbs say what a refused operation (fs.denied's op) would have done.
var opVerbs = map[string]string{
	"upload": "upload", "download": "download", "remove": "delete", "rename": "rename",
	"mkdir": "create a folder", "rmdir": "remove a folder", "setstat": "change times or permissions",
	"list": "list a folder", "stat": "look at a file", "write": "write", "read": "read",
}

// Filter keeps the entries whose person, file or description contains
// text, ignoring case; all of them for an empty text.
func Filter(entries []Entry, text string) []Entry {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return entries
	}
	var out []Entry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.User), text) || strings.Contains(strings.ToLower(e.File), text) ||
			strings.Contains(strings.ToLower(e.What), text) {
			out = append(out, e)
		}
	}
	return out
}

// Snapshot is what the activity view shows.
type Snapshot struct {
	Sharing   bool
	Landlock  string               // v2 to v5, off, unavailable; "" before server.start
	Connected []supervisor.Session // the oldest first; none when not sharing
	Entries   []Entry              // the newest first
	Warnings  []string             // the newest last, in plain words
}

// Activity polls the audit log and returns what the activity view
// shows. Before the first share there is no log, and nothing to show.
func (a *App) Activity() (Snapshot, error) {
	connected, err := a.Poll()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Sharing: a.srv != nil, Connected: connected}
	if s.Sharing {
		s.Landlock = a.activity.Landlock
	}
	for _, e := range a.activity.Transfers {
		s.Entries = append(s.Entries, Describe(e))
	}
	for _, e := range a.logTail {
		s.Warnings = append(s.Warnings, e.plain)
	}
	return s, err
}

// ClearActivity hides the entries shown so far, here and in later runs
// of the GUI: the place in the audit log is kept in the preferences. The
// audit log itself is never changed: it is the record of who uploaded
// what (D20).
func (a *App) ClearActivity() error {
	a.mu.Lock()
	f := a.followerLocked()
	pos := f.Position()
	a.activity.Transfers = nil
	a.mu.Unlock()
	if a.PrefsPath == "" {
		return nil
	}
	p, err := LoadPrefs(a.PrefsPath)
	if err != nil {
		return err
	}
	p.ActivityFrom, p.ActivityLog = pos, fileID(a.G.Layout.AuditLog())
	return SavePrefs(a.PrefsPath, p)
}

// followerLocked returns the follower of the audit log, made on first
// use from where Clear activity left the view. a.mu is held.
func (a *App) followerLocked() *supervisor.Follower {
	if a.follower != nil {
		return a.follower
	}
	path := a.G.Layout.AuditLog()
	a.follower = supervisor.NewFollower(path)
	if a.PrefsPath != "" {
		if p, err := LoadPrefs(a.PrefsPath); err == nil && p.ActivityFrom > 0 && p.ActivityLog == fileID(path) {
			a.follower.Resume(p.ActivityFrom)
		}
	}
	return a.follower
}

// plainWarnings say known warnings and errors of gosftpd's operational
// log in plain words, by the start of their message. Others are shown as
// gosftpd wrote them (ADR 0013, "Activity").
var plainWarnings = []struct{ prefix, text string }{
	{"mount unavailable", "A shared folder cannot be opened: it was moved or deleted, or its disk is not connected. People cannot use it until it is back."},
	{"refusing connection: audit log unavailable", "Connections are refused: the activity log cannot be written. Is the disk full?"},
	{"cannot reopen the audit log", "The activity log cannot be written, so connections are refused until it can. Is the disk full?"},
	{"configuration reload failed", "gosftpd could not read the changed configuration and keeps sharing as before."},
	{"banning source after repeated login failures", "An address is blocked for a while after repeated failed logins"},
	{"closed connections that did not finish in time", "Stopping cut connections that did not finish in time."},
	{"landlock: not available", "This system cannot confine gosftpd with Landlock: it shares without that protection."},
	{"landlock: failed", "Confining gosftpd with Landlock failed: it shares without that protection."},
	{"accept failed, retrying", "gosftpd could not accept a connection, and tries again."},
	{"this setting changes only at restart", "A changed setting applies only once sharing starts again."},
	{"host keys cannot be used", "The changed host key cannot be used: the one in use stays."},
	{"panic while serving connection", "A connection failed because of an error in gosftpd. Please report it."},
}

// PlainRecord is a record of the operational log in plain words when it
// is a known one, else as FormatRecord shows it.
func PlainRecord(r supervisor.LogRecord) string {
	for _, w := range plainWarnings {
		if strings.HasPrefix(r.Msg, w.prefix) {
			if src, ok := r.Attrs["source"]; ok && w.prefix == "banning source after repeated login failures" {
				return fmt.Sprintf("%s: %v.", w.text, src)
			}
			return w.text
		}
	}
	return FormatRecord(r)
}
