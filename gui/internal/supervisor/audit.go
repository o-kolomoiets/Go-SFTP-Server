// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

// Event is a line of the audit log (docs/audit-log.md), with the fields
// the GUI shows.
type Event struct {
	Time            time.Time `json:"time"`
	Name            string    `json:"event"`
	ConnID          string    `json:"conn_id"`
	SessionID       string    `json:"session_id"`
	User            string    `json:"user"`
	RemoteAddr      string    `json:"remote_addr"`
	Op              string    `json:"op"`
	Path            string    `json:"path"`
	TargetPath      string    `json:"target_path"`
	FinalPath       string    `json:"final_path"`
	VersionPath     string    `json:"version_path"`
	Mount           string    `json:"mount"`
	Conflict        string    `json:"conflict"`
	Bytes           int64     `json:"bytes"`
	Result          string    `json:"result"`
	Reason          string    `json:"reason"`
	RestartRequired string    `json:"restart_required"`
	Disconnected    int       `json:"disconnected"`
	Landlock        string    `json:"landlock"`
}

// ReloadResult is a server.reload event.
type ReloadResult struct {
	OK     bool
	Reason string // why it failed: config, mounts or audit_output
	// RestartRequired are the keys that changed but apply only at a
	// restart; under Landlock also a new folder, or upload rights on a
	// read-only one (ADR 0011).
	RestartRequired []string
	// Disconnected is how many connections the reload closed: those of
	// the people disabled or removed (disconnect_removed_users).
	Disconnected int
}

func (e Event) reloadResult() ReloadResult {
	r := ReloadResult{OK: e.Result == "ok", Reason: e.Reason, Disconnected: e.Disconnected}
	for k := range strings.SplitSeq(e.RestartRequired, ",") {
		if k = strings.TrimSpace(k); k != "" {
			r.RestartRequired = append(r.RestartRequired, k)
		}
	}
	return r
}

// Follower reads the audit log as it grows.
type Follower struct {
	path    string
	off     int64
	partial []byte
	last    fs.FileInfo
}

// NewFollower follows the audit log at path from its start.
func NewFollower(path string) *Follower { return &Follower{path: path} }

// Offset is how far Poll has read.
func (f *Follower) Offset() int64 { return f.off }

// Position is where the next event begins: Offset less a line still
// being written. A follower moved there with Seek reads every event
// after those Poll returned.
func (f *Follower) Position() int64 { return f.off - int64(len(f.partial)) }

// Resume makes Poll read from off, the Position of an earlier follower of
// the same file. A log shorter than off, or another file, is read from
// its start, with reset.
func (f *Follower) Resume(off int64) {
	f.off, f.partial, f.last = off, nil, nil
}

// Skip moves to the end of the log without reading it: Poll then returns
// only the events written after. A log that does not exist yet is
// followed from its start.
func (f *Follower) Skip() error {
	fi, err := os.Stat(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		f.off, f.partial, f.last = 0, nil, nil
		return nil
	}
	if err != nil {
		return err
	}
	f.off, f.partial, f.last = fi.Size(), nil, fi
	return nil
}

// Poll returns the events written since the last Poll; a line still
// being written waits for the next one. reset is true when the log
// became another file or shorter (truncated, rotated, deleted): the
// events then come from its start, and what was shown before them is
// gone. A log that does not exist yet has no events.
func (f *Follower) Poll() (events []Event, reset bool, err error) {
	file, err := os.Open(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		if f.last != nil || f.off > 0 {
			f.off, f.partial, f.last, reset = 0, nil, nil, true
		}
		return nil, reset, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if (f.last != nil && !os.SameFile(f.last, fi)) || fi.Size() < f.off {
		f.off, f.partial, reset = 0, nil, true
	}
	f.last = fi
	if fi.Size() == f.off {
		return nil, reset, nil
	}
	if _, err := file.Seek(f.off, io.SeekStart); err != nil {
		return nil, reset, err
	}
	data, err := io.ReadAll(io.LimitReader(file, fi.Size()-f.off))
	if err != nil {
		return nil, reset, err
	}
	f.off += int64(len(data))
	data = append(f.partial, data...)
	end := bytes.LastIndexByte(data, '\n')
	if end < 0 {
		f.partial = data
		return nil, reset, nil
	}
	f.partial = append([]byte(nil), data[end+1:]...)
	for line := range bytes.SplitSeq(data[:end], []byte{'\n'}) {
		var e Event
		if json.Unmarshal(line, &e) == nil && e.Name != "" {
			events = append(events, e)
		}
	}
	return events, reset, nil
}

// Session is a person connected: an SFTP session that has started and
// not ended.
type Session struct {
	ConnID, SessionID string
	User, RemoteAddr  string
	Since             time.Time
}

// MaxTransfers is how many transfers Activity keeps.
const MaxTransfers = 200

// Activity is what the audit log says now: whether gosftpd serves, who
// is connected and the latest transfers, newest first.
type Activity struct {
	Running   bool
	Landlock  string // server.start's landlock: v2 to v5, off, unavailable, ...
	Sessions  map[string]Session
	Transfers []Event
}

// transferEvents are the events Activity lists: finished transfers and
// changes, and what was refused.
var transferEvents = map[string]bool{
	"fs.upload": true, "fs.download": true, "fs.rename": true, "fs.remove": true,
	"fs.mkdir": true, "fs.rmdir": true, "fs.setstat": true, "fs.denied": true,
}

// Apply takes in an event, in the order of the log.
func (a *Activity) Apply(e Event) {
	if a.Sessions == nil {
		a.Sessions = map[string]Session{}
	}
	key := e.ConnID + "/" + e.SessionID
	switch {
	case e.Name == "server.start":
		// Only sessions after the last server.start count: a stop that
		// was cut short wrote no session.end.
		a.Running, a.Landlock = true, e.Landlock
		clear(a.Sessions)
	case e.Name == "server.stop":
		a.Running = false
		clear(a.Sessions)
	case e.Name == "session.start":
		a.Sessions[key] = Session{ConnID: e.ConnID, SessionID: e.SessionID, User: e.User, RemoteAddr: e.RemoteAddr, Since: e.Time}
	case e.Name == "session.end":
		delete(a.Sessions, key)
	case e.Name == "conn.close":
		for k, s := range a.Sessions {
			if s.ConnID == e.ConnID {
				delete(a.Sessions, k)
			}
		}
	case transferEvents[e.Name]:
		a.Transfers = slices.Insert(a.Transfers, 0, e)
		if len(a.Transfers) > MaxTransfers {
			a.Transfers = a.Transfers[:MaxTransfers]
		}
	}
}

// Exited is gosftpd's exit: nobody is connected any more, also after a
// stop that wrote neither session.end nor server.stop (Stop now, or a
// stop after the GUI died).
func (a *Activity) Exited() {
	a.Running = false
	clear(a.Sessions)
}

// Reset forgets everything: the log became another file or shorter, and
// Poll reads it again from its start.
func (a *Activity) Reset() {
	running := a.Running
	*a = Activity{Running: running}
}

// Connected returns the sessions, the oldest first.
func (a *Activity) Connected() []Session {
	out := make([]Session, 0, len(a.Sessions))
	for _, s := range a.Sessions {
		out = append(out, s)
	}
	slices.SortFunc(out, func(x, y Session) int {
		if c := x.Since.Compare(y.Since); c != 0 {
			return c
		}
		return strings.Compare(x.ConnID+x.SessionID, y.ConnID+y.SessionID)
	})
	return out
}
