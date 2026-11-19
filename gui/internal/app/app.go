// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Package app is what gosftpd-gui does, apart from its window: it turns
// what the person filled in into gosftpd commands through the supervisor,
// starts and stops sharing, and follows who is connected. It knows no
// toolkit, so that it is tested without a display (ADR 0013).
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// DefaultPort is the port of a first share, as with gosftpd serve --dir.
const DefaultPort = 2022

// maxLogTail is how many warnings and errors of gosftpd's operational log
// the App keeps to show.
const maxLogTail = 50

// App is the GUI's state directory, the gosftpd it runs, and the server
// while it shares. Its methods may be called from any goroutine.
type App struct {
	G supervisor.Gosftpd
	// Lock records the pid of the server, for a GUI started after this
	// one dies; nil records nothing.
	Lock *supervisor.Lock
	// Version is the GUI's own: Start refuses a gosftpd of another
	// version. A development build leaves it empty.
	Version string
	// PrefsPath is the GUI's preferences file (gosftpd-gui.conf), where
	// Clear activity keeps its place in the audit log; "" keeps none.
	PrefsPath string

	mu       sync.Mutex
	srv      *supervisor.Server
	stopping bool
	follower *supervisor.Follower
	activity supervisor.Activity
	logTail  []logEntry
	logSeq   int // the number of the last entry of logTail

	// changeMu runs one change of the configuration at a time.
	changeMu sync.Mutex
}

// logEntry is a warning or error of gosftpd's operational log, numbered
// so that a reload can tell what it logged.
type logEntry struct {
	seq   int
	text  string // as gosftpd wrote it
	plain string // in plain words, when it is a known one
}

func (a *App) admin() supervisor.Admin { return supervisor.Admin{G: a.G} }

// Current is the configuration as the window shows it.
type Current struct {
	Configured bool // a folder was shared before: the configuration exists
	Settings   supervisor.Settings
	// Reset are the folders a hand edit set apart (on_conflict, create):
	// the next change of the folders resets them.
	Reset  []string
	People []supervisor.Person
}

// Port is the port the configuration listens on: that of its first
// address, DefaultPort when it has none.
func (c Current) Port() int {
	if len(c.Settings.Listen) == 0 {
		return DefaultPort
	}
	_, port, err := net.SplitHostPort(c.Settings.Listen[0])
	if err != nil {
		return DefaultPort
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return DefaultPort
	}
	return n
}

// Load reads the configuration and the people, if a folder was shared
// before. It refuses a state directory whose users.d/ holds people
// without a configuration: a first share would keep their files, and
// their grants would go to new folders that happen to have the names of
// their old ones.
func (a *App) Load(ctx context.Context) (Current, error) {
	// The first read of the audit log may take a moment: here, off the
	// window's thread, and not at its first Poll.
	_, _ = a.Poll()
	if !a.G.Layout.Exists() {
		files, err := filepath.Glob(filepath.Join(a.G.Layout.UsersDir(), "*.toml"))
		if err != nil {
			return Current{}, err
		}
		if len(files) > 0 {
			return Current{}, fmt.Errorf("%s holds people, but %s is missing: put the configuration back, or remove %s to start afresh",
				a.G.Layout.UsersDir(), a.G.Layout.Config(), a.G.Layout.UsersDir())
		}
		return Current{}, nil
	}
	s, reset, err := a.admin().Read(ctx)
	if err != nil {
		return Current{}, err
	}
	ps, err := a.admin().People(ctx)
	if err != nil {
		return Current{}, err
	}
	return Current{Configured: true, Settings: s, Reset: reset, People: ps}, nil
}

// Form is what the person filled in to share.
type Form struct {
	Folders []supervisor.Folder
	Port    int
	// OnConflict is what an upload to an existing file does, written by
	// a first share ("rename" when empty); later, SetOnConflict changes it.
	OnConflict string
	Person     NewPerson
}

// NewPerson is a person to add, who may use every folder of the form:
// upload to the folders people may upload to, read the read-only ones.
// Name is empty when nobody is added. A person has either a password or
// a public key, an authorized_keys line, never a private key.
type NewPerson struct {
	Name     string
	Password string
	Key      string
}

func (p NewPerson) empty() bool { return p.Name == "" && p.Password == "" && p.Key == "" }

// Check refuses, before any command runs, a form that cannot be shared.
// gosftpd checks the rest, such as the person's name, with its own
// messages.
func (f Form) Check(cur Current) error {
	if len(f.Folders) == 0 {
		return errors.New("choose a folder to share")
	}
	if f.Port < 1 || f.Port > 65535 {
		return errors.New("the port must be a number from 1 to 65535")
	}
	if f.OnConflict != "" && !slices.Contains(OnConflict, f.OnConflict) {
		return fmt.Errorf("on_conflict %q: want one of %s", f.OnConflict, strings.Join(OnConflict, ", "))
	}
	p := f.Person
	switch {
	case p.empty() && len(cur.People) == 0:
		return errors.New("add a person who may connect: a name, and a password or their public key")
	case p.empty():
		return nil
	case p.Name == "":
		return errors.New("give the person a name")
	case p.Password == "" && p.Key == "":
		return fmt.Errorf("give %s a password or their public key", p.Name)
	case p.Password != "" && p.Key != "":
		return fmt.Errorf("give %s a password or a public key, not both", p.Name)
	case p.Password != "":
		return supervisor.CheckPassword(p.Password)
	}
	return nil
}

// Access is what a person added with the form may do: upload to the
// folders people may upload to, read the read-only ones.
func (f Form) Access() map[string]string {
	m := make(map[string]string, len(f.Folders))
	for _, fo := range f.Folders {
		if fo.ReadOnly {
			m[fo.Name] = "read"
		} else {
			m[fo.Name] = "upload"
		}
	}
	return m
}

// Apply writes the form to the configuration through gosftpd commands:
// the folders and the port, then the person. A first share writes the
// configuration with init; later only what changed is written, and the
// people lose the folders that go away. It returns the warnings gosftpd
// wrote. A failure leaves what was done so far: the folders may be
// written while the person is not added, and the next Apply adds them.
func (a *App) Apply(ctx context.Context, cur Current, f Form) (warnings string, err error) {
	if err := f.Check(cur); err != nil {
		return "", err
	}
	a.changeMu.Lock()
	defer a.changeMu.Unlock()
	var b strings.Builder
	if !cur.Configured {
		// Never over a configuration that was not read: init --force
		// would replace it, and keep the people of its users.d/.
		if _, err := a.Load(ctx); err != nil {
			return "", err
		}
		if a.G.Layout.Exists() {
			return "", fmt.Errorf("%s exists but was not read: start gosftpd-gui again", a.G.Layout.Config())
		}
		w, err := a.admin().Write(ctx, supervisor.Settings{
			Folders:        f.Folders,
			Listen:         []string{":" + strconv.Itoa(f.Port)},
			OnConflict:     f.OnConflict,
			PasswordLogins: f.Person.Password != "",
		})
		b.WriteString(w)
		if err != nil {
			return b.String(), err
		}
	} else {
		old := cur.Port()
		w, err := a.admin().Change(ctx, func(s *supervisor.Settings) {
			s.Folders = f.Folders
			s.Listen = withPort(s.Listen, old, f.Port)
		})
		b.WriteString(w)
		if err != nil {
			return b.String(), err
		}
	}
	p := f.Person
	var w string
	switch {
	case p.empty():
	case p.Password != "":
		w, err = a.admin().AddWithPassword(ctx, p.Name, p.Password, f.Access())
	default:
		w, err = a.admin().AddWithKey(ctx, p.Name, p.Key, f.Access())
	}
	b.WriteString(w)
	return b.String(), err
}

// withPort returns listen with port instead of old in every address that
// has it, and [":port"] for an empty list.
func withPort(listen []string, old, port int) []string {
	if len(listen) == 0 {
		return []string{":" + strconv.Itoa(port)}
	}
	out := slices.Clone(listen)
	for i, addr := range out {
		host, p, err := net.SplitHostPort(addr)
		if err == nil && p == strconv.Itoa(old) {
			out[i] = net.JoinHostPort(host, strconv.Itoa(port))
		}
	}
	return out
}

// ErrSharing is a Start while the App shares already.
var ErrSharing = errors.New("already sharing")

// Start starts sharing: gosftpd serve, once its version is the GUI's and
// a server that a GUI before this one started has exited. waiting, if not
// nil, gets that server's pid before Start waits for it. Done then tells
// when gosftpd exits.
func (a *App) Start(ctx context.Context, waiting func(pid int)) (supervisor.Details, error) {
	a.mu.Lock()
	running := a.srv != nil
	a.mu.Unlock()
	if running {
		return supervisor.Details{}, ErrSharing
	}
	if a.Version != "" {
		if err := a.G.CheckVersion(ctx, a.Version); err != nil {
			return supervisor.Details{}, err
		}
	}
	if err := a.waitPrevious(ctx, waiting); err != nil {
		return supervisor.Details{}, err
	}
	// Nobody is connected to a server that has not started: the log is
	// read to its end, and its sessions, of a server that died without
	// server.stop, do not count. The new server's server.start and
	// sessions follow, and may come before Start returns.
	a.mu.Lock()
	a.logTail = nil
	_, _, _ = a.followerLocked().Poll()
	a.activity.Exited()
	a.mu.Unlock()
	srv, err := a.G.Start(ctx, a.log)
	if err != nil {
		return supervisor.Details{}, err
	}
	if a.Lock != nil {
		if err := a.Lock.SetServer(srv.Details.PID); err != nil {
			srv.StopNow()
			return supervisor.Details{}, fmt.Errorf("recording the server's pid: %w", err)
		}
	}
	a.mu.Lock()
	a.srv, a.stopping = srv, false
	a.mu.Unlock()
	return srv.Details, nil
}

// waitPrevious waits until a gosftpd that a GUI before this one started
// on the state directory has exited: one draining after its GUI was
// killed. A new server would mix its audit events with that one's.
func (a *App) waitPrevious(ctx context.Context, waiting func(pid int)) error {
	if a.Lock == nil {
		return nil
	}
	told := false
	for {
		pid, err := a.Lock.PreviousServer(a.G.Layout)
		if err != nil || pid == 0 {
			return err
		}
		if !told && waiting != nil {
			waiting(pid)
			told = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// log keeps the warnings and errors of gosftpd's operational log.
func (a *App) log(r supervisor.LogRecord) {
	if r.Text == "" && r.Level != "WARN" && r.Level != "ERROR" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logSeq++
	a.logTail = append(a.logTail, logEntry{seq: a.logSeq, text: FormatRecord(r), plain: PlainRecord(r)})
	if len(a.logTail) > maxLogTail {
		a.logTail = a.logTail[len(a.logTail)-maxLogTail:]
	}
}

// FormatRecord is a record of the operational log as a line to show:
// "WARN message key=value ..." with the attributes sorted, or the line as
// gosftpd wrote it when it was not JSON.
func FormatRecord(r supervisor.LogRecord) string {
	if r.Text != "" {
		return r.Text
	}
	var b strings.Builder
	b.WriteString(r.Level)
	b.WriteByte(' ')
	b.WriteString(r.Msg)
	keys := make([]string, 0, len(r.Attrs))
	for k := range r.Attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%v", k, r.Attrs[k])
	}
	return b.String()
}

// LogTail returns the last warnings and errors gosftpd wrote since the
// last Start, oldest first.
func (a *App) LogTail() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.logTexts()
}

func (a *App) logTexts() []string {
	out := make([]string, len(a.logTail))
	for i, e := range a.logTail {
		out[i] = e.text
	}
	return out
}

// Done is closed when the gosftpd of the last Start exits; nil when the
// App never started one.
func (a *App) Done() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv == nil {
		return nil
	}
	return a.srv.Done()
}

// Sharing reports whether gosftpd runs.
func (a *App) Sharing() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.srv != nil
}

// Stop asks gosftpd to stop: it stops accepting, waits up to
// shutdown_timeout (30 s by default) for the connections to end, then
// closes the rest. It returns at once; Done tells when gosftpd exits.
func (a *App) Stop() {
	a.mu.Lock()
	srv := a.srv
	a.stopping = srv != nil
	a.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

// StopNow ends gosftpd at once, cutting the connections still open
// ("Stop now"). It blocks for up to a few seconds.
func (a *App) StopNow() {
	a.mu.Lock()
	srv := a.srv
	a.stopping = srv != nil
	a.mu.Unlock()
	if srv != nil {
		srv.StopNow()
	}
}

// Exited forgets gosftpd once Done is closed, and says how it ended: nil
// when it was asked to stop and did, or an error that names its exit and
// the last error it logged.
func (a *App) Exited() error {
	a.mu.Lock()
	srv, stopping := a.srv, a.stopping
	if srv == nil {
		a.mu.Unlock()
		return nil
	}
	select {
	case <-srv.Done():
	default:
		// A Restart's new server: the exit was of the one it replaced,
		// which Restart has dealt with.
		a.mu.Unlock()
		return nil
	}
	a.srv, a.stopping = nil, false
	a.activity.Exited()
	tail := a.logTexts()
	a.mu.Unlock()
	if a.Lock != nil {
		_ = a.Lock.ClearServer()
	}
	err := srv.Err()
	if stopping && (err == nil || stoppedBySignal(err)) {
		return nil
	}
	if err == nil {
		err = errors.New("it exited")
	}
	msg := "gosftpd stopped unexpectedly: " + err.Error()
	if len(tail) > 0 {
		msg += "\n" + strings.Join(tail, "\n")
	}
	return errors.New(msg)
}

// stoppedBySignal reports whether gosftpd was ended by the second SIGTERM
// of StopNow, which it leaves to the signal's default action, or by the
// SIGKILL StopNow falls back on.
func stoppedBySignal(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && (ws.Signal() == syscall.SIGTERM || ws.Signal() == syscall.SIGKILL)
}

// Poll reads the audit events gosftpd wrote since the last Poll, from
// where Clear activity left the view, and returns who is connected, the
// oldest first: nobody when the App does not share.
func (a *App) Poll() (connected []supervisor.Session, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	events, reset, err := a.followerLocked().Poll()
	if reset {
		a.activity.Reset()
		a.forgetClearedLocked()
	}
	for _, e := range events {
		a.activity.Apply(e)
	}
	if a.srv == nil {
		return nil, err
	}
	return a.activity.Connected(), err
}

// Landlock is the sandbox state of the running server, from its
// server.start event: v2 to v5, off, unavailable; empty before the event
// or on a system without Landlock.
func (a *App) Landlock() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activity.Landlock
}

// Names returns the user names of sessions, each once, in order.
func Names(sessions []supervisor.Session) []string {
	var names []string
	for _, s := range sessions {
		if !slices.Contains(names, s.User) {
			names = append(names, s.User)
		}
	}
	return names
}
