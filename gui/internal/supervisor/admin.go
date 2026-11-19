// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// Folder is a shared folder: a mount of the configuration.
type Folder struct {
	Name     string
	Path     string
	ReadOnly bool
}

// Settings are what the GUI writes with init --force. The configuration
// is their only record: the GUI reads them back with Read.
type Settings struct {
	Folders        []Folder
	Listen         []string // [":2022"] when empty
	OnConflict     string   // "rename" when empty
	PasswordLogins bool
}

// Shown is config show --json: the part of the configuration the GUI
// reads.
type Shown struct {
	File   string `json:"file"`
	Server struct {
		Listen   []string `json:"listen"`
		HostKeys []string `json:"host_keys"`
	} `json:"server"`
	Auth struct {
		Methods []string `json:"methods"`
	} `json:"auth"`
	Defaults struct {
		OnConflict string `json:"on_conflict"`
	} `json:"defaults"`
	Mounts map[string]ShownMount `json:"mounts"`
	Audit  struct {
		Output string `json:"output"`
	} `json:"audit"`
	Reload struct {
		DisconnectRemovedUsers bool `json:"disconnect_removed_users"`
	} `json:"reload"`
}

// ShownMount is a mount of config show --json.
type ShownMount struct {
	Path       string `json:"path"`
	ReadOnly   bool   `json:"read_only"`
	Create     bool   `json:"create"`
	OnConflict string `json:"on_conflict"`
}

// Person is an entry of user list --json.
type Person struct {
	Name           string            `json:"name"`
	Access         map[string]string `json:"access"`
	Keys           int               `json:"keys"`
	KeysUnreadable bool              `json:"keys_unreadable"`
	KeysOff        bool              `json:"keys_off"`
	Principals     []string          `json:"principals"`
	PrincipalsOff  bool              `json:"principals_off"`
	Password       bool              `json:"password"`
	PasswordOff    bool              `json:"password_off"`
	Expires        *string           `json:"expires"`
	Status         string            `json:"status"`
}

// Admin changes the GUI's configuration, only through gosftpd commands
// (ADR 0013, "Lifecycle"). Its methods return the warnings gosftpd wrote,
// for the GUI to show.
type Admin struct {
	G Gosftpd
}

func (a Admin) config() string { return a.G.Layout.Config() }

// Write writes the configuration of s with init --force, as the GUI writes
// it: no user of init's own, folders that must exist, the people's
// connections closed when they are disabled or removed, and the audit log
// in the state directory. init refuses an invalid configuration and then
// leaves the old file as it was.
func (a Admin) Write(ctx context.Context, s Settings) (warnings string, err error) {
	if len(s.Folders) == 0 {
		return "", errors.New("share at least one folder")
	}
	if err := a.G.Layout.Ensure(); err != nil {
		return "", err
	}
	l := a.G.Layout
	args := []string{
		"init", "--force", "--out", l.Config(), "--state-dir", l.Dir,
		"--no-user", "--no-create", "--disconnect-removed-users", "--audit-output", l.AuditLog(),
	}
	onConflict := s.OnConflict
	if onConflict == "" {
		onConflict = "rename"
	}
	args = append(args, "--on-conflict", onConflict)
	listen := s.Listen
	if len(listen) == 0 {
		listen = []string{":2022"}
	}
	for _, addr := range listen {
		args = append(args, "--listen", addr)
	}
	if s.PasswordLogins {
		args = append(args, "--password-logins")
	}
	for _, f := range s.Folders {
		args = append(args, "--dir", f.Name+"="+f.Path)
	}
	for _, f := range s.Folders {
		if f.ReadOnly {
			args = append(args, "--read-only", f.Name)
		}
	}
	_, warnings, err = a.G.run(ctx, nil, args...)
	return warnings, err
}

// Show is config show --json.
func (a Admin) Show(ctx context.Context) (Shown, error) {
	var s Shown
	err := a.G.runJSON(ctx, &s, "config", "show", "--json", "--config", a.config())
	return s, err
}

// Read returns the settings of the configuration, and the names of the
// folders whose on_conflict or create a hand edit set apart from the
// rest: the next Write resets them, which the GUI says first.
func (a Admin) Read(ctx context.Context) (s Settings, reset []string, err error) {
	shown, err := a.Show(ctx)
	if err != nil {
		return Settings{}, nil, err
	}
	s.Listen = shown.Server.Listen
	s.OnConflict = shown.Defaults.OnConflict
	s.PasswordLogins = slices.Contains(shown.Auth.Methods, "password")
	for _, name := range slices.Sorted(maps.Keys(shown.Mounts)) {
		m := shown.Mounts[name]
		s.Folders = append(s.Folders, Folder{Name: name, Path: m.Path, ReadOnly: m.ReadOnly})
		if m.OnConflict != shown.Defaults.OnConflict || m.Create {
			reset = append(reset, name)
		}
	}
	return s, reset, nil
}

// People is user list --json.
func (a Admin) People(ctx context.Context) ([]Person, error) {
	var ps []Person
	err := a.G.runJSON(ctx, &ps, "user", "list", "--json", "--config", a.config())
	return ps, err
}

// CheckPassword refuses a password that user add --password-stdin cannot
// take: it reads one line, so a password may hold no line break or other
// control character.
func CheckPassword(p string) error {
	if p == "" {
		return errors.New("the password is empty")
	}
	if strings.ContainsFunc(p, unicode.IsControl) {
		return errors.New("the password holds a line break or another control character")
	}
	return nil
}

// GeneratePassword returns 16 URL-safe characters from crypto/rand: 96
// bits.
func GeneratePassword() string {
	var b [12]byte
	_, _ = rand.Read(b[:]) // never fails (crypto/rand)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// errNoAccess is a person added with no folder: user add needs one.
var errNoAccess = errors.New("give the person at least one folder")

// accessArgs are --access flags for access, folder name to permissions,
// in a stable order; --no-access for none.
func accessArgs(access map[string]string) []string {
	if len(access) == 0 {
		return []string{"--no-access"}
	}
	args := make([]string, 0, 2*len(access))
	for _, name := range slices.Sorted(maps.Keys(access)) {
		args = append(args, "--access", name+"="+access[name])
	}
	return args
}

// passwordLogins turns password logins on or off in the configuration,
// keeping the rest of its settings, if they are not so already.
func (a Admin) passwordLogins(ctx context.Context, on bool) (warnings string, err error) {
	s, _, err := a.Read(ctx)
	if err != nil {
		return "", err
	}
	if s.PasswordLogins == on {
		return "", nil
	}
	s.PasswordLogins = on
	return a.Write(ctx, s)
}

// anyPassword reports whether a person has a password, enabled or not:
// password logins stay on while one does, so that enabling a person again
// never leaves them unable to log in.
func anyPassword(ps []Person) bool {
	return slices.ContainsFunc(ps, func(p Person) bool { return p.Password })
}

// AddWithPassword adds a person who logs in with password, turning
// password logins on first if nobody has a password yet. The password
// goes to gosftpd on stdin, never as an argument.
func (a Admin) AddWithPassword(ctx context.Context, name, password string, access map[string]string) (warnings string, err error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	if len(access) == 0 {
		return "", errNoAccess
	}
	w1, err := a.passwordLogins(ctx, true)
	if err != nil {
		return w1, err
	}
	args := append([]string{"user", "add", name, "--password-stdin", "--write", "--config", a.config()}, accessArgs(access)...)
	_, w2, err := a.G.run(ctx, strings.NewReader(password+"\n"), args...)
	if err != nil {
		// Password logins only while someone has a password: not after
		// an add that gosftpd refused.
		_, _ = a.syncPasswordLogins(ctx)
	}
	return w1 + w2, err
}

// syncPasswordLogins turns password logins on exactly while someone has a
// password.
func (a Admin) syncPasswordLogins(ctx context.Context) (warnings string, err error) {
	ps, err := a.People(ctx)
	if err != nil {
		return "", err
	}
	return a.passwordLogins(ctx, anyPassword(ps))
}

// AddWithKey adds a person who logs in with key, an authorized_keys line.
func (a Admin) AddWithKey(ctx context.Context, name, key string, access map[string]string) (warnings string, err error) {
	if len(access) == 0 {
		return "", errNoAccess
	}
	args := append([]string{"user", "add", name, "--key", strings.TrimSpace(key), "--write", "--config", a.config()}, accessArgs(access)...)
	_, warnings, err = a.G.run(ctx, nil, args...)
	return warnings, err
}

// SetAccess replaces what the person may do: folder name to permissions,
// none when access is empty. People who are connected keep the access
// they had until they disconnect (ADR 0005).
func (a Admin) SetAccess(ctx context.Context, name string, access map[string]string) (warnings string, err error) {
	args := append([]string{"user", "set", name, "--config", a.config()}, accessArgs(access)...)
	_, warnings, err = a.G.run(ctx, nil, args...)
	return warnings, err
}

// SetPassword gives the person a new password, turning password logins on
// first if nobody had a password.
func (a Admin) SetPassword(ctx context.Context, name, password string) (warnings string, err error) {
	if err := CheckPassword(password); err != nil {
		return "", err
	}
	w1, err := a.passwordLogins(ctx, true)
	if err != nil {
		return w1, err
	}
	_, w2, err := a.G.run(ctx, strings.NewReader(password+"\n"), "user", "set", name, "--password-stdin", "--config", a.config())
	return w1 + w2, err
}

// Disable keeps the person, but refuses their logins and ends their
// connections at the next reload. Password logins stay as they are.
func (a Admin) Disable(ctx context.Context, name string) (string, error) {
	_, w, err := a.G.run(ctx, nil, "user", "disable", name, "--config", a.config())
	return w, err
}

// Enable lets a disabled person log in again.
func (a Admin) Enable(ctx context.Context, name string) (string, error) {
	_, w, err := a.G.run(ctx, nil, "user", "enable", name, "--config", a.config())
	return w, err
}

// Remove removes the person, and turns password logins off when nobody
// with a password is left.
func (a Admin) Remove(ctx context.Context, name string) (warnings string, err error) {
	_, w1, err := a.G.run(ctx, nil, "user", "remove", name, "--config", a.config())
	if err != nil {
		return w1, err
	}
	w2, err := a.syncPasswordLogins(ctx)
	return w1 + w2, err
}

// SetFolders replaces the shared folders, keeping the other settings, as
// Change does.
func (a Admin) SetFolders(ctx context.Context, folders []Folder) (warnings string, err error) {
	return a.Change(ctx, func(s *Settings) { s.Folders = folders })
}

// Change reads the settings, applies edit and writes them if they
// changed. First it takes every folder that goes away from everyone who
// has it, since a grant for a missing folder makes the configuration
// invalid. It refuses to remove the last folder: a configuration needs
// one.
func (a Admin) Change(ctx context.Context, edit func(*Settings)) (warnings string, err error) {
	s, _, err := a.Read(ctx)
	if err != nil {
		return "", err
	}
	old := s
	old.Folders = slices.Clone(s.Folders)
	old.Listen = slices.Clone(s.Listen)
	edit(&s)
	if len(s.Folders) == 0 {
		return "", errors.New("keep at least one folder: a configuration needs one")
	}
	if settingsEqual(old, s) {
		return "", nil
	}
	keep := map[string]bool{}
	for _, f := range s.Folders {
		keep[f.Name] = true
	}
	ps, err := a.People(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, p := range ps {
		access := maps.Clone(p.Access)
		maps.DeleteFunc(access, func(name, _ string) bool { return !keep[name] })
		if len(access) == len(p.Access) {
			continue
		}
		w, err := a.SetAccess(ctx, p.Name, access)
		b.WriteString(w)
		if err != nil {
			return b.String(), fmt.Errorf("taking the removed folders from %s: %w", p.Name, err)
		}
	}
	w, err := a.Write(ctx, s)
	b.WriteString(w)
	return b.String(), err
}

// settingsEqual reports whether a and b write the same configuration.
// The order of the folders does not matter: Read returns them by name.
func settingsEqual(a, b Settings) bool {
	norm := func(s Settings) Settings {
		if len(s.Listen) == 0 {
			s.Listen = []string{":2022"}
		}
		if s.OnConflict == "" {
			s.OnConflict = "rename"
		}
		s.Folders = slices.SortedFunc(slices.Values(s.Folders), func(x, y Folder) int { return strings.Compare(x.Name, y.Name) })
		return s
	}
	a, b = norm(a), norm(b)
	return slices.Equal(a.Folders, b.Folders) && slices.Equal(a.Listen, b.Listen) &&
		a.OnConflict == b.OnConflict && a.PasswordLogins == b.PasswordLogins
}
