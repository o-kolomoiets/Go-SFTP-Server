// SPDX-License-Identifier: Apache-2.0

// Package config loads, validates and checks the gosftpd configuration file
// (TOML, schema version 1; ROADMAP §6.6).
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// Version is the configuration schema version this build understands.
const Version = 1

// maxFileSize bounds a configuration file.
const maxFileSize = 1 << 20

// Config is the whole configuration.
type Config struct {
	ConfigVersion int               `toml:"config_version"`
	Include       []string          `toml:"include,omitempty"`
	Server        Server            `toml:"server"`
	Limits        Limits            `toml:"limits"`
	Auth          Auth              `toml:"auth"`
	Defaults      Defaults          `toml:"defaults"`
	Mounts        map[string]*Mount `toml:"mounts"`
	Users         map[string]*User  `toml:"users"`
	Log           Log               `toml:"log"`
	Audit         Audit             `toml:"audit"`

	// File is the file the configuration was loaded from, "" when it was
	// built from command-line flags. Files lists File and every included
	// file.
	File  string   `toml:"-"`
	Files []string `toml:"-"`
	// AnyUser is set in zero-config mode (serve --dir): every SSH user name
	// is accepted with these keys and gets full access to every mount.
	AnyUser *ZeroConfigUser `toml:"-"`
}

// Server is the [server] table.
type Server struct {
	Listen              []string `toml:"listen"`
	HostKeys            []string `toml:"host_keys"`
	HostKeyAutoGenerate bool     `toml:"host_key_auto_generate"`
	CryptoPolicy        string   `toml:"crypto_policy"`
	HandshakeTimeout    Duration `toml:"handshake_timeout"`
	IdleTimeout         Duration `toml:"idle_timeout"`
	KeepaliveInterval   Duration `toml:"keepalive_interval"`
	ShutdownTimeout     Duration `toml:"shutdown_timeout"`
}

// Limits is the [limits] table.
type Limits struct {
	MaxConnections        int `toml:"max_connections"`
	MaxConnectionsPerIP   int `toml:"max_connections_per_ip"`
	MaxPreauthConnections int `toml:"max_preauth_connections"`
	MaxSessionsPerConn    int `toml:"max_sessions_per_conn"`
	MaxOpenHandles        int `toml:"max_open_handles"`
	MaxAuthTries          int `toml:"max_auth_tries"`
}

// Auth is the [auth] table.
type Auth struct {
	Methods []string `toml:"methods"`
	Ban     Ban      `toml:"ban"`
}

// HasMethod reports whether login method m is enabled.
func (a Auth) HasMethod(m string) bool { return slices.Contains(a.Methods, m) }

// Ban is the [auth.ban] table.
type Ban struct {
	AfterFailures int      `toml:"after_failures"` // 0 disables bans
	Within        Duration `toml:"within"`
	Duration      Duration `toml:"duration"`
	Exempt        []string `toml:"exempt"`
}

// MountOptions are the per-mount options; [defaults] provides the values a
// mount does not set.
type MountOptions struct {
	OnConflict         string   `toml:"on_conflict"`
	RenameTemplate     string   `toml:"rename_template"`
	MaxRenameAttempts  int      `toml:"max_rename_attempts"`
	CompoundExtensions []string `toml:"compound_extensions"`
	SetstatMode        string   `toml:"setstat_mode"`
	Umask              FileMode `toml:"umask"`
	RequireMountpoint  bool     `toml:"require_mountpoint"`
	Resume             string   `toml:"resume"`
	StatRedirect       bool     `toml:"stat_redirect"`
	Symlinks           string   `toml:"symlinks"`
}

func (o MountOptions) clone() MountOptions {
	o.CompoundExtensions = slices.Clone(o.CompoundExtensions)
	return o
}

// Defaults is the [defaults] table.
type Defaults struct {
	MountOptions

	// Flatten serves a user's only mount as "/".
	Flatten bool `toml:"flatten"`
}

// Mount is a [mounts.NAME] table.
type Mount struct {
	Path     string `toml:"path"`
	Create   bool   `toml:"create"`
	ReadOnly bool   `toml:"read_only"`
	MountOptions
}

// User is a [users.NAME] table.
type User struct {
	AuthorizedKeys     []string          `toml:"authorized_keys,omitempty"`
	AuthorizedKeysFile string            `toml:"authorized_keys_file,omitempty"`
	PasswordHash       string            `toml:"password_hash,omitempty"`
	AllowFrom          []string          `toml:"allow_from,omitempty"`
	Expires            *time.Time        `toml:"expires,omitempty"`
	Disabled           bool              `toml:"disabled,omitempty"`
	Access             map[string]string `toml:"access"`

	// From is the file that defined the user (an include or the main file).
	From string `toml:"-"`
}

// ZeroConfigUser describes the implicit user of zero-config mode.
type ZeroConfigUser struct {
	Name               string // "" accepts any name
	AuthorizedKeysFile string
}

// Log is the [log] table.
type Log struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Audit is the [audit] table.
type Audit struct {
	Output string `toml:"output"`
	// Events lists the recorded categories; server events are always on.
	Events  []string `toml:"events"`
	OnError string   `toml:"on_error"`
}

// Audit error modes (decision D20).
const (
	AuditFailClosed = "fail-closed"
	AuditFailOpen   = "fail-open"
)

// Default returns the built-in defaults.
func Default() *Config {
	o := vfs.DefaultMountOptions()
	return &Config{
		ConfigVersion: Version,
		Server: Server{
			Listen:            []string{":2022"},
			CryptoPolicy:      "modern",
			HandshakeTimeout:  Duration(30 * time.Second),
			IdleTimeout:       Duration(15 * time.Minute),
			KeepaliveInterval: Duration(30 * time.Second),
			ShutdownTimeout:   Duration(30 * time.Second),
		},
		Limits: Limits{
			MaxConnections:        256,
			MaxConnectionsPerIP:   16,
			MaxPreauthConnections: 64,
			MaxSessionsPerConn:    4,
			MaxOpenHandles:        64,
			MaxAuthTries:          6,
		},
		Auth: Auth{
			Methods: []string{auth.MethodPublicKey},
			Ban: Ban{
				AfterFailures: auth.DefaultBanAfterFailures,
				Within:        Duration(auth.DefaultBanWithin),
				Duration:      Duration(auth.DefaultBanDuration),
				Exempt:        []string{"127.0.0.0/8", "::1/128"},
			},
		},
		Defaults: Defaults{
			MountOptions: MountOptions{
				OnConflict:         string(o.OnConflict),
				RenameTemplate:     o.RenameTemplate,
				MaxRenameAttempts:  o.MaxRenameAttempts,
				CompoundExtensions: o.CompoundExts,
				SetstatMode:        string(o.SetstatMode),
				Umask:              FileMode(o.Umask),
				Resume:             string(o.Resume),
				StatRedirect:       o.StatRedirect,
				Symlinks:           string(o.Symlinks),
			},
			Flatten: true,
		},
		Mounts: map[string]*Mount{},
		Users:  map[string]*User{},
		Log:    Log{Level: "info", Format: "text"},
		Audit:  Audit{Output: "stdout", Events: slices.Clone(audit.DefaultCategories), OnError: AuditFailClosed},
	}
}

// AddMount adds a mount that inherits [defaults] and returns it.
func (c *Config) AddMount(name, path string) *Mount {
	m := &Mount{Path: path, MountOptions: c.Defaults.clone()}
	c.Mounts[name] = m
	return m
}

// fileConfig is the decoding shape of a main configuration file: mounts are
// decoded after [defaults], so that they inherit it.
type fileConfig struct {
	ConfigVersion int                       `toml:"config_version"`
	Include       []string                  `toml:"include"`
	Server        Server                    `toml:"server"`
	Limits        Limits                    `toml:"limits"`
	Auth          Auth                      `toml:"auth"`
	Defaults      Defaults                  `toml:"defaults"`
	Mounts        map[string]toml.Primitive `toml:"mounts"`
	Users         map[string]*User          `toml:"users"`
	Log           Log                       `toml:"log"`
	Audit         Audit                     `toml:"audit"`
}

// includeFile is what an included file may contain.
type includeFile struct {
	Users map[string]*User `toml:"users"`
}

// Load reads the configuration file at path and the files it includes.
// Relative paths inside are resolved against the directory of path. The
// result still needs Validate.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := readFile(abs)
	if err != nil {
		return nil, err
	}

	d := Default()
	raw := fileConfig{
		Server:   d.Server,
		Limits:   d.Limits,
		Auth:     d.Auth,
		Defaults: d.Defaults,
		Log:      d.Log,
		Audit:    d.Audit,
	}
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, decodeError(abs, err)
	}

	c := &Config{
		ConfigVersion: raw.ConfigVersion,
		Include:       raw.Include,
		Server:        raw.Server,
		Limits:        raw.Limits,
		Auth:          raw.Auth,
		Defaults:      raw.Defaults,
		Mounts:        make(map[string]*Mount, len(raw.Mounts)),
		Users:         raw.Users,
		Log:           raw.Log,
		Audit:         raw.Audit,
		File:          abs,
		Files:         []string{abs},
	}
	if c.Users == nil {
		c.Users = map[string]*User{}
	}
	for name, u := range c.Users {
		if u == nil {
			c.Users[name] = &User{}
		}
		c.Users[name].From = abs
	}
	for _, name := range sortedKeys(raw.Mounts) {
		m := &Mount{MountOptions: c.Defaults.clone()}
		if err := md.PrimitiveDecode(raw.Mounts[name], m); err != nil {
			return nil, decodeError(abs, err)
		}
		c.Mounts[name] = m
	}
	if err := errors.Join(unknownKeys(abs, md), exactKeys(abs, md, reflect.TypeFor[Config]())); err != nil {
		return nil, err
	}

	dir := filepath.Dir(abs)
	c.resolvePaths(dir)
	if err := c.loadIncludes(dir); err != nil {
		return nil, err
	}
	return c, nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxFileSize)
	}
	return data, nil
}

// decodeError shows TOML syntax and type errors with their position.
func decodeError(file string, err error) error {
	if pe, ok := errors.AsType[toml.ParseError](err); ok {
		return fmt.Errorf("%s: %s", file, pe.ErrorWithPosition())
	}
	return fmt.Errorf("%s: %w", file, err)
}

func unknownKeys(file string, md toml.MetaData) error {
	undecoded := md.Undecoded()
	errs := make([]error, 0, len(undecoded))
	for _, k := range undecoded {
		errs = append(errs, fmt.Errorf("%s: unknown key %s", file, k))
	}
	return errors.Join(errs...)
}

// exactKeys reports keys that match a field only when case is ignored:
// BurntSushi/toml accepts PATH for path, but TOML keys are case-sensitive
// and a second spelling would silently compete with the first. Keys with no
// match at all are reported by unknownKeys.
func exactKeys(file string, md toml.MetaData, root reflect.Type) error {
	var errs []error
	var reported []toml.Key
	for _, k := range md.Keys() {
		if slices.ContainsFunc(reported, func(r toml.Key) bool { return len(r) <= len(k) && slices.Equal(r, k[:len(r)]) }) {
			continue // a parent table was already reported
		}
		t := root
	walk:
		for _, part := range k {
			for t.Kind() == reflect.Pointer {
				t = t.Elem()
			}
			switch {
			case t.Kind() == reflect.Map:
				t = t.Elem() // part is a name: a mount, a user, an access entry
			case t.Kind() == reflect.Struct && t != reflect.TypeFor[time.Time]():
				f, exact, found := fieldByTag(t, part)
				if !found {
					break walk
				}
				if !exact {
					errs = append(errs, fmt.Errorf("%s: unknown key %s (keys are case-sensitive)", file, k))
					reported = append(reported, k)
					break walk
				}
				t = f.Type
			default:
				break walk
			}
		}
	}
	return errors.Join(errs...)
}

// fieldByTag finds the field whose toml tag is name, looking into embedded
// structs; exact is false when only a case-insensitive match exists.
func fieldByTag(t reflect.Type, name string) (f reflect.StructField, exact, found bool) {
	for sf := range t.Fields() {
		if sf.Anonymous && sf.Type.Kind() == reflect.Struct {
			ff, ex, ok := fieldByTag(sf.Type, name)
			if ok && ex {
				return ff, true, true
			}
			if ok && !found {
				f, found = ff, true
			}
			continue
		}
		tag, _, _ := strings.Cut(sf.Tag.Get("toml"), ",")
		switch {
		case tag == name:
			return sf, true, true
		case strings.EqualFold(tag, name) && !found:
			f, found = sf, true
		}
	}
	return f, false, found
}

// resolvePaths makes relative file paths relative to the config directory.
// Mount paths are not touched: they must be absolute (Validate).
func (c *Config) resolvePaths(dir string) {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	for i, p := range c.Server.HostKeys {
		c.Server.HostKeys[i] = abs(p)
	}
	if c.Audit.Output != "stdout" {
		c.Audit.Output = abs(c.Audit.Output)
	}
	for _, u := range c.Users {
		u.AuthorizedKeysFile = abs(u.AuthorizedKeysFile)
	}
}

// loadIncludes merges the users of every included file. An include may only
// define users, and a user may be defined once.
func (c *Config) loadIncludes(dir string) error {
	var errs []error
	for _, pattern := range c.Include {
		files, err := globInclude(dir, pattern)
		if err != nil {
			errs = append(errs, fmt.Errorf("include %q: %w", pattern, err))
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			if slices.Contains(c.Files, f) {
				continue
			}
			if err := c.loadInclude(f); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// globInclude expands an include pattern. A relative pattern is matched
// inside dir without treating dir itself as a pattern (it may contain [ or
// *), and must stay below it.
func globInclude(dir, pattern string) ([]string, error) {
	if filepath.IsAbs(pattern) {
		return filepath.Glob(pattern)
	}
	rel := filepath.ToSlash(filepath.Clean(pattern))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, errors.New("a relative pattern must stay inside the configuration directory; use an absolute path")
	}
	matches, err := fs.Glob(os.DirFS(dir), rel)
	if err != nil {
		return nil, err
	}
	files := make([]string, len(matches))
	for i, m := range matches {
		files[i] = filepath.Join(dir, filepath.FromSlash(m))
	}
	return files, nil
}

func (c *Config) loadInclude(file string) error {
	data, err := readFile(file)
	if err != nil {
		return err
	}
	var inc includeFile
	md, err := toml.Decode(string(data), &inc)
	if err != nil {
		return decodeError(file, err)
	}
	if err := errors.Join(unknownKeys(file, md), exactKeys(file, md, reflect.TypeFor[includeFile]())); err != nil {
		return fmt.Errorf("%w (an included file may only define [users.NAME] tables)", err)
	}
	c.Files = append(c.Files, file)
	var errs []error
	for _, name := range sortedKeys(inc.Users) {
		u := inc.Users[name]
		if u == nil {
			u = &User{}
		}
		if prev, ok := c.Users[name]; ok {
			errs = append(errs, fmt.Errorf("%s: user %q is already defined in %s", file, name, prev.From))
			continue
		}
		u.From = file
		if u.AuthorizedKeysFile != "" && !filepath.IsAbs(u.AuthorizedKeysFile) {
			u.AuthorizedKeysFile = filepath.Join(filepath.Dir(file), u.AuthorizedKeysFile)
		}
		c.Users[name] = u
	}
	return errors.Join(errs...)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Duration is a time.Duration written as a string such as "30s".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("invalid duration %q (examples: 30s, 15m, 1h)", b)
	}
	*d = Duration(v)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// FileMode is a permission mask written as an octal string such as "0027".
type FileMode fs.FileMode

// UnmarshalTOML accepts only strings, so that umask = 27 (decimal) cannot
// be mistaken for 0o027.
func (m *FileMode) UnmarshalTOML(v any) error {
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("want a quoted octal string such as \"0027\", got %v", v)
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return fmt.Errorf("invalid mode %q: want an octal string from \"0000\" to \"0777\"", s)
	}
	*m = FileMode(n)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (m FileMode) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%04o", uint32(m))), nil
}
