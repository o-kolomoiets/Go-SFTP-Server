// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// problems collects validation errors and warnings, each with its key path.
type problems struct {
	errs  []error
	warns []string
}

func (p *problems) errorf(key, format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, args...)))
}

func (p *problems) warnf(key, format string, args ...any) {
	p.warns = append(p.warns, fmt.Sprintf("%s: %s", key, fmt.Sprintf(format, args...)))
}

func (p *problems) result() ([]string, error) { return p.warns, errors.Join(p.errs...) }

// key formats a TOML key path, quoting parts that need it.
func key(parts ...string) string { return toml.Key(parts).String() }

// Limits for numeric settings.
const (
	maxHandshakeTimeout = 10 * time.Minute
	maxShutdownTimeout  = time.Hour
	maxSessions         = 64
	maxHandles          = 4096
	maxAuthTries        = 20
)

// Validate checks the configuration without touching the filesystem and
// reports every problem at once. Warnings do not prevent startup.
func (c *Config) Validate() (warnings []string, err error) {
	p := &problems{}
	switch c.ConfigVersion {
	case Version:
	case 0:
		p.errorf("config_version", "missing; add config_version = %d at the top of the file", Version)
	default:
		p.errorf("config_version", "%d is not supported by this version of gosftpd (it supports %d)", c.ConfigVersion, Version)
	}
	c.validateServer(p)
	c.validateLimits(p)
	c.Defaults.validate(p, nil, "defaults")
	c.validateMounts(p)
	c.validateUsers(p)
	c.validateLogs(p)
	return p.result()
}

func (c *Config) validateServer(p *problems) {
	s := c.Server
	if len(s.Listen) == 0 {
		p.errorf("server.listen", "at least one address is required, e.g. [\":2022\"]")
	}
	for _, addr := range s.Listen {
		if err := validListen(addr); err != nil {
			p.errorf("server.listen", "%v", err)
		}
	}
	if len(s.HostKeys) == 0 && c.AnyUser == nil {
		p.errorf("server.host_keys", "at least one host key file is required (with host_key_auto_generate = true it is created on first start)")
	}
	for _, k := range s.HostKeys {
		if k == "" {
			p.errorf("server.host_keys", "empty path")
		}
	}
	if d := time.Duration(s.HandshakeTimeout); d <= 0 || d > maxHandshakeTimeout {
		p.errorf("server.handshake_timeout", "must be between 1s and %s", maxHandshakeTimeout)
	}
	if d := time.Duration(s.ShutdownTimeout); d <= 0 || d > maxShutdownTimeout {
		p.errorf("server.shutdown_timeout", "must be between 1s and %s", maxShutdownTimeout)
	}
}

func validListen(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: want HOST:PORT or :PORT", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%q: invalid port", addr)
	}
	return nil
}

func (c *Config) validateLimits(p *problems) {
	for _, l := range []struct {
		key      string
		val, max int
	}{
		{"limits.max_sessions_per_conn", c.Limits.MaxSessionsPerConn, maxSessions},
		{"limits.max_open_handles", c.Limits.MaxOpenHandles, maxHandles},
		{"limits.max_auth_tries", c.Limits.MaxAuthTries, maxAuthTries},
	} {
		if l.val < 1 || l.val > l.max {
			p.errorf(l.key, "must be between 1 and %d", l.max)
		}
	}
}

// validate checks mount options under prefix. Values equal to the inherited
// ones in base were already reported for [defaults] and are skipped.
func (o MountOptions) validate(p *problems, base *MountOptions, prefix ...string) {
	inherited := func(field string) bool {
		if base == nil {
			return false
		}
		return reflect.DeepEqual(reflect.ValueOf(o).FieldByName(field).Interface(),
			reflect.ValueOf(*base).FieldByName(field).Interface())
	}
	k := func(name string) string { return key(append(prefix, name)...) }

	if !inherited("OnConflict") {
		if _, err := vfs.ParseConflictPolicy(o.OnConflict); err != nil {
			p.errorf(k("on_conflict"), "%v", err)
		}
	}
	if !inherited("RenameTemplate") {
		if err := vfs.ValidateRenameTemplate(o.RenameTemplate); err != nil {
			p.errorf(k("rename_template"), "%v", err)
		}
	}
	if !inherited("MaxRenameAttempts") && (o.MaxRenameAttempts < 1 || o.MaxRenameAttempts > vfs.MaxRenameAttempts) {
		p.errorf(k("max_rename_attempts"), "must be between 1 and %d", vfs.MaxRenameAttempts)
	}
	if !inherited("CompoundExtensions") {
		for _, e := range o.CompoundExtensions {
			if len(e) < 2 || e[0] != '.' || strings.ContainsAny(e, `/\`+"\x00") {
				p.errorf(k("compound_extensions"), "%q must start with '.' and contain no slashes", e)
			}
		}
	}
	if !inherited("SetstatMode") {
		if _, err := vfs.ParseSetstatMode(o.SetstatMode); err != nil {
			p.errorf(k("setstat_mode"), "%v", err)
		}
	}
}

func (c *Config) validateMounts(p *problems) {
	if len(c.Mounts) == 0 {
		p.errorf("mounts", "no mounts configured; add a [mounts.NAME] table with a path")
	}
	names := sortedKeys(c.Mounts)
	lower := map[string]string{}
	for i, name := range names {
		m := c.Mounts[name]
		k := func(parts ...string) string { return key(append([]string{"mounts", name}, parts...)...) }
		if !vfs.ValidMountName(name) {
			p.errorf(k(), "invalid mount name: use letters, digits, '.', '_', '-' and spaces (max 64, not starting with '.', not a device name like NUL)")
		}
		if prev, ok := lower[strings.ToLower(name)]; ok {
			p.errorf(k(), "clashes with mount %q (names are case-insensitive)", prev)
		}
		lower[strings.ToLower(name)] = name
		m.validate(p, &c.Defaults.MountOptions, "mounts", name)

		if m.Path == "" {
			p.errorf(k("path"), "required")
			continue
		}
		if err := vfs.ValidateMountPath(m.Path); err != nil {
			p.errorf(k("path"), "%v", err)
			continue
		}
		for _, other := range names[:i] {
			if o := c.Mounts[other]; vfs.ValidateMountPath(o.Path) == nil && vfs.PathsOverlap(m.Path, o.Path) {
				p.errorf(k("path"), "overlaps with mount %q (one directory inside the other)", other)
			}
		}
	}
}

func (c *Config) validateUsers(p *problems) {
	if len(c.Users) == 0 && c.AnyUser == nil {
		p.warnf("users", "no users configured: nobody can log in")
	}
	for _, name := range sortedKeys(c.Users) {
		u := c.Users[name]
		where := key("users", name)
		if u.From != "" && u.From != c.File {
			where += " (" + u.From + ")"
		}
		k := func(field string) string {
			if u.From != "" && u.From != c.File {
				return key("users", name, field) + " (" + u.From + ")"
			}
			return key("users", name, field)
		}
		if !auth.ValidUserName(name) {
			p.errorf(where, "invalid user name: use lowercase letters, digits, '.', '_' and '-' (max 32, starting with a letter or digit)")
		}
		if len(u.Access) == 0 {
			p.warnf(k("access"), "no mounts: the user can log in but sees nothing")
		}
		for _, mount := range sortedKeys(u.Access) {
			if _, ok := c.Mounts[mount]; !ok {
				p.errorf(k("access"), "unknown mount %q", mount)
			}
			if _, err := vfs.ParsePerm(u.Access[mount]); err != nil {
				p.errorf(k("access"), "%s: %v", mount, err)
			}
		}
		for i, line := range u.AuthorizedKeys {
			if strings.HasPrefix(strings.TrimSpace(line), "<") {
				p.errorf(k("authorized_keys"), "entry %d is a placeholder: replace it with a public key (the contents of ~/.ssh/id_ed25519.pub)", i+1)
				continue
			}
			keys, warns := auth.ParseAuthorizedKeys([]byte(line), "entry "+strconv.Itoa(i+1))
			for _, w := range warns {
				p.errorf(k("authorized_keys"), "%s", w)
			}
			if len(keys) == 0 && len(warns) == 0 {
				p.errorf(k("authorized_keys"), "entry %d is empty", i+1)
			}
		}
		for _, a := range u.AllowFrom {
			if _, err := auth.ParsePrefix(a); err != nil {
				p.errorf(k("allow_from"), "%v", err)
			}
		}
		if u.Expires != nil && u.Expires.Before(time.Now()) {
			p.warnf(k("expires"), "already expired (%s)", u.Expires.Format(time.RFC3339))
		}
		if len(u.AuthorizedKeys) == 0 && u.AuthorizedKeysFile == "" {
			p.warnf(where, "no authorized_keys or authorized_keys_file: the user cannot log in")
		}
	}
}

func (c *Config) validateLogs(p *problems) {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		p.errorf("log.level", "unknown level %q (want debug, info, warn or error)", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		p.errorf("log.format", "unknown format %q (want text or json)", c.Log.Format)
	}
	if c.Audit.Output == "" {
		p.errorf("audit.output", `required: "stdout" or a file path`)
	}
}
