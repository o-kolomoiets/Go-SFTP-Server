// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// MountSpecs converts the mounts for vfs.Open. Call after Validate.
func (c *Config) MountSpecs() ([]vfs.MountSpec, error) {
	specs := make([]vfs.MountSpec, 0, len(c.Mounts))
	for _, name := range sortedKeys(c.Mounts) {
		m := c.Mounts[name]
		opts, err := m.toVFS()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key("mounts", name), err)
		}
		specs = append(specs, vfs.MountSpec{Name: name, Path: m.Path, ReadOnly: m.ReadOnly, Create: m.Create, Options: opts})
	}
	return specs, nil
}

func (o MountOptions) toVFS() (vfs.MountOptions, error) {
	policy, err := vfs.ParseConflictPolicy(o.OnConflict)
	if err != nil {
		return vfs.MountOptions{}, err
	}
	mode, err := vfs.ParseSetstatMode(o.SetstatMode)
	if err != nil {
		return vfs.MountOptions{}, err
	}
	resume, err := vfs.ParseResumeMode(o.Resume)
	if err != nil {
		return vfs.MountOptions{}, err
	}
	links, err := vfs.ParseSymlinkPolicy(o.Symlinks)
	if err != nil {
		return vfs.MountOptions{}, err
	}
	return vfs.MountOptions{
		OnConflict:        policy,
		RenameTemplate:    o.RenameTemplate,
		MaxRenameAttempts: o.MaxRenameAttempts,
		CompoundExts:      slices.Clone(o.CompoundExtensions),
		SetstatMode:       mode,
		Umask:             fs.FileMode(o.Umask),
		Resume:            resume,
		StatRedirect:      o.StatRedirect,
		Symlinks:          links,
		MaxFileSize:       int64(o.MaxFileSize),
		MinFreeSpace:      int64(o.MinFreeSpace),
		AtomicUploads:     o.AtomicUploads,
		Fsync:             o.Fsync,
		Versions: vfs.VersionsOptions{
			Dir:    o.Versions.Dir,
			Keep:   o.Versions.Keep,
			MaxAge: time.Duration(o.Versions.MaxAge),
		},
	}, nil
}

// AuditOptions converts the [audit] table. Call after Validate.
func (c *Config) AuditOptions() audit.Options {
	return audit.Options{Categories: slices.Clone(c.Audit.Events), FailOpen: c.Audit.OnError == AuditFailOpen}
}

// Authenticator builds the authenticator, reading authorized_keys files.
// Key lines that cannot be used are skipped and returned as warnings. Call
// after Validate.
func (c *Config) Authenticator() (*auth.Authenticator, []string, error) {
	a, _, warns, err := c.BuildAuthenticator(AuthOptions{})
	return a, warns, err
}

// KeyFiles holds the keys read from authorized_keys files that are pipes,
// by path: a pipe can be read only once.
type KeyFiles map[string][]auth.Key

// AuthOptions configure BuildAuthenticator.
type AuthOptions struct {
	// Reload builds the authenticator for a configuration reload: an
	// authorized_keys file that is missing, not a regular file, not trusted
	// (as CheckFS checks at start) or without usable keys then gives no
	// keys, with a warning, instead of an error. So deleting a file, or
	// pointing it at /dev/null, revokes its keys, and one user's file does
	// not block the reload. A pipe, such as that of --authorized-keys
	// <(...), keeps the keys it gave before (Previous).
	Reload   bool
	Previous KeyFiles
}

// BuildAuthenticator is Authenticator with options; it also returns the
// keys of the files that are pipes, for the next reload.
func (c *Config) BuildAuthenticator(o AuthOptions) (*auth.Authenticator, KeyFiles, []string, error) {
	files := KeyFiles{}
	if c.AnyUser != nil {
		path := c.AnyUser.AuthorizedKeysFile
		keys, warns, err := o.readKeys(path, "--authorized-keys")
		if err != nil {
			return nil, nil, nil, err
		}
		if len(keys) == 0 {
			if !o.Reload {
				return nil, nil, warns, noKeysError(path)
			}
			warns = append(warns, "--authorized-keys: "+path+" has no usable keys; nobody can log in")
		}
		files.remember(path, keys)
		return auth.New(c.AnyUser.Name, keys), files, warns, nil
	}

	var (
		users []auth.User
		warns []string
		read  = map[string][]auth.Key{} // each file once
	)
	for _, name := range sortedKeys(c.Users) {
		u := c.Users[name]
		au := auth.User{Name: name, Disabled: u.Disabled}
		if u.Expires != nil {
			au.Expires = *u.Expires
		}
		if c.canUsePassword(u) {
			h, err := auth.ParsePasswordHash(u.PasswordHash)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s: %w", key("users", name, "password_hash"), err)
			}
			au.Password = h
		}
		keysOn := c.Auth.HasMethod(auth.MethodPublicKey) // otherwise keys are not even read
		for i, line := range u.AuthorizedKeys {
			if !keysOn {
				break
			}
			ks, ws := auth.ParseAuthorizedKeys([]byte(line), key("users", name, "authorized_keys")+"["+strconv.Itoa(i+1)+"]")
			au.Keys = append(au.Keys, ks...)
			warns = append(warns, ws...)
		}
		if f := u.AuthorizedKeysFile; f != "" && keysOn {
			ks, ok := read[f]
			if !ok {
				var ws []string
				var err error
				ks, ws, err = o.readKeys(f, key("users", name, "authorized_keys_file"))
				if err != nil {
					return nil, nil, nil, fmt.Errorf("%s: %w", key("users", name, "authorized_keys_file"), err)
				}
				read[f] = ks
				files.remember(f, ks)
				warns = append(warns, ws...)
			}
			au.Keys = append(au.Keys, ks...)
		}
		for _, a := range u.AllowFrom {
			p, err := auth.ParsePrefix(a)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s: %w", key("users", name, "allow_from"), err)
			}
			au.AllowFrom = append(au.AllowFrom, p)
		}
		if len(au.Keys) == 0 && au.Password == nil && !u.Disabled {
			warns = append(warns, key("users", name)+": no usable keys, the user cannot log in")
		}
		users = append(users, au)
	}
	return auth.NewUsers(users), files, warns, nil
}

// remember records the keys of path if it is a pipe.
func (f KeyFiles) remember(path string, keys []auth.Key) {
	if fi, err := os.Stat(path); err == nil && fi.Mode()&fs.ModeNamedPipe != 0 {
		f[path] = keys
	}
}

// readKeys reads the authorized_keys file path; k names it in messages.
func (o AuthOptions) readKeys(path, k string) ([]auth.Key, []string, error) {
	if !o.Reload {
		return readAuthorizedKeys(path)
	}
	unused := func(err error) []string { return []string{fmt.Sprintf("%s: %v; its keys are not used", k, err)} }
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return nil, unused(err), nil
	case fi.Mode()&fs.ModeNamedPipe != 0:
		if keys, ok := o.Previous[path]; ok {
			return keys, []string{k + ": " + path + " is a pipe; keeping the keys read from it before"}, nil
		}
		return nil, unused(fmt.Errorf("%s is a pipe that was not read before", path)), nil
	case !fi.Mode().IsRegular():
		return nil, unused(fmt.Errorf("%s is not a regular file", path)), nil
	}
	if err := checkOwner(path, fi); err != nil {
		return nil, unused(err), nil
	}
	keys, warns, err := readAuthorizedKeys(path)
	if err != nil {
		return nil, append(warns, unused(err)...), nil
	}
	return keys, warns, nil
}

// usesKeys reports whether u has keys that may be used.
func (c *Config) usesKeys(u *User) bool {
	return (len(u.AuthorizedKeys) > 0 || u.AuthorizedKeysFile != "") && c.Auth.HasMethod(auth.MethodPublicKey)
}

// canUsePassword reports whether u has a password that may be used.
func (c *Config) canUsePassword(u *User) bool {
	return u.PasswordHash != "" && c.Auth.HasMethod(auth.MethodPassword)
}

// Bans builds the ban table, or returns nil when bans are off. Call after
// Validate.
func (c *Config) Bans() *auth.BanTable {
	b := c.Auth.Ban
	if b.AfterFailures == 0 {
		return nil
	}
	exempt := make([]netip.Prefix, 0, len(b.Exempt))
	for _, e := range b.Exempt {
		if p, err := auth.ParsePrefix(e); err == nil {
			exempt = append(exempt, p)
		}
	}
	return auth.NewBanTable(auth.BanOptions{
		AfterFailures: b.AfterFailures,
		Within:        time.Duration(b.Within),
		Duration:      time.Duration(b.Duration),
		Exempt:        exempt,
	})
}

// Grants returns the mounts user may access. In zero-config mode every user
// gets full access to every mount (read-only mounts stay read-only).
func (c *Config) Grants(user string) []vfs.Grant {
	if c.AnyUser != nil {
		gs := make([]vfs.Grant, 0, len(c.Mounts))
		for _, name := range sortedKeys(c.Mounts) {
			gs = append(gs, vfs.Grant{Mount: name, Perm: vfs.PermAll})
		}
		return gs
	}
	u := c.Users[user]
	if u == nil {
		return nil
	}
	gs := make([]vfs.Grant, 0, len(u.Access))
	for _, mount := range sortedKeys(u.Access) {
		p, err := vfs.ParsePerm(u.Access[mount])
		if err != nil {
			continue // rejected by Validate
		}
		gs = append(gs, vfs.Grant{Mount: mount, Perm: p})
	}
	return gs
}

// Encode returns the configuration as TOML, with every default spelled out
// and the users of included files merged in (so include is left out).
func (c *Config) Encode() ([]byte, error) {
	var b bytes.Buffer
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	out := *c
	out.Include = nil
	if err := enc.Encode(&out); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
