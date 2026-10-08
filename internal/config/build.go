// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"io/fs"
	"slices"
	"strconv"

	"github.com/BurntSushi/toml"

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
	return vfs.MountOptions{
		OnConflict:        policy,
		RenameTemplate:    o.RenameTemplate,
		MaxRenameAttempts: o.MaxRenameAttempts,
		CompoundExts:      slices.Clone(o.CompoundExtensions),
		SetstatMode:       mode,
		Umask:             fs.FileMode(o.Umask),
	}, nil
}

// Authenticator builds the authenticator, reading authorized_keys files.
// Key lines that cannot be used are skipped and returned as warnings. Call
// after Validate.
func (c *Config) Authenticator() (*auth.Authenticator, []string, error) {
	if c.AnyUser != nil {
		keys, warns, err := readAuthorizedKeys(c.AnyUser.AuthorizedKeysFile)
		if err != nil {
			return nil, nil, err
		}
		if len(keys) == 0 {
			return nil, warns, noKeysError(c.AnyUser.AuthorizedKeysFile)
		}
		return auth.New(c.AnyUser.Name, keys), warns, nil
	}

	var (
		users []auth.User
		warns []string
		files = map[string][]auth.Key{}
	)
	for _, name := range sortedKeys(c.Users) {
		u := c.Users[name]
		au := auth.User{Name: name, Disabled: u.Disabled}
		if u.Expires != nil {
			au.Expires = *u.Expires
		}
		for i, line := range u.AuthorizedKeys {
			ks, ws := auth.ParseAuthorizedKeys([]byte(line), key("users", name, "authorized_keys")+"["+strconv.Itoa(i+1)+"]")
			au.Keys = append(au.Keys, ks...)
			warns = append(warns, ws...)
		}
		if f := u.AuthorizedKeysFile; f != "" {
			ks, ok := files[f]
			if !ok {
				var ws []string
				var err error
				ks, ws, err = readAuthorizedKeys(f)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: %w", key("users", name, "authorized_keys_file"), err)
				}
				files[f] = ks
				warns = append(warns, ws...)
			}
			au.Keys = append(au.Keys, ks...)
		}
		for _, a := range u.AllowFrom {
			p, err := auth.ParsePrefix(a)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", key("users", name, "allow_from"), err)
			}
			au.AllowFrom = append(au.AllowFrom, p)
		}
		if len(au.Keys) == 0 && !u.Disabled {
			warns = append(warns, key("users", name)+": no usable keys, the user cannot log in")
		}
		users = append(users, au)
	}
	return auth.NewUsers(users), warns, nil
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

// Encode returns the configuration as TOML, with every default spelled out.
func (c *Config) Encode() ([]byte, error) {
	var b bytes.Buffer
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
