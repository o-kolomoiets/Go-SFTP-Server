// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// CheckFS checks the environment the configuration refers to: mount
// directories, host keys, authorized_keys files and the permissions of every
// file gosftpd trusts (ROADMAP §6.5). Call it after Validate.
func (c *Config) CheckFS() (warnings []string, err error) {
	p := &problems{}
	for _, f := range c.Files {
		fi, err := os.Stat(f)
		if err != nil {
			p.errorf(f, "%v", err)
			continue
		}
		if err := checkOwner(f, fi); err != nil {
			p.errs = append(p.errs, err)
		}
		if worldReadable(fi) {
			p.warnf(f, "readable by all users; consider chmod o-r")
		}
	}
	c.checkMounts(p)
	c.checkHostKeys(p)
	c.checkUsers(p)
	c.checkAudit(p)
	return p.result()
}

func (c *Config) checkMounts(p *problems) {
	for _, name := range sortedKeys(c.Mounts) {
		m := c.Mounts[name]
		k := key("mounts", name, "path")
		dir := m.Path
		if filepath.Base(dir) == vfs.UserPlaceholder {
			dir = filepath.Dir(dir)
		}
		fi, err := os.Stat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist) && m.Create:
			if m.RequireMountpoint {
				p.errorf(k, "%s does not exist, so it cannot be a mount point (require_mountpoint = true)", dir)
			}
			continue
		case errors.Is(err, fs.ErrNotExist):
			p.errorf(k, "%s does not exist (set create = true to create it)", dir)
			continue
		case err != nil:
			p.errorf(k, "%v", err)
			continue
		case !fi.IsDir():
			p.errorf(k, "%s is not a directory", dir)
			continue
		}
		if m.RequireMountpoint {
			checkMountpoint(p, key("mounts", name, "require_mountpoint"), dir, fi)
		}
	}
}

// checkMountpoint fails if dir is on the same filesystem as its parent:
// the disk meant to be mounted there is missing (ROADMAP §6.1 item 9).
func checkMountpoint(p *problems, k, dir string, fi fs.FileInfo) {
	parent, err := os.Stat(filepath.Dir(dir))
	if err != nil {
		p.errorf(k, "%v", err)
		return
	}
	same, known := sameDevice(fi, parent)
	switch {
	case !known:
		p.warnf(k, "cannot be checked on %s", runtime.GOOS)
	case same:
		p.errorf(k, "%s is not a mount point (it is on the same filesystem as its parent); is the disk mounted?", dir)
	}
}

func (c *Config) checkHostKeys(p *problems) {
	for _, path := range c.Server.HostKeys {
		fi, err := os.Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && c.Server.HostKeyAutoGenerate:
			if _, err := os.Stat(filepath.Dir(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				p.errorf("server.host_keys", "%v", err)
			}
		case errors.Is(err, fs.ErrNotExist):
			p.errorf("server.host_keys", "%s does not exist (create it with gosftpd hostkey generate --out %s, or set host_key_auto_generate = true)", path, path)
		case err != nil:
			p.errorf("server.host_keys", "%v", err)
		case runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0:
			p.errorf("server.host_keys", "%s: permissions %04o are too open; fix with: chmod 600 %s", path, fi.Mode().Perm(), path)
		default:
			if err := checkOwner(path, fi); err != nil {
				p.errs = append(p.errs, err)
			}
		}
	}
}

func (c *Config) checkUsers(p *problems) {
	files := map[string]string{} // path -> key, checked once
	for _, name := range sortedKeys(c.Users) {
		if f := c.Users[name].AuthorizedKeysFile; f != "" {
			if _, ok := files[f]; !ok {
				files[f] = key("users", name, "authorized_keys_file")
			}
		}
	}
	if c.AnyUser != nil && c.AnyUser.AuthorizedKeysFile != "" {
		files[c.AnyUser.AuthorizedKeysFile] = "--authorized-keys"
	}
	for _, f := range sortedKeys(files) {
		k := files[f]
		fi, err := os.Stat(f)
		if err != nil {
			p.errorf(k, "%v", err)
			continue
		}
		if err := checkOwner(f, fi); err != nil {
			p.errorf(k, "%v", err)
			continue
		}
		_, warns, err := readAuthorizedKeys(f)
		if err != nil {
			p.errorf(k, "%v", err)
		}
		for _, w := range warns {
			p.warnf(k, "skipping %s", w)
		}
	}
}

func (c *Config) checkAudit(p *problems) {
	out := c.Audit.Output
	if out == "stdout" || out == "" {
		return
	}
	if fi, err := os.Stat(out); err == nil && !fi.Mode().IsRegular() {
		p.errorf("audit.output", "%s is not a regular file", out)
		return
	}
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || !fi.IsDir() {
		p.errorf("audit.output", "directory %s does not exist", filepath.Dir(out))
	}
}

// readAuthorizedKeys parses an authorized_keys file.
func readAuthorizedKeys(path string) ([]auth.Key, []string, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, nil, err
	}
	keys, warns := auth.ParseAuthorizedKeys(data, path)
	return keys, warns, nil
}

// errNoKeys is returned when an authorized_keys file has no usable key.
var errNoKeys = errors.New("contains no usable keys")

func noKeysError(path string) error { return fmt.Errorf("%s %w", path, errNoKeys) }
