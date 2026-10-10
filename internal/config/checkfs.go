// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// CheckFS checks the environment the configuration refers to: mount
// directories, host keys, authorized_keys files and the permissions of every
// file gosftpd trusts (ROADMAP §6.5). Call it after Validate.
func (c *Config) CheckFS() (warnings []string, err error) {
	warnings, _, err = c.checkFS(false, nil)
	return warnings, err
}

// LiveMount is a mount that connections of an earlier configuration still
// use (see CheckFSReload).
type LiveMount struct {
	Name, Path string
	ReadOnly   bool
}

// CheckFSReload is CheckFS for a configuration reload. Host keys and
// authorized_keys files are not checked here: on reload a broken one must
// not block the rest (ADR 0005, ADR 0008), so their readers check them. A mount that fails its checks is
// a warning and is returned in unavailable, so that one mount (a disk that
// is not mounted, say) does not block the rest of the reload; its users
// find it unavailable. Trusted files are also checked against live: the
// mounts that open connections still use, since they may still write them.
func (c *Config) CheckFSReload(live []LiveMount) (warnings, unavailable []string, err error) {
	return c.checkFS(true, live)
}

func (c *Config) checkFS(reload bool, live []LiveMount) (warnings, unavailable []string, err error) {
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
	unavailable = c.checkMounts(p, reload)
	if !reload {
		c.checkHostKeys(p)
		c.checkUsers(p)
	}
	c.checkAudit(p)
	c.checkTrusted(p, live)
	warnings, err = p.result()
	return warnings, unavailable, err
}

// checkMounts checks every mount directory. With reload, a mount's errors
// are warnings and the mount is returned as unavailable.
func (c *Config) checkMounts(p *problems, reload bool) (unavailable []string) {
	for _, name := range sortedKeys(c.Mounts) {
		mp := &problems{}
		c.checkMount(mp, name)
		p.warns = append(p.warns, mp.warns...)
		switch {
		case len(mp.errs) == 0:
		case !reload:
			p.errs = append(p.errs, mp.errs...)
		default:
			for _, err := range mp.errs {
				p.warns = append(p.warns, err.Error()+"; the mount is unavailable until this is fixed")
			}
			unavailable = append(unavailable, name)
		}
	}
	return unavailable
}

func (c *Config) checkMount(p *problems, name string) {
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
		return
	case errors.Is(err, fs.ErrNotExist):
		p.errorf(k, "%s does not exist (set create = true to create it)", dir)
		return
	case err != nil:
		p.errorf(k, "%v", err)
		return
	case !fi.IsDir():
		p.errorf(k, "%s is not a directory", dir)
		return
	}
	if m.RequireMountpoint {
		checkMountpoint(p, key("mounts", name, "require_mountpoint"), dir, fi)
	}
}

// checkTrusted refuses files gosftpd trusts inside a mount that clients can
// write to: a client could change the configuration, add a key or a user,
// or rewrite the audit log, and a reload would apply it. Host keys and
// configuration files, which can hold password hashes, must not be in any
// mount, since clients could read them. live are mounts of earlier
// configurations that open connections still use.
func (c *Config) checkTrusted(p *problems, live []LiveMount) {
	type trusted struct {
		path, what string
		secret     bool // refused in read-only mounts too
		private    bool // warned about in read-only mounts
	}
	var files []trusted
	for _, f := range c.Files {
		files = append(files, trusted{f, "the configuration file", true, false})
	}
	for _, f := range c.Server.HostKeys {
		files = append(files, trusted{f, "the host key", true, false})
		for _, g := range []string{f + ".next", f + ".old"} {
			if _, err := os.Lstat(g); err == nil {
				files = append(files, trusted{g, "a host key", true, false})
			}
		}
		if c.Server.HostCertificates {
			for _, g := range []string{f + "-cert.pub", f + ".next-cert.pub"} {
				if _, err := os.Lstat(g); err == nil {
					files = append(files, trusted{g, "a host certificate", false, false})
				}
			}
		}
	}
	if c.AnyUser != nil {
		files = append(files, trusted{c.AnyUser.AuthorizedKeysFile, "the authorized_keys file", false, false})
	}
	for _, name := range sortedKeys(c.Users) {
		if f := c.Users[name].AuthorizedKeysFile; f != "" {
			files = append(files, trusted{f, "the authorized_keys file of " + name, false, false})
		}
	}
	if f := c.Auth.TrustedUserCAKeysFile; f != "" {
		files = append(files, trusted{f, "the trusted CA keys", false, false})
	}
	if f := c.Auth.RevokedKeysFile; f != "" {
		files = append(files, trusted{f, "the revoked keys", false, false})
	}
	if out := c.Audit.Output; out != "" && out != "stdout" {
		files = append(files, trusted{out, "the audit log", false, true})
	}
	type mount struct {
		key, path string
		readOnly  bool
	}
	var mounts []mount
	for _, name := range sortedKeys(c.Mounts) {
		k := key("mounts", name, "path")
		if c.AnyUser != nil {
			k = "--dir " + name
		}
		mounts = append(mounts, mount{k, c.Mounts[name].Path, c.Mounts[name].ReadOnly})
	}
	for _, l := range live {
		same := slices.ContainsFunc(mounts, func(m mount) bool { return m.path == l.Path && m.readOnly == l.ReadOnly })
		if !same {
			mounts = append(mounts, mount{"mount " + strconv.Quote(l.Name) + " of open connections", l.Path, l.ReadOnly})
		}
	}
	mi := readMountInfo()
	for _, m := range mounts {
		for _, f := range files {
			if !insideMount(f.path, m.path, mi) {
				continue
			}
			switch {
			case !m.readOnly:
				p.errorf(m.key, "covers %s (%s): clients could change it; serve another directory", f.what, f.path)
			case f.secret:
				p.errorf(m.key, "covers %s (%s): clients could read it; serve another directory", f.what, f.path)
			case f.private:
				p.warnf(m.key, "covers %s (%s): clients can read it", f.what, f.path)
			}
		}
	}
}

// insideMount reports whether file lies in the directory of a mount: by
// path, after resolving symlinks, or by where both lie on their filesystem,
// since a bind mount shows one directory at two paths (Linux).
func insideMount(file, mountPath string, mi mountInfo) bool {
	if vfs.PathsOverlap(file, mountPath) {
		return true
	}
	dir := mountPath
	if filepath.Base(dir) == vfs.UserPlaceholder {
		dir = filepath.Dir(dir)
	}
	rf, err := filepath.EvalSymlinks(file)
	if err != nil {
		rf, err = filepath.EvalSymlinks(filepath.Dir(file)) // a file still to be created
		rf = filepath.Join(rf, filepath.Base(file))
	}
	rd, derr := filepath.EvalSymlinks(dir)
	if err != nil || derr != nil {
		return false
	}
	if vfs.PathsOverlap(rf, rd) {
		return true
	}
	fdev, frel, fok := mi.locate(rf)
	ddev, drel, dok := mi.locate(rd)
	return fok && dok && fdev == ddev && vfs.PathsOverlap(frel, drel)
}

// mountInfo lists the mounts of the process: device, the directory of the
// filesystem that is mounted, and where.
type mountInfo []struct{ dev, root, point string }

// locate returns the filesystem path lies on and its path within it.
func (mi mountInfo) locate(path string) (dev, rel string, ok bool) {
	best := -1
	for _, m := range mi {
		var rest string
		switch {
		case m.point == "/":
			rest = path
		case path == m.point || strings.HasPrefix(path, m.point+"/"):
			rest = path[len(m.point):]
		default:
			continue
		}
		if len(m.point) > best {
			best, dev, rel = len(m.point), m.dev, filepath.Join(m.root, rest)
		}
	}
	return dev, rel, best >= 0
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
		c.checkHostKey(p, path, false)
		// Next and previous keys of a rotation (ADR 0008).
		for _, f := range []string{path + ".next", path + ".old"} {
			if _, err := os.Lstat(f); err == nil {
				c.checkHostKey(p, f, true)
			}
		}
	}
}

func (c *Config) checkHostKey(p *problems, path string, rotation bool) {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && c.Server.HostKeyAutoGenerate && !rotation:
		if _, err := os.Stat(filepath.Dir(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			p.errorf("server.host_keys", "%v", err)
		}
	case errors.Is(err, fs.ErrNotExist) && !rotation:
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

func (c *Config) checkUsers(p *problems) {
	files := map[string]string{} // path -> key, checked once
	for _, name := range sortedKeys(c.Users) {
		if f := c.Users[name].AuthorizedKeysFile; f != "" && c.Auth.HasMethod(auth.MethodPublicKey) {
			if _, ok := files[f]; !ok {
				files[f] = key("users", name, "authorized_keys_file")
			}
		}
	}
	if c.AnyUser != nil && c.AnyUser.AuthorizedKeysFile != "" {
		files[c.AnyUser.AuthorizedKeysFile] = "--authorized-keys"
	}
	if c.Auth.HasMethod(auth.MethodPublicKey) {
		for f, k := range map[string]string{
			c.Auth.TrustedUserCAKeysFile: "auth.trusted_user_ca_keys_file",
			c.Auth.RevokedKeysFile:       "auth.revoked_keys_file",
		} {
			if _, ok := files[f]; f != "" && !ok {
				files[f] = k
			}
		}
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
		}
		// Not parsed here: Authenticator reads each file once, which also
		// keeps a pipe (--authorized-keys <(...)) usable.
	}
}

func (c *Config) checkAudit(p *problems) {
	out := c.Audit.Output
	if out == "stdout" || out == "" {
		return
	}
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		p.errorf("audit.output", "%s is a directory", out)
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
