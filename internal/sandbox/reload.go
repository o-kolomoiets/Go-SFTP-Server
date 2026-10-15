// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// Ruleset is the ruleset applied at start, kept for reloads. Its rules are
// not computed again, since dedication may answer differently by then;
// instead each use of a new configuration is checked against them
// (ADR 0011, Reload). A nil *Ruleset, where Landlock is not applied,
// covers everything.
type Ruleset struct {
	rules    []Rule
	fs       FS
	linux    bool
	resolver []string // the name-resolution files that got a rule
	// audit is the audit file of the start when it got no rule: a link
	// to a pipe, or one that resolves under /dev or /proc (/dev/null, a
	// terminal behind /dev/stdout), as a path under /dev does.
	audit string
}

func newRuleset(rules []Rule, in Input) *Ruleset {
	rs := &Ruleset{rules: slices.Clone(rules), fs: in.FS, linux: in.Linux}
	for _, f := range resolverFiles {
		if rs.grants(f) != 0 {
			rs.resolver = append(rs.resolver, f)
		}
	}
	if out := in.Config.Audit.Output; out != "" && out != "stdout" {
		// Covers takes a target under /dev or /proc for covered.
		if r, err := rs.fs.EvalSymlinks(out); err != nil || rs.special(filepath.Clean(r)) || !rs.Covers(out, WriteFile) {
			rs.audit = filepath.Clean(out)
		}
	}
	return rs
}

// Rules returns the rules applied at start.
func (rs *Ruleset) Rules() []Rule {
	if rs == nil {
		return nil
	}
	return slices.Clone(rs.rules)
}

// Create says what stands for a used path that does not exist yet.
type Create int

const (
	// Skip leaves a missing path out: the next reload checks it once it
	// exists.
	Skip Create = iota
	// CreateFile checks the directory, where the file will be created
	// (the audit file).
	CreateFile
	// CreateDir checks the nearest existing ancestor, below which the
	// directory will be created (a mount with create = true).
	CreateDir
)

// Use is a file or directory that a configuration uses, with the rights
// the use needs.
type Use struct {
	// Key is the configuration key that restart_required names.
	Key    string
	Path   string
	Need   Rights
	Create Create
}

// Finding is a use that the ruleset does not cover.
type Finding struct {
	Use
	// Checked is what was checked: Use.Path, or for a path still to be
	// created, the directory that stands for it.
	Checked string
	// Have are the rights the ruleset grants there, 0 for a path that
	// exists but cannot be resolved.
	Have Rights
}

// Uses lists the uses of a configuration: each include file and each
// include pattern's leading directory, each trusted file, the audit file
// (its directory while the file is missing), each mount directory (with
// create = true its nearest existing ancestor while it is missing). The
// main configuration file is not listed: a reload reads it first, and an
// error reading it carries Hint when Covers says so.
func Uses(c *config.Config) []Use {
	var uses []Use
	if c.File != "" {
		for _, f := range c.Files {
			if f != c.File {
				uses = append(uses, Use{Key: keyInclude, Path: f, Need: ReadFile})
			}
		}
		for _, pattern := range c.Include {
			uses = append(uses, Use{Key: keyInclude, Path: parseInclude(filepath.Dir(c.File), pattern).lead, Need: ReadDir})
		}
	}
	p := &planner{c: c}
	for _, t := range p.trustedFiles(true) {
		uses = append(uses, Use{Key: t.key, Path: t.path, Need: ReadFile})
	}
	if out := c.Audit.Output; out != "" && out != "stdout" {
		uses = append(uses, Use{Key: keyAudit, Path: out, Need: WriteFile, Create: CreateFile})
	}
	for _, name := range sortedKeys(c.Mounts) {
		uses = append(uses, MountUse(name, c.Mounts[name]))
	}
	return uses
}

// MountUse is the use of mount name's directory, for a {user} mount the
// parent of {user}, with the rights of ADR 0011's table. A reload checks
// it again with the running read_only and create when the new ones are
// not covered.
func MountUse(name string, m *config.Mount) Use {
	dir := filepath.Clean(m.Path)
	home := filepath.Base(dir) == vfs.UserPlaceholder
	if home {
		dir = filepath.Dir(dir)
	}
	u := Use{Key: toml.Key{"mounts", name, "path"}.String(), Path: dir, Need: MountRW}
	if m.ReadOnly {
		u.Need = MountRO
		if home && m.Create {
			u.Need |= MakeDir
		}
	}
	if m.Create {
		u.Create = CreateDir
	}
	return u
}

// Check returns the uses that the ruleset does not cover. A use is covered
// when the resolved file's (device, inode) is that of a file rule,
// wherever the file now lies (Landlock binds a file rule to the inode), or
// when a directory rule's path is the resolved path or an ancestor of it
// and still has its (device, inode); in both cases with the rights the
// use needs. A path that does not exist (a dangling symlink too) is left
// out, see Create; one that exists but cannot be resolved is not covered.
// Paths under /dev and /proc never had rules and are left out.
func (rs *Ruleset) Check(uses []Use) []Finding {
	if rs == nil {
		return nil
	}
	var findings []Finding
	for _, u := range uses {
		path, need, ok := rs.stand(u)
		if !ok {
			continue
		}
		have, err := rs.rights(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// A dangling symlink: what reads it reports that, and a
			// restart would not help.
		case err != nil:
			findings = append(findings, Finding{Use: u, Checked: path})
		case have&need != need:
			findings = append(findings, Finding{Use: u, Checked: path, Have: have})
		}
	}
	return findings
}

// stand returns the path checked for u and the rights it needs there; ok
// is false when u is left out.
func (rs *Ruleset) stand(u Use) (path string, need Rights, ok bool) {
	path, need = filepath.Clean(u.Path), u.Need
	if rs.special(path) {
		return "", 0, false
	}
	if _, err := rs.fs.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return path, need, true
	}
	switch u.Create {
	case Skip:
	case CreateFile:
		path, need = filepath.Dir(path), MakeReg|WriteFile
		if _, err := rs.fs.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return "", 0, false // the reload's own checks refuse it
		}
		return path, need, true
	case CreateDir:
		for {
			parent := filepath.Dir(path)
			if parent == path {
				return "", 0, false
			}
			path = parent
			if _, err := rs.fs.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				return path, need | MakeDir, true
			}
		}
	}
	return "", 0, false
}

// rights returns what the ruleset grants on path, or why path cannot be
// resolved.
func (rs *Ruleset) rights(path string) (Rights, error) {
	r, err := rs.fs.EvalSymlinks(path)
	if err != nil {
		return 0, err
	}
	r = filepath.Clean(r)
	if rs.special(r) {
		return ^Rights(0), nil
	}
	info, err := rs.fs.Stat(r)
	if err != nil {
		return 0, err
	}
	var have Rights
	for _, rule := range rs.rules {
		switch {
		case !rule.Dir:
			if rule.Dev == info.Dev && rule.Ino == info.Ino {
				have |= rule.Rights
			}
		case beneath(r, rule.Path):
			if d, err := rs.fs.Stat(rule.Path); err == nil && d.Dev == rule.Dev && d.Ino == rule.Ino {
				have |= rule.Rights
			}
		}
	}
	return have, nil
}

// grants returns the rights on path, 0 when it cannot be resolved.
func (rs *Ruleset) grants(path string) Rights {
	have, _ := rs.rights(path)
	return have
}

// Covers reports whether the ruleset gives need on path. A permission
// error on a path that it does not cover carries Hint.
func (rs *Ruleset) Covers(path string, need Rights) bool {
	if rs == nil {
		return true
	}
	if rs.special(filepath.Clean(path)) {
		return true
	}
	have, err := rs.rights(path)
	return err == nil && have&need == need
}

// ResolverWarnings names each name-resolution file that had a rule at
// start but is no longer covered: replaced by rename (NetworkManager or
// dhclient rewriting /etc/resolv.conf, sed -i on /etc/hosts), Go's resolver
// cannot read it and silently asks 127.0.0.1:53. A systemd-resolved stub
// replaced inside its /run directory stays covered. The caller logs each
// warning under the message "landlock", as Start logs the start warnings.
func (rs *Ruleset) ResolverWarnings() []string {
	if rs == nil {
		return nil
	}
	var warns []string
	for _, f := range rs.resolver {
		if _, err := rs.fs.Lstat(f); err == nil && !rs.Covers(f, ReadFile) {
			warns = append(warns, f+" was replaced after start; webhooks resolve names again after a restart")
		}
	}
	return warns
}

// Explain adds Hint to err when err holds a permission error on a path
// that the ruleset does not cover with need: read_dir for a directory, and
// make_reg on the directory of a path that does not exist yet, where it
// would be created. Any other error, and every error without a ruleset,
// comes back as it is.
func (rs *Ruleset) Explain(err error, need Rights) error {
	if rs == nil || err == nil {
		return err
	}
	for _, pe := range pathErrors(err, nil) {
		if !errors.Is(pe.Err, fs.ErrPermission) || !filepath.IsAbs(pe.Path) {
			continue
		}
		path, want := filepath.Clean(pe.Path), need
		switch info, serr := rs.fs.Stat(path); {
		case errors.Is(serr, fs.ErrNotExist):
			path, want = filepath.Dir(path), MakeReg
		case serr == nil && info.IsDir():
			want = ReadDir
		}
		if !rs.Covers(path, want) {
			return &hintError{err}
		}
	}
	return err
}

// pathErrors collects the *fs.PathError values in err's tree, those of
// joined errors too.
func pathErrors(err error, found []*fs.PathError) []*fs.PathError {
	switch e := err.(type) { //nolint:errorlint // it walks the tree itself, joined errors too
	case nil:
		return found
	case *fs.PathError:
		return append(found, e)
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			found = pathErrors(inner, found)
		}
		return found
	}
	return pathErrors(errors.Unwrap(err), found)
}

// hintError is an error that follows from the ruleset applied at start:
// a restart cures it.
type hintError struct{ err error }

func (e *hintError) Error() string { return e.err.Error() + " (" + Hint + ")" }

func (e *hintError) Unwrap() error { return e.err }

// KeepsOpen reports whether a file that gosftpd opened at start must stay
// open, since opening it again would be refused: it lies under /dev or
// /proc, which never get a rule (audit.output on /dev/stderr), or it is
// the audit file of the start, which got no rule (a link to stderr when
// that is a pipe, or to /dev/null). Without Landlock nothing has to.
func (rs *Ruleset) KeepsOpen(path string) bool {
	if rs == nil {
		return false
	}
	path = filepath.Clean(path)
	return rs.special(path) || rs.audit != "" && path == rs.audit
}

func (rs *Ruleset) special(path string) bool {
	return rs.linux && (beneath(path, "/dev") || beneath(path, "/proc"))
}
