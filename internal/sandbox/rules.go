// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// FS is what Compute and Ruleset read of the file system; tests give them
// one in memory.
type FS interface {
	// Lstat describes path without following a final symlink.
	Lstat(path string) (Info, error)
	// Stat describes path, following symlinks.
	Stat(path string) (Info, error)
	// ReadDir returns the names in a directory.
	ReadDir(path string) ([]string, error)
	// EvalSymlinks returns path with every symlink resolved.
	EvalSymlinks(path string) (string, error)
}

// Info is what the rules need to know of a file.
type Info struct {
	Dev, Ino uint64
	Mode     fs.FileMode // the type bits
}

// IsDir reports whether the file is a directory.
func (i Info) IsDir() bool { return i.Mode.IsDir() }

func (i Info) same(o Info) bool { return i.Dev == o.Dev && i.Ino == o.Ino }

// Input is what Compute computes the rules from.
type Input struct {
	// Config is the validated configuration.
	Config *config.Config
	// Mounts are the open mount directories. With nil, as for config
	// validate, a mount directory is found by its path and one that
	// does not exist yet gets no rule.
	Mounts []MountDir
	// Ephemeral is the directory of serve --ephemeral
	// (Config.EphemeralDir) as gosftpd holds it open. With nil it is
	// found by its path.
	Ephemeral *MountDir
	FS        FS
	// Home is the home directory of the user running gosftpd, "" if none.
	Home string
	// Linux adds the rows of /proc/self and name resolution, and keeps
	// paths under /dev and /proc without rules.
	Linux bool
	// ProcSelfFD is /proc/self held open (O_PATH): a rule added by path
	// is lost when the kernel reclaims the dentry. -1 adds it by path.
	ProcSelfFD int
	// CoverDir is where a -cover build writes its counters, "" otherwise.
	CoverDir string
}

// Rule is a Landlock rule: rights on a file, or beneath a directory.
type Rule struct {
	// Path is where the rule is, with every symlink resolved. Open is
	// what is opened to add it: Path, or a descriptor held open
	// (/proc/self/fd/N) for a mount directory and /proc/self.
	Path, Open string
	Rights     Rights
	Dir        bool
	// Dev and Ino identify Path when the rule was computed.
	Dev, Ino uint64
	// For lists what needs the rule: configuration keys, "configuration",
	// "include", "/proc/self", "name resolution", "coverage",
	// "--ephemeral".
	For []string
}

// Plan is a ruleset computed from a configuration, before it is applied.
type Plan struct {
	Rules []Rule
	// Warnings name each key whose file got a rule of its own, and why:
	// a rename, or a re-pointed link, takes the file away until a
	// restart. They also name an include directory that does not exist.
	Warnings []string
}

// RootError reports a rule that would have to be placed on the root
// directory, which would open the whole file system: a mount, or an
// include pattern's leading directory, at /.
type RootError struct{ Key string }

func (e *RootError) Error() string { return e.Key + ": " + reasonRoot }

// Keys of the rows that have none in the configuration.
const (
	keyConfig     = "configuration"
	keyInclude    = "include"
	keyAudit      = "audit.output"
	keyHostKeys   = "server.host_keys"
	keyProcSelf   = "/proc/self"
	keyResolver   = "name resolution"
	keyCoverage   = "coverage"
	keyEphemeral  = "--ephemeral"
	maxNamedShown = 3
)

// resolverFiles are the files Go's resolver reads for webhooks.
var resolverFiles = []string{"/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf"}

// auditRotationWarning is the start warning (and config validate's) for an
// audit file that gets a rule on the file only.
const auditRotationWarning = "rotation by rename (logrotate's create, as in docs/audit-log.md) makes the audit log unwritable until a restart; with on_error = fail-closed every new connection is refused; use copytruncate or a directory of its own"

// Compute returns the rules for in, with the start warnings (ADR 0011,
// Rules). A rule that would have to be placed on / is a *RootError; any
// other error fails the start. A directory that cannot be listed is not
// an error: it is not dedicated.
func Compute(in Input) (Plan, error) {
	p := newPlanner(in)
	for _, row := range []func() error{p.mountRules, p.ephemeralRule, p.configRules, p.includeRules, p.trustedRules, p.auditRules} {
		if err := row(); err != nil {
			return Plan{}, err
		}
	}
	if in.Linux {
		if err := p.procSelfRule(); err != nil {
			return Plan{}, err
		}
		p.resolverRules()
	}
	p.missingIncludes()
	p.coverageRule()
	return Plan{Rules: dedupe(p.rules), Warnings: p.warnings()}, nil
}

// planner computes one Plan.
type planner struct {
	in    Input
	fs    FS
	c     *config.Config
	named map[string]bool     // the named entries, by path
	byDir map[string][]string // the base names of named files, by directory
	incs  []include
	// verdicts memoizes dedication by directory; visiting holds the
	// resolved directories being decided, against symlink loops.
	verdicts map[string]verdict
	visiting map[string]bool
	rules    []Rule
	missing  []string // include directories that do not exist
	notes    []*note
}

// include is an include pattern, split into the directory it is relative
// to and the components that are matched below it.
type include struct {
	base  string
	globs []string
	lead  string // the leading directory: base and the globs without * ? [
}

// verdict is whether a directory is dedicated to gosftpd and, if not, why:
// a phrase that follows the directory, such as "holds a, b and c".
type verdict struct {
	dedicated bool
	why       string
}

// note is a start warning in the making: files of one key that got rules
// of their own.
type note struct {
	key, dir, why string
	files         []string
	text          string // a finished warning instead
}

func newPlanner(in Input) *planner {
	p := &planner{
		in: in, fs: in.FS, c: in.Config,
		named: map[string]bool{}, byDir: map[string][]string{},
		verdicts: map[string]verdict{}, visiting: map[string]bool{},
	}
	for _, t := range p.namedFiles() {
		f := filepath.Clean(t.path)
		if !p.named[f] {
			p.named[f] = true
			p.byDir[filepath.Dir(f)] = append(p.byDir[filepath.Dir(f)], filepath.Base(f))
		}
	}
	if c := p.c; c.File != "" {
		dir := filepath.Dir(c.File)
		for _, pattern := range c.Include {
			p.incs = append(p.incs, parseInclude(dir, pattern))
		}
	}
	return p
}

type keyed struct{ key, path string }

// namedFiles are the files the configuration names or uses: the main file,
// the include matches and the files of trustedFiles and the audit row.
func (p *planner) namedFiles() []keyed {
	var files []keyed
	for _, f := range p.c.Files {
		files = append(files, keyed{keyConfig, f})
	}
	if p.c.File != "" {
		files = append(files, keyed{keyConfig, p.c.File})
	}
	files = append(files, p.trustedFiles(false)...)
	if out := p.c.Audit.Output; out != "" && out != "stdout" {
		files = append(files, keyed{keyAudit, out})
	}
	return files
}

// trustedFiles are the files of the trusted-files row, with their keys.
// With read, only those the configuration reads: authorized_keys files,
// the CA file and the revocation list with "publickey", certificates with
// server.host_certificates. Otherwise all of them, so that a reload that
// turns either on finds them covered.
func (p *planner) trustedFiles(read bool) []keyed {
	c := p.c
	keys := !read || c.Auth.HasMethod(auth.MethodPublicKey)
	var files []keyed
	for _, name := range sortedKeys(c.Users) {
		if f := c.Users[name].AuthorizedKeysFile; f != "" && keys {
			files = append(files, keyed{toml.Key{"users", name, "authorized_keys_file"}.String(), f})
		}
	}
	if c.AnyUser != nil && c.AnyUser.AuthorizedKeysFile != "" {
		files = append(files, keyed{"--authorized-keys", c.AnyUser.AuthorizedKeysFile})
	}
	if f := c.Auth.TrustedUserCAKeysFile; f != "" && keys {
		files = append(files, keyed{"auth.trusted_user_ca_keys_file", f})
	}
	if f := c.Auth.RevokedKeysFile; f != "" && keys {
		files = append(files, keyed{"auth.revoked_keys_file", f})
	}
	for _, k := range c.Server.HostKeys {
		files = append(files, keyed{keyHostKeys, k}, keyed{keyHostKeys, hostkey.Next(k)}, keyed{keyHostKeys, hostkey.Old(k)})
		if !read || c.Server.HostCertificates {
			files = append(files, keyed{keyHostKeys, hostkey.Cert(k)}, keyed{keyHostKeys, hostkey.Cert(hostkey.Next(k))})
		}
	}
	for i, h := range c.Hooks {
		if h != nil && h.Webhook != nil && h.Webhook.SecretFile != "" {
			files = append(files, keyed{"hooks[" + strconv.Itoa(i) + "].webhook.secret_file", h.Webhook.SecretFile})
		}
	}
	return files
}

// parseInclude splits an include pattern as config.Load matches it: a
// relative pattern below the main file's directory (which may itself hold
// * or [), an absolute one from the root.
func parseInclude(dir, pattern string) include {
	var inc include
	if filepath.IsAbs(pattern) {
		clean := filepath.Clean(pattern)
		vol := filepath.VolumeName(clean)
		inc.base = vol + string(filepath.Separator)
		inc.globs = strings.Split(strings.TrimPrefix(clean[len(vol):], string(filepath.Separator)), string(filepath.Separator))
	} else {
		inc.base = dir
		inc.globs = strings.Split(filepath.ToSlash(filepath.Clean(pattern)), "/")
	}
	inc.lead = inc.base
	for _, g := range inc.globs[:len(inc.globs)-1] {
		if strings.ContainsAny(g, "*?[") {
			break
		}
		inc.lead = filepath.Join(inc.lead, g)
	}
	return inc
}

// match reports whether path matches the first n components of inc below
// its base, all of them with n < 0.
func (inc include) match(path string, n int) bool {
	if n < 0 {
		n = len(inc.globs)
	}
	rel, ok := relative(path, inc.base)
	if !ok {
		return false
	}
	var parts []string
	if rel != "" {
		parts = strings.Split(rel, string(filepath.Separator))
	}
	if len(parts) != n {
		return false
	}
	for i, part := range parts {
		if ok, err := filepath.Match(inc.globs[i], part); err != nil || !ok {
			return false
		}
	}
	return true
}

// onPath reports whether dir is an include pattern's leading directory or
// lies on a pattern's path, as a directory its matches lie in.
func (p *planner) onPath(dir string) bool {
	for _, inc := range p.incs {
		for n := range len(inc.globs) {
			if inc.match(dir, n) {
				return true
			}
		}
	}
	return false
}

// matches returns the files loaded through inc.
func (p *planner) matches(inc include) []string {
	var files []string
	for _, f := range p.c.Files {
		if f != p.c.File && inc.match(f, -1) {
			files = append(files, f)
		}
	}
	return files
}

// holdsNamed reports whether a named entry lies below dir.
func (p *planner) holdsNamed(dir string) bool {
	for n := range p.named {
		if n != dir && beneath(n, dir) {
			return true
		}
	}
	return false
}

// k8sTimestamp is the directory a ConfigMap or Secret volume writes each
// version to: "..2006_01_02_15_04_05." and digits.
var k8sTimestamp = regexp.MustCompile(`^\.\.\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}\.\d+$`)

// namedEntry reports whether the entry name of dir is named: an entry of a
// Kubernetes volume, lost+found at the root of a file system, a named file
// or a name derived from one, or a dedicated subdirectory that an include
// pattern goes through or that holds a named entry. A subdirectory is
// never named for its name alone (config.toml.d): a rule on dir would
// cover whatever it holds.
func (p *planner) namedEntry(dir, name string) bool {
	full := filepath.Join(dir, name)
	switch {
	case name == "..data", name == "..data_tmp", k8sTimestamp.MatchString(name),
		name == "lost+found" && p.fsRoot(dir):
		return true
	}
	info, err := p.fs.Stat(full)
	if err != nil || !info.IsDir() {
		return p.named[full] || p.derived(dir, name)
	}
	if !p.onPath(full) && !p.holdsNamed(full) {
		return false
	}
	return p.dedicated(full).dedicated
}

// derived reports whether name in dir is derived from a named file there:
// it begins with the file's name (config.toml~, users.toml.bak, a host
// key's .pub), or is a temporary or editor file of such a name: vim's
// .NAME.sw?, user add's .NAME.*.tmp, gosftpd's own .NAME.tmp-* (of host
// keys, their .pub files and certificates), emacs's .#NAME and #NAME#.
func (p *planner) derived(dir, name string) bool {
	for _, b := range p.byDir[dir] {
		if strings.HasPrefix(name, b) || strings.HasPrefix(name, ".#"+b) ||
			strings.HasPrefix(name, "#"+b) && strings.HasSuffix(name, "#") && len(name) >= len(b)+2 {
			return true
		}
		// What follows ".NAME", where NAME may go on: ".pub", ".tmp-1".
		if rest, ok := strings.CutPrefix(name, "."+b); ok {
			swap := len(rest) >= 4 && rest[len(rest)-4:len(rest)-1] == ".sw"
			if swap || strings.HasSuffix(rest, ".tmp") || strings.Contains(rest, ".tmp-") {
				return true
			}
		}
	}
	return false
}

// never returns why dir is never dedicated: it is a .ssh directory, the
// root, or the home directory of the user running gosftpd (the packaged
// user's home is /).
func (p *planner) never(dir string) (string, bool) {
	switch {
	case filepath.Base(dir) == ".ssh":
		return "is a .ssh directory", true
	case isRoot(dir):
		return "is the root directory", true
	case p.isHome(dir):
		return "is the home directory of the user running gosftpd", true
	}
	return "", false
}

func (p *planner) isHome(dir string) bool {
	if p.in.Home == "" {
		return false
	}
	if filepath.Clean(p.in.Home) == dir {
		return true
	}
	h, err1 := p.fs.Stat(p.in.Home)
	d, err2 := p.fs.Stat(dir)
	return err1 == nil && err2 == nil && h.same(d)
}

// dedicated decides, once per directory, whether dir is dedicated to
// gosftpd: it can be listed and every entry in it is named. A directory
// that cannot be listed is not, and that is never an error.
func (p *planner) dedicated(dir string) verdict {
	if v, ok := p.verdicts[dir]; ok {
		return v
	}
	v := p.decide(dir)
	p.verdicts[dir] = v
	return v
}

func (p *planner) decide(dir string) verdict {
	if why, ok := p.never(dir); ok {
		return verdict{why: why}
	}
	resolved, err := p.fs.EvalSymlinks(dir)
	if err != nil {
		return verdict{why: "cannot be resolved"}
	}
	if p.visiting[resolved] {
		return verdict{why: "is in a symlink loop"}
	}
	p.visiting[resolved] = true
	defer delete(p.visiting, resolved)
	names, err := p.fs.ReadDir(dir)
	if err != nil {
		return verdict{why: "cannot be listed"}
	}
	slices.Sort(names)
	var unnamed []string
	for _, name := range names {
		if !p.namedEntry(dir, name) {
			unnamed = append(unnamed, name)
		}
	}
	if len(unnamed) == 0 {
		return verdict{dedicated: true}
	}
	return verdict{why: "holds " + listShown(unnamed)}
}

// auditDedicated is the audit row's stricter test: every entry in dir is
// the audit file or a rotated copy (a name beginning with the file's name,
// or with its name up to the last dot, as logrotate's extension writes
// it), a subdirectory holding only such names (olddir), or lost+found at
// the root of a file system. Configuration and key files never share a
// directory that gets write rights.
func (p *planner) auditDedicated(dir, file string) verdict {
	if why, ok := p.never(dir); ok {
		return verdict{why: why}
	}
	audit := filepath.Join(dir, file)
	stem := strings.TrimSuffix(file, filepath.Ext(file))
	// rotated reports whether the entry name of d is the audit file or a
	// copy logrotate made of it. With extension, logrotate writes the
	// name up to the last dot followed by a separator or a digit
	// (audit.1.jsonl, audit-20261012.jsonl), never auditor.toml. A file
	// the configuration names is no copy, also when its name looks like
	// one: it would become writable. Nor is a directory (audit-keys/):
	// it is an olddir or nothing.
	rotated := func(d, name string) bool {
		full := filepath.Join(d, name)
		if p.named[full] && full != audit {
			return false
		}
		if info, err := p.fs.Stat(full); err == nil && info.IsDir() {
			return false
		}
		if strings.HasPrefix(name, file) {
			return true
		}
		rest, ok := strings.CutPrefix(name, stem)
		return ok && stem != "" && rest != "" && (strings.ContainsRune(".-_", rune(rest[0])) || '0' <= rest[0] && rest[0] <= '9')
	}
	names, err := p.fs.ReadDir(dir)
	if err != nil {
		return verdict{why: "cannot be listed"}
	}
	slices.Sort(names)
	var other []string
	for _, name := range names {
		switch {
		case rotated(dir, name), name == "lost+found" && p.fsRoot(dir):
			continue
		}
		full := filepath.Join(dir, name)
		// An olddir; not one that an include pattern goes through or
		// that holds a named file, also while it is empty: the audit
		// directory's write rights would reach it.
		if info, err := p.fs.Stat(full); err == nil && info.IsDir() && !p.onPath(full) && !p.holdsNamed(full) {
			if sub, err := p.fs.ReadDir(full); err == nil && !slices.ContainsFunc(sub, func(n string) bool { return !rotated(full, n) }) {
				continue
			}
		}
		other = append(other, name)
	}
	if len(other) == 0 {
		return verdict{dedicated: true}
	}
	return verdict{why: "holds " + listShown(other)}
}

// fsRoot reports whether dir is the root of a file system: a volume of its
// own, where lost+found belongs.
func (p *planner) fsRoot(dir string) bool {
	if isRoot(dir) {
		return true
	}
	d, err1 := p.fs.Stat(dir)
	parent, err2 := p.fs.Stat(filepath.Dir(dir))
	return err1 == nil && err2 == nil && d.Dev != parent.Dev
}

// resolved is a path with every symlink resolved.
type resolved struct {
	path   string
	info   Info
	exists bool
}

// resolve resolves path. A path that does not exist, or a dangling
// symlink, is not an error; one that exists but cannot be resolved is.
func (p *planner) resolve(path string) (resolved, error) {
	if _, err := p.fs.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return resolved{}, nil
	} else if err != nil {
		return resolved{}, err
	}
	r, err := p.fs.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return resolved{}, nil
	} else if err != nil {
		return resolved{}, err
	}
	info, err := p.fs.Stat(r)
	if err != nil {
		return resolved{}, err
	}
	return resolved{path: filepath.Clean(r), info: info, exists: true}, nil
}

// special reports whether path never gets a rule: paths under /dev and
// /proc (an authorized_keys link to /dev/null, a pipe, audit.output on
// stderr). Such files stay usable through descriptors opened before.
func (p *planner) special(path string) bool {
	return p.in.Linux && (beneath(path, "/dev") || beneath(path, "/proc"))
}

func (p *planner) addFile(r resolved, rights Rights, key string) {
	if r.info.IsDir() {
		return // a directory where a file is named: it is not read
	}
	p.rules = append(p.rules, Rule{Path: r.path, Open: r.path, Rights: rights, Dev: r.info.Dev, Ino: r.info.Ino, For: []string{key}})
}

func (p *planner) addDir(r resolved, rights Rights, key string) {
	p.rules = append(p.rules, Rule{Path: r.path, Open: r.path, Rights: rights, Dir: true, Dev: r.info.Dev, Ino: r.info.Ino, For: []string{key}})
}

// place adds the rules for a named file: its directory with dirRights when
// the directory is dedicated, else the file with fileRights and a start
// warning. A named file that is a symlink resolving outside a dedicated
// directory also gets a rule on its target: a directory rule covers only
// what resolves beneath it. One that cannot be resolved, below a directory
// gosftpd cannot search (an authorized_keys file read only with
// "publickey"), gets no rule and a start warning.
func (p *planner) place(key, path string, fileRights, dirRights Rights) error {
	path = filepath.Clean(path)
	if p.special(path) {
		return nil
	}
	r, err := p.resolve(path)
	switch {
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.ELOOP):
		why := err
		if pe, ok := errors.AsType[*fs.PathError](err); ok {
			why = pe.Err
		}
		p.notes = append(p.notes, &note{text: key + ": " + path + " cannot be resolved (" + why.Error() + "): no Landlock rule; reading it needs a restart"})
		return nil
	case err != nil:
		return fmt.Errorf("%s: %w", key, err)
	}
	if !r.exists || p.special(r.path) {
		return nil
	}
	dir := filepath.Dir(path)
	v := p.dedicated(dir)
	if !v.dedicated {
		p.addFile(r, fileRights, key)
		p.noteShared(key, dir, v.why, filepath.Base(path))
		return nil
	}
	rd, err := p.resolve(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	p.addDir(rd, dirRights, key)
	if !beneath(r.path, rd.path) {
		p.addFile(r, fileRights, key)
		p.noteLink(key, path, r.path, dir)
	}
	return nil
}

// mountRules: a mount's directory, for a {user} mount its parent, through
// the descriptor the mount holds open. A mount that is unavailable from the
// start (Config.Unavailable) is not open and gets none.
func (p *planner) mountRules() error {
	byName := map[string]MountDir{}
	for _, m := range p.in.Mounts {
		byName[m.Name] = m
	}
	for _, name := range sortedKeys(p.c.Mounts) {
		if slices.Contains(p.c.Unavailable, name) {
			continue
		}
		m := p.c.Mounts[name]
		dir := filepath.Clean(m.Path)
		key := toml.Key{"mounts", name, "path"}.String()
		switch {
		case p.c.EphemeralDir != "" && beneath(dir, filepath.Clean(p.c.EphemeralDir)):
			key = keyEphemeral + " " + name
		case p.c.AnyUser != nil, p.c.EphemeralDir != "":
			key = "--dir " + name
		case p.c.Atmoz:
			key = config.AtmozKey(m)
		}
		home := filepath.Base(dir) == vfs.UserPlaceholder
		if home {
			dir = filepath.Dir(dir)
		}
		rights := MountRW
		if m.ReadOnly {
			rights = MountRO
			if home && m.Create {
				rights |= MakeDir
			}
		}
		if isRoot(dir) {
			return &RootError{Key: key}
		}
		if p.special(dir) {
			p.notes = append(p.notes, &note{text: key + ": " + dir + " is under /dev or /proc, which never get a Landlock rule: the mount cannot be used; " + p.elsewhere()})
			continue
		}
		r, err := p.resolve(dir)
		switch {
		case err != nil:
			return fmt.Errorf("%s: %w", key, err)
		case r.exists && isRoot(r.path):
			return &RootError{Key: key}
		case r.exists && p.special(r.path):
			p.notes = append(p.notes, &note{text: key + ": " + dir + " resolves to " + r.path + " under /dev or /proc, which never get a Landlock rule: the mount cannot be used; " + p.elsewhere()})
			continue
		case p.in.Mounts == nil:
			if r.exists {
				p.addDir(r, rights, key)
			}
			continue
		}
		md, ok := byName[name]
		switch {
		case !ok:
			return fmt.Errorf("%s: the mount is not open", key)
		case !r.exists || r.info.Dev != md.Dev || r.info.Ino != md.Ino:
			return fmt.Errorf("%s: %s is no longer the directory the mount opened", key, dir)
		}
		rule := Rule{Path: r.path, Open: r.path, Rights: rights, Dir: true, Dev: md.Dev, Ino: md.Ino, For: []string{key}}
		if md.FD >= 0 {
			rule.Open = "/proc/self/fd/" + strconv.Itoa(md.FD)
		}
		p.rules = append(p.rules, rule)
	}
	return nil
}

// elsewhere says what to do about a mount under /dev or /proc. serve
// --ephemeral has no server.landlock to turn off.
func (p *planner) elsewhere() string {
	switch {
	case p.c.EphemeralDir != "":
		return "set TMPDIR to another directory, or serve another one with --dir"
	case p.c.Atmoz:
		return "make it a directory, or mount one there"
	}
	return `serve another directory or set server.landlock = "off"`
}

// ephemeralRule: serve --ephemeral removes the client key and the data
// directory at exit, and removing an entry is a right of the directory
// that holds it: the directory it created gets remove_file and
// remove_dir, through the descriptor it holds. The directory holds
// nothing else, and itself stays: removing it would need remove_dir on
// its parent, $TMPDIR, which would let gosftpd remove other empty
// directories there (ADR 0012).
func (p *planner) ephemeralRule() error {
	if p.c.EphemeralDir == "" {
		return nil
	}
	dir := filepath.Clean(p.c.EphemeralDir)
	if p.special(dir) {
		p.notes = append(p.notes, &note{text: keyEphemeral + ": " + dir + " is under /dev or /proc, which never get a Landlock rule: the client key and the data stay there at exit; set TMPDIR to another directory"})
		return nil
	}
	r, err := p.resolve(dir)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", keyEphemeral, err)
	case !r.exists || !r.info.IsDir():
		return fmt.Errorf("%s: %s is no longer the directory gosftpd created", keyEphemeral, dir)
	case isRoot(r.path):
		return &RootError{Key: keyEphemeral}
	case p.special(r.path):
		p.notes = append(p.notes, &note{text: keyEphemeral + ": " + dir + " resolves to " + r.path + " under /dev or /proc, which never get a Landlock rule: the client key and the data stay there at exit; set TMPDIR to another directory"})
		return nil
	}
	rule := Rule{Path: r.path, Open: r.path, Rights: RemoveFile | RemoveDir, Dir: true, Dev: r.info.Dev, Ino: r.info.Ino, For: []string{keyEphemeral}}
	if held := p.in.Ephemeral; held != nil {
		if r.info.Dev != held.Dev || r.info.Ino != held.Ino {
			return fmt.Errorf("%s: %s is no longer the directory gosftpd created", keyEphemeral, dir)
		}
		if held.FD >= 0 {
			rule.Open = "/proc/self/fd/" + strconv.Itoa(held.FD)
		}
	}
	p.rules = append(p.rules, rule)
	return nil
}

// configRules: the main file's directory if dedicated, else the file.
func (p *planner) configRules() error {
	if p.c.File == "" {
		return nil
	}
	return p.place(keyConfig, p.c.File, ReadFile, ReadFile|ReadDir)
}

// includeRules: each pattern's leading directory, whether or not the main
// file's directory is dedicated. A dedicated one gets read rights on its
// tree; another one read_dir, and its matches rules of their own.
func (p *planner) includeRules() error {
	for _, inc := range p.incs {
		if isRoot(inc.lead) {
			return &RootError{Key: keyInclude}
		}
		if p.special(inc.lead) {
			continue
		}
		rl, err := p.resolve(inc.lead)
		if err != nil {
			return fmt.Errorf("%s: %w", keyInclude, err)
		}
		switch {
		case !rl.exists:
			p.missing = append(p.missing, inc.lead)
			continue
		case !rl.info.IsDir():
			continue // nothing matches below a file
		case isRoot(rl.path):
			return &RootError{Key: keyInclude}
		}
		v := p.dedicated(inc.lead)
		if !v.dedicated {
			p.addDir(rl, ReadDir, keyInclude)
			for _, f := range p.matches(inc) {
				if rf, err := p.resolve(f); err != nil {
					return fmt.Errorf("%s: %w", keyInclude, err)
				} else if rf.exists && !p.special(rf.path) {
					p.addFile(rf, ReadFile, keyInclude)
				}
			}
			if err := p.linkedIncludeDirs(inc, false); err != nil {
				return err
			}
			p.notes = append(p.notes, &note{text: keyInclude + ": Landlock covers only the include files found at start in " + inc.lead +
				", which " + v.why + "; a new or renamed include file needs a restart"})
			continue
		}
		p.addDir(rl, ReadFile|ReadDir, keyInclude)
		if rp, err := p.resolve(filepath.Dir(inc.lead)); err == nil && rp.exists && !beneath(rl.path, rp.path) {
			p.noteLink(keyInclude, inc.lead, rl.path, filepath.Dir(inc.lead))
		}
		for _, f := range p.matches(inc) {
			rf, err := p.resolve(f)
			if err != nil {
				return fmt.Errorf("%s: %w", keyInclude, err)
			}
			if !rf.exists || p.special(rf.path) {
				continue
			}
			// Beneath its own directory, wherever that resolves to (a
			// linked directory gets its rule below), or beneath the
			// leading directory, whose rule covers it.
			rd, err := p.resolve(filepath.Dir(f))
			if err != nil {
				return fmt.Errorf("%s: %w", keyInclude, err)
			}
			if !beneath(rf.path, rd.path) && !beneath(rf.path, rl.path) {
				p.addFile(rf, ReadFile, keyInclude)
				p.noteLink(keyInclude, f, rf.path, filepath.Dir(f))
			}
		}
		if err := p.linkedIncludeDirs(inc, true); err != nil {
			return err
		}
	}
	return nil
}

// linkedIncludeDirs adds a rule on the target of each directory between
// inc's leading directory and a match that resolves outside the rules so
// far, with a start warning naming it: a team directory of
// teams/*/users.toml that is a link into another tree. Glob lists it, and
// ignores a directory it cannot list. The target gets read_file too when
// the leading directory and the linked one are dedicated.
func (p *planner) linkedIncludeDirs(inc include, dedicated bool) error {
	for _, f := range p.matches(inc) {
		rel, ok := relative(filepath.Dir(f), inc.lead)
		if !ok || rel == "" {
			continue
		}
		d := inc.lead
		for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
			d = filepath.Join(d, part)
			rights := ReadDir
			if dedicated && p.dedicated(d).dedicated {
				rights |= ReadFile
			}
			if p.covers(d, rights) {
				continue
			}
			rd, err := p.resolve(d)
			switch {
			case err != nil:
				return fmt.Errorf("%s: %w", keyInclude, err)
			case !rd.exists || !rd.info.IsDir() || p.special(rd.path):
				continue
			case isRoot(rd.path):
				return &RootError{Key: keyInclude}
			}
			p.addDir(rd, rights, keyInclude)
			p.noteLink(keyInclude, d, rd.path, filepath.Dir(d))
		}
	}
	return nil
}

// missingIncludes warns about an include directory that does not exist at
// start and that no rule covers.
func (p *planner) missingIncludes() {
	for _, dir := range p.missing {
		if !p.covers(dir, ReadFile|ReadDir) {
			p.notes = append(p.notes, &note{text: keyInclude + ": " + dir + " does not exist: the first file added there needs a restart"})
		}
	}
}

// covers reports whether a directory rule gives need on path, which may
// not exist yet.
func (p *planner) covers(path string, need Rights) bool {
	rest := ""
	for {
		if r, err := p.resolve(path); err == nil && r.exists {
			full := filepath.Join(r.path, rest)
			return slices.ContainsFunc(p.rules, func(rule Rule) bool {
				return rule.Dir && beneath(full, rule.Path) && rule.Rights&need == need
			})
		}
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		rest = filepath.Join(filepath.Base(path), rest)
		path = parent
	}
}

// trustedRules: authorized_keys files, the CA file and the revocation
// list, host keys with their siblings, hook secret files.
func (p *planner) trustedRules() error {
	for _, t := range p.trustedFiles(false) {
		if err := p.place(t.key, t.path, ReadFile, ReadFile); err != nil {
			return err
		}
	}
	return nil
}

// auditRules: the directory of audit.output when it passes the stricter
// test, else the file, with the rotation warning.
func (p *planner) auditRules() error {
	out := p.c.Audit.Output
	if out == "" || out == "stdout" {
		return nil
	}
	path := filepath.Clean(out)
	if p.special(path) {
		return nil // not reopened at reload: the descriptor opened at start stays
	}
	r, err := p.resolve(path)
	if err != nil {
		return fmt.Errorf("%s: %w", keyAudit, err)
	}
	if r.exists && p.special(r.path) {
		return nil
	}
	dir := filepath.Dir(path)
	v := p.auditDedicated(dir, filepath.Base(path))
	if !v.dedicated {
		if r.exists {
			p.addFile(r, WriteFile, keyAudit)
		}
		p.notes = append(p.notes, &note{text: keyAudit + ": Landlock covers only the file " + filepath.Base(path) + " in " + dir +
			", which " + v.why + ": " + auditRotationWarning})
		return nil
	}
	rd, err := p.resolve(dir)
	if err != nil {
		return fmt.Errorf("%s: %w", keyAudit, err)
	}
	if !rd.exists {
		return nil
	}
	p.addDir(rd, WriteFile|MakeReg, keyAudit)
	if r.exists && !beneath(r.path, rd.path) {
		p.addFile(r, WriteFile, keyAudit)
		p.noteLink(keyAudit, path, r.path, dir)
	}
	return nil
}

// procSelfRule: /proc/self for the process metrics and mountinfo, through
// the descriptor held open.
func (p *planner) procSelfRule() error {
	info, err := p.fs.Stat("/proc/self")
	if err != nil {
		return fmt.Errorf("%s: %w", keyProcSelf, err)
	}
	rule := Rule{Path: "/proc/self", Open: "/proc/self", Rights: ReadFile | ReadDir, Dir: true, Dev: info.Dev, Ino: info.Ino, For: []string{keyProcSelf}}
	if p.in.ProcSelfFD >= 0 {
		rule.Open = "/proc/self/fd/" + strconv.Itoa(p.in.ProcSelfFD)
	}
	p.rules = append(p.rules, rule)
	return nil
}

// resolverRules: the files Go's resolver reads, for webhooks, also when
// none is configured, so that a reload can add one. They are file rules (a
// rule on /etc would open it), and resolv.conf's directory too when it
// lies under /run (systemd-resolved, NetworkManager), where it is replaced
// by rename.
func (p *planner) resolverRules() {
	for _, f := range resolverFiles {
		r, err := p.resolve(f)
		if err != nil || !r.exists || p.special(r.path) || r.info.IsDir() {
			continue
		}
		p.addFile(r, ReadFile, keyResolver)
		if f == "/etc/resolv.conf" && beneath(r.path, "/run") {
			if rd, err := p.resolve(filepath.Dir(r.path)); err == nil && rd.exists && !isRoot(rd.path) && rd.path != "/run" {
				p.addDir(rd, ReadFile, keyResolver)
			}
		}
	}
}

// coverageRule: where a -cover build writes its counters at exit, never on
// / and never on a directory that gets another rule.
func (p *planner) coverageRule() {
	if p.in.CoverDir == "" {
		return
	}
	r, err := p.resolve(p.in.CoverDir)
	if err != nil || !r.exists || !r.info.IsDir() || isRoot(r.path) ||
		slices.ContainsFunc(p.rules, func(rule Rule) bool { return rule.Path == r.path }) {
		return
	}
	p.addDir(r, coverRights, keyCoverage)
}

// noteShared records a file of key that got a rule of its own because dir
// is not dedicated.
func (p *planner) noteShared(key, dir, why, file string) {
	for _, n := range p.notes {
		if n.text == "" && n.key == key && n.dir == dir {
			if !slices.Contains(n.files, file) {
				n.files = append(n.files, file)
			}
			return
		}
	}
	p.notes = append(p.notes, &note{key: key, dir: dir, why: why, files: []string{file}})
}

// noteLink records a named symlink whose target lies outside its
// directory.
func (p *planner) noteLink(key, link, target, dir string) {
	p.notes = append(p.notes, &note{text: key + ": " + link + " is a link to " + target + ", outside " + dir +
		", so Landlock covers only that target; re-pointed, the link cannot be read until a restart"})
}

// warnings formats the notes.
func (p *planner) warnings() []string {
	warns := make([]string, 0, len(p.notes))
	for _, n := range p.notes {
		if n.text != "" {
			warns = append(warns, n.text)
			continue
		}
		what, it := "the file "+n.files[0], "it"
		if len(n.files) > 1 {
			what, it = "the files "+listAll(n.files), "such a file"
		}
		warns = append(warns, n.key+": Landlock covers only "+what+" in "+n.dir+", which "+n.why+
			"; replaced by rename, "+it+" cannot be read until a restart")
	}
	return warns
}

// dedupe merges the rules on one path and drops those that a directory
// rule above them already covers with all their rights. The result is
// sorted by path.
func dedupe(rules []Rule) []Rule {
	var merged []Rule
	at := map[string]int{}
	for _, r := range rules {
		if i, ok := at[r.Path]; ok && merged[i].Dir == r.Dir {
			m := &merged[i]
			m.Rights |= r.Rights
			for _, f := range r.For {
				if !slices.Contains(m.For, f) {
					m.For = append(m.For, f)
				}
			}
			if m.Open == m.Path { // a descriptor held open wins
				m.Open = r.Open
			}
			continue
		}
		at[r.Path] = len(merged)
		r.For = slices.Clone(r.For)
		merged = append(merged, r)
	}
	out := merged[:0:0]
	for i, r := range merged {
		covered := slices.ContainsFunc(merged, func(d Rule) bool {
			return d.Dir && d.Path != r.Path && beneath(r.Path, d.Path) && d.Rights&r.Rights == r.Rights
		})
		if !covered {
			out = append(out, merged[i])
		}
	}
	// sort.Slice, not slices.SortFunc: a generic sort of this struct
	// would add 15 KiB to the binary.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// listShown lists up to maxNamedShown names: "a", "a and b", "a, b and c",
// "a, b, c and 2 more".
func listShown(names []string) string {
	if len(names) > maxNamedShown {
		return strings.Join(names[:maxNamedShown], ", ") + " and " + strconv.Itoa(len(names)-maxNamedShown) + " more"
	}
	return listAll(names)
}

func listAll(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// isRoot reports whether path is a root directory, such as / or C:\.
func isRoot(path string) bool {
	path = filepath.Clean(path)
	return filepath.Dir(path) == path
}

// beneath reports whether path is dir or lies below it.
func beneath(path, dir string) bool {
	_, ok := relative(path, dir)
	return ok
}

// relative returns path relative to dir ("" for dir itself), and whether
// path is dir or lies below it.
func relative(path, dir string) (string, bool) {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	if path == dir {
		return "", true
	}
	prefix := strings.TrimSuffix(dir, string(filepath.Separator)) + string(filepath.Separator)
	rest, ok := strings.CutPrefix(path, prefix)
	return rest, ok
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
