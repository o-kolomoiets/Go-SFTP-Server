// SPDX-License-Identifier: Apache-2.0

// Package vfs exposes a set of host directories ("mounts") as one virtual
// POSIX tree per user. Every file operation goes through an *os.Root per
// mount, so a client path can never resolve outside its mount, whether via
// "..", absolute paths or symlinks.
package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ConflictPolicy decides what an upload does when the target file exists.
type ConflictPolicy string

// Conflict policies.
const (
	ConflictRename    ConflictPolicy = "rename"
	ConflictReject    ConflictPolicy = "reject"
	ConflictOverwrite ConflictPolicy = "overwrite"
	// ConflictVersion moves the existing file into the versions directory
	// when an upload or rename replaces it.
	ConflictVersion ConflictPolicy = "version"
)

// ParseConflictPolicy validates a policy name.
func ParseConflictPolicy(s string) (ConflictPolicy, error) {
	switch p := ConflictPolicy(s); p {
	case ConflictRename, ConflictReject, ConflictOverwrite, ConflictVersion:
		return p, nil
	default:
		return "", fmt.Errorf("unknown conflict policy %q (want rename, reject, overwrite or version)", s)
	}
}

// SetstatMode decides what SETSTAT does with file times.
type SetstatMode string

// Setstat modes. Permissions and ownership are never settable; a size change
// on a file this session is uploading is allowed in every mode.
const (
	SetstatTimes  SetstatMode = "times"  // apply atime and mtime
	SetstatIgnore SetstatMode = "ignore" // accept and ignore
	SetstatDeny   SetstatMode = "deny"   // refuse with permission denied
)

// ParseSetstatMode validates a setstat mode.
func ParseSetstatMode(s string) (SetstatMode, error) {
	switch m := SetstatMode(s); m {
	case SetstatTimes, SetstatIgnore, SetstatDeny:
		return m, nil
	default:
		return "", fmt.Errorf("unknown setstat_mode %q (want times, ignore or deny)", s)
	}
}

// ResumeMode decides whether uploads may continue an existing file.
type ResumeMode string

// Resume modes.
const (
	// ResumeAppendOnly lets a client append to an existing file but never
	// change the bytes that were there when it opened the file.
	ResumeAppendOnly ResumeMode = "append-only"
	ResumeOff        ResumeMode = "off"
)

// ParseResumeMode validates a resume mode.
func ParseResumeMode(s string) (ResumeMode, error) {
	switch m := ResumeMode(s); m {
	case ResumeAppendOnly, ResumeOff:
		return m, nil
	default:
		return "", fmt.Errorf("unknown resume mode %q (want append-only or off)", s)
	}
}

// SymlinkPolicy decides how existing symlinks inside a mount are treated.
// Clients can never create links.
type SymlinkPolicy string

// Symlink policies.
const (
	SymlinksInsideOnly SymlinkPolicy = "inside-only" // follow links that stay inside the mount
	SymlinksDeny       SymlinkPolicy = "deny"        // refuse any path through a symlink
)

// ParseSymlinkPolicy validates a symlink policy.
func ParseSymlinkPolicy(s string) (SymlinkPolicy, error) {
	switch p := SymlinkPolicy(s); p {
	case SymlinksInsideOnly, SymlinksDeny:
		return p, nil
	default:
		return "", fmt.Errorf("unknown symlinks policy %q (want inside-only or deny)", s)
	}
}

const (
	maxPathLen = 4096
	maxDepth   = 64
	maxNameLen = 255
	// maxTemplateLen bounds rename_template, so that a candidate name
	// always fits maxNameLen.
	maxTemplateLen = 64

	// DefaultRenameTemplate names copies made by the rename policy.
	DefaultRenameTemplate = "{stem} ({n}){ext}"
	// DefaultMaxRenameAttempts bounds the numbered names tried before a
	// timestamped one.
	DefaultMaxRenameAttempts = 100
	// MaxRenameAttempts is the largest accepted max_rename_attempts.
	MaxRenameAttempts = 10000
	// DefaultUmask masks the mode of created files (0666) and directories (0777).
	DefaultUmask fs.FileMode = 0o027

	// UserPlaceholder as the last component of a mount path makes a personal
	// home directory per user.
	UserPlaceholder = "{user}"
	homeDirPerm     = 0o750
)

// DefaultCompoundExtensions are kept whole when naming copies.
var DefaultCompoundExtensions = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"}

// Version retention defaults.
const (
	DefaultVersionsDir    = ".versions"
	DefaultVersionsKeep   = 10
	DefaultVersionsMaxAge = 30 * 24 * time.Hour
	// MaxVersionsKeep is the largest accepted versions.keep.
	MaxVersionsKeep = 10000
	// DefaultMinFreeSpace is the free space below which uploads are refused.
	DefaultMinFreeSpace = 1 << 30
)

// VersionsOptions configure on_conflict = "version".
type VersionsOptions struct {
	// Dir is the directory, at the top of the mount, that holds old
	// versions: <Dir>/<path of the file>/<stem>.<UTC time><ext>. Clients
	// can read it but not change it.
	Dir string
	// Keep is how many old versions of a file are kept; 0 keeps all.
	Keep int
	// MaxAge removes versions older than this; 0 keeps them forever.
	MaxAge time.Duration
}

// MountOptions configure how a mount handles uploads and attributes.
type MountOptions struct {
	OnConflict        ConflictPolicy
	RenameTemplate    string
	MaxRenameAttempts int
	CompoundExts      []string
	SetstatMode       SetstatMode
	Umask             fs.FileMode
	Resume            ResumeMode
	// StatRedirect makes STAT, LSTAT and SETSTAT of a path the user just
	// uploaded or moved under another name (rename policy) answer for that
	// name, in all of the user's sessions.
	StatRedirect bool
	Symlinks     SymlinkPolicy

	// MaxFileSize refuses writes past this size; 0 means no limit.
	MaxFileSize int64
	// MinFreeSpace refuses opening a file for writing while the mount's
	// filesystem has less free space; 0 turns the check off.
	MinFreeSpace int64
	// AtomicUploads writes uploads to a hidden temporary file and gives it
	// its name only when the upload is closed; resume is not possible.
	AtomicUploads bool
	// Fsync flushes an upload to disk before it gets its name (with
	// AtomicUploads or on_conflict = "version").
	Fsync    bool
	Versions VersionsOptions
}

// DefaultMountOptions returns the documented defaults.
func DefaultMountOptions() MountOptions {
	return MountOptions{
		OnConflict:        ConflictRename,
		RenameTemplate:    DefaultRenameTemplate,
		MaxRenameAttempts: DefaultMaxRenameAttempts,
		CompoundExts:      slices.Clone(DefaultCompoundExtensions),
		SetstatMode:       SetstatTimes,
		Umask:             DefaultUmask,
		Resume:            ResumeAppendOnly,
		StatRedirect:      true,
		Symlinks:          SymlinksInsideOnly,
		MinFreeSpace:      DefaultMinFreeSpace,
		Versions:          VersionsOptions{Dir: DefaultVersionsDir, Keep: DefaultVersionsKeep, MaxAge: DefaultVersionsMaxAge},
	}
}

// Validate checks the options.
func (o MountOptions) Validate() error {
	var errs []error
	if _, err := ParseConflictPolicy(string(o.OnConflict)); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateRenameTemplate(o.RenameTemplate); err != nil {
		errs = append(errs, err)
	}
	if o.MaxRenameAttempts < 1 || o.MaxRenameAttempts > MaxRenameAttempts {
		errs = append(errs, fmt.Errorf("max_rename_attempts must be between 1 and %d", MaxRenameAttempts))
	}
	for _, e := range o.CompoundExts {
		if len(e) < 2 || e[0] != '.' || strings.ContainsAny(e, `/\`+"\x00") {
			errs = append(errs, fmt.Errorf("compound extension %q must start with '.' and contain no slashes", e))
		}
	}
	if _, err := ParseSetstatMode(string(o.SetstatMode)); err != nil {
		errs = append(errs, err)
	}
	if _, err := ParseResumeMode(string(o.Resume)); err != nil {
		errs = append(errs, err)
	}
	if _, err := ParseSymlinkPolicy(string(o.Symlinks)); err != nil {
		errs = append(errs, err)
	}
	if o.Umask&^fs.ModePerm != 0 {
		errs = append(errs, fmt.Errorf("umask %#o has bits outside 0777", uint32(o.Umask)))
	}
	if o.MaxFileSize < 0 || o.MinFreeSpace < 0 {
		errs = append(errs, errors.New("max_file_size and min_free_space must not be negative"))
	}
	if d := o.Versions.Dir; d == "" || d == "." || d == ".." || strings.ContainsAny(d, `/\`+"\x00") || strings.HasPrefix(d, tempPrefix) {
		errs = append(errs, fmt.Errorf("versions.dir %q must be one directory name", d))
	}
	if o.Versions.Keep < 0 || o.Versions.Keep > MaxVersionsKeep {
		errs = append(errs, fmt.Errorf("versions.keep must be between 0 (all) and %d", MaxVersionsKeep))
	}
	if o.Versions.MaxAge < 0 {
		errs = append(errs, errors.New("versions.max_age must not be negative"))
	}
	return errors.Join(errs...)
}

// ValidateRenameTemplate checks a rename_template: it must contain {n}, may
// contain {stem} and {ext}, and no other braces or path separators.
func ValidateRenameTemplate(t string) error {
	if strings.Count(t, "{n}") != 1 {
		return fmt.Errorf("rename_template %q must contain {n} once", t)
	}
	if len(t) > maxTemplateLen || !utf8.ValidString(t) {
		return fmt.Errorf("rename_template must be valid UTF-8 of at most %d bytes", maxTemplateLen)
	}
	if strings.ContainsAny(t, `/\`+"\x00") {
		return fmt.Errorf("rename_template %q must not contain slashes", t)
	}
	rest := strings.NewReplacer("{stem}", "", "{n}", "", "{ext}", "").Replace(t)
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("rename_template %q: only {stem}, {n} and {ext} are supported", t)
	}
	return nil
}

func (o MountOptions) filePerm() fs.FileMode { return 0o666 &^ o.Umask }
func (o MountOptions) dirPerm() fs.FileMode  { return 0o777 &^ o.Umask }

var mountNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)

// windowsDeviceNames are refused as mount names on every platform.
var windowsDeviceNames = []string{
	"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

// ValidMountName reports whether name can be used as a mount name.
func ValidMountName(name string) bool {
	if !mountNameRE.MatchString(name) {
		return false
	}
	base, _, _ := strings.Cut(name, ".")
	for _, d := range windowsDeviceNames {
		if strings.EqualFold(strings.TrimRight(base, " "), d) {
			return false
		}
	}
	return true
}

// MountSpec describes one directory to expose.
type MountSpec struct {
	Name string // the top-level directory clients see
	// Path is the absolute host path. If its last component is {user}, every
	// user gets their own subdirectory of the parent (a "home" mount).
	Path     string
	ReadOnly bool
	Create   bool // create Path (or the parent of a home mount) if missing
	Options  MountOptions
}

// Options configure a Table.
type Options struct {
	// Flatten exposes a user's only mount as "/" instead of "/<name>".
	Flatten bool
}

// Mount is an opened MountSpec.
type Mount struct {
	name     string
	hostPath string
	readOnly bool
	create   bool
	home     bool
	opts     MountOptions
	root     *os.Root // for a home mount: the parent directory
}

// Name returns the mount name.
func (m *Mount) Name() string { return m.name }

// HostPath returns the host directory (for server-side messages only).
func (m *Mount) HostPath() string { return m.hostPath }

// ReadOnly reports whether the mount rejects modifications.
func (m *Mount) ReadOnly() bool { return m.readOnly }

// Home reports whether the mount is a per-user home ({user}).
func (m *Mount) Home() bool { return m.home }

// Options returns the mount options.
func (m *Mount) Options() MountOptions { return m.opts }

// Table is the set of mounts served to clients.
type Table struct {
	mounts  []*Mount // sorted by name
	byName  map[string]*Mount
	flatten bool
	started time.Time

	// Open uploads of all sessions, to refuse a second writer on a file
	// (ROADMAP §6.2: existing data must not change behind an upload).
	wmu     sync.Mutex
	writing []*WriteHandle

	umu   sync.Mutex
	users map[string]*userState // see users.go
	now   func() time.Time
}

// Open validates specs and opens an os.Root for every mount.
func Open(specs []MountSpec, opts Options) (*Table, error) {
	if len(specs) == 0 {
		return nil, errors.New("no directories to serve")
	}
	if err := ValidateSpecs(specs); err != nil {
		return nil, err
	}

	t := &Table{
		byName:  make(map[string]*Mount, len(specs)),
		flatten: opts.Flatten,
		started: time.Now(),
		users:   map[string]*userState{},
		now:     time.Now,
	}
	for _, s := range specs {
		m, err := openMount(s)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("mount %q: %w", s.Name, err)
		}
		t.mounts = append(t.mounts, m)
		t.byName[s.Name] = m
	}
	slices.SortFunc(t.mounts, func(a, b *Mount) int { return strings.Compare(a.name, b.name) })
	return t, nil
}

func openMount(s MountSpec) (*Mount, error) {
	m := &Mount{
		name:     s.Name,
		hostPath: s.Path,
		readOnly: s.ReadOnly,
		create:   s.Create,
		home:     isHomePath(s.Path),
		opts:     s.Options,
	}
	dir := s.Path
	if m.home {
		dir = filepath.Dir(s.Path)
	}
	if s.Create {
		if err := os.MkdirAll(dir, s.Options.dirPerm()); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	m.root = root
	return m, nil
}

func isHomePath(p string) bool { return filepath.Base(p) == UserPlaceholder }

// ValidateSpecs checks names, paths and options without touching the
// filesystem.
func ValidateSpecs(specs []MountSpec) error {
	var errs []error
	seen := make(map[string]bool, len(specs))
	for i, s := range specs {
		if !ValidMountName(s.Name) {
			errs = append(errs, fmt.Errorf("mount name %q: use letters, digits, '.', '_', '-' and spaces (max 64), not a device name", s.Name))
		}
		key := strings.ToLower(s.Name)
		if seen[key] {
			errs = append(errs, fmt.Errorf("duplicate mount name %q (names are case-insensitive)", s.Name))
		}
		seen[key] = true
		if err := validateMountPath(s.Path); err != nil {
			errs = append(errs, fmt.Errorf("mount %q: %w", s.Name, err))
			continue
		}
		if err := s.Options.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("mount %q: %w", s.Name, err))
		}
		for _, o := range specs[:i] {
			if validateMountPath(o.Path) != nil {
				continue
			}
			if PathsOverlap(s.Path, o.Path) {
				errs = append(errs, fmt.Errorf("mounts %q and %q overlap", o.Name, s.Name))
			}
		}
	}
	return errors.Join(errs...)
}

func validateMountPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q is not absolute", p)
	}
	dir := p
	if isHomePath(p) {
		dir = filepath.Dir(p)
	}
	if strings.Contains(dir, UserPlaceholder) {
		return fmt.Errorf("path %q: %s is only allowed as the whole last component", p, UserPlaceholder)
	}
	return nil
}

// PathsOverlap reports whether two mount paths overlap: one equals or lies
// inside the other. A home mount occupies the parent of {user}.
func PathsOverlap(a, b string) bool {
	a, b = overlapPath(a), overlapPath(b)
	return within(a, b) || within(b, a)
}

// ValidateMountPath checks that a mount path is absolute and uses {user}
// only as its whole last component.
func ValidateMountPath(p string) error { return validateMountPath(p) }

// overlapPath is the host directory a mount occupies: for a home mount, the
// parent of {user}.
func overlapPath(p string) string {
	if isHomePath(p) {
		return filepath.Dir(p)
	}
	return p
}

// within reports whether p equals dir or lies below it.
func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// Mounts returns the mounts sorted by name.
func (t *Table) Mounts() []*Mount { return slices.Clone(t.mounts) }

// Mount returns the mount called name, or nil.
func (t *Table) Mount(name string) *Mount { return t.byName[name] }

// Flattened reports whether a user who can access every mount sees it as
// "/": flattening is on and there is exactly one mount.
func (t *Table) Flattened() bool { return t.flatten && len(t.mounts) == 1 }

// Close releases all mount roots.
func (t *Table) Close() error {
	errs := make([]error, 0, len(t.mounts))
	for _, m := range t.mounts {
		errs = append(errs, m.root.Close())
	}
	return errors.Join(errs...)
}

// openHome opens user's directory below a home mount's parent (ROADMAP §6.1
// item 4). The directory must be a real directory: a symlink, even one that
// points inside the parent ("alice -> bob"), makes the mount unavailable.
func (m *Mount) openHome(user string) (*os.Root, error) {
	if !validHomeName(user) {
		return nil, ErrHomeNotDir
	}
	if m.create {
		if err := m.root.Mkdir(user, homeDirPerm); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	fi, err := m.root.Lstat(user)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrHomeMissing
		}
		return nil, err
	}
	if !fi.IsDir() {
		return nil, ErrHomeNotDir
	}
	r, err := m.root.OpenRoot(user)
	if err != nil {
		return nil, ErrHomeNotDir
	}
	// Close the window between Lstat and OpenRoot: the opened directory must
	// be the one just checked.
	rfi, err := r.Stat(".")
	if err != nil || !os.SameFile(fi, rfi) {
		_ = r.Close()
		return nil, ErrHomeNotDir
	}
	return r, nil
}

// validHomeName reports whether user can be used as a single directory name.
func validHomeName(user string) bool {
	if user == "" || user == "." || user == ".." || len(user) > maxNameLen || strings.ContainsAny(user, `/\`+"\x00") {
		return false
	}
	local, err := filepath.Localize(user)
	return err == nil && local == user
}
