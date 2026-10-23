// SPDX-License-Identifier: Apache-2.0

package atmoz

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// Home is where atmoz keeps its users' homes: user foo with directory
// upload sees /upload, stored in /home/foo/upload.
const Home = "/home"

// maxFileSize bounds the users file and each key file.
const maxFileSize = 1 << 20

// ErrNoUsers means that no source holds a user spec.
var ErrNoUsers = errors.New("no atmoz user specs")

// Options configure Build.
type Options struct {
	// UsersFile is the users file: --users-conf, or in the image
	// /etc/sftp/users.conf when it exists; "" for none.
	UsersFile string
	Args      []string // specs given as arguments
	Env       string   // $SFTP_USERS
	// Home holds the users' homes: Home.
	Home string
	// Discover adds every directory that exists directly under a user's
	// home, other than .ssh, to the user's directories: in the image only
	// (ADR 0012).
	Discover bool
}

// Mode is the configuration of atmoz mode, with what Build found on the
// way.
type Mode struct {
	Config *config.Config
	// Users counts the users of each Kind.
	Users [3]int
	// Warnings are for the log; none holds a password or a raw spec.
	Warnings []string
	// IDs reports that a spec gives a uid or a gid, which are ignored.
	IDs bool
}

// input is one spec with its source.
type input struct {
	raw string
	src Source
}

// Build reads the users of the sources in atmoz's order: the users file,
// the arguments, then $SFTP_USERS, split at white space. A user given again
// is skipped with a warning, as atmoz skips it: the first definition wins.
// Every user gets one plain mount per directory, at Home/<user>/<dir>,
// shown under the directory's name, and the keys of the files in
// Home/<user>/.ssh/keys/; the directories are created now, and one that
// cannot be is unavailable to its user (Config.Unavailable). The users
// file and the key files are read now, once, and must pass the permission
// check of trusted files. Without any spec it returns ErrNoUsers.
func Build(o Options) (*Mode, error) {
	var inputs []input
	if o.UsersFile != "" {
		data, err := readTrusted(o.UsersFile, "the users file")
		if err != nil {
			return nil, err
		}
		inputs = fileInputs(o.UsersFile, data)
	}
	inputs = append(inputs, argInputs(o.Args)...)
	inputs = append(inputs, envInputs(o.Env)...)
	specs, warns, err := collect(inputs, o.Home)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return nil, ErrNoUsers
	}

	mode := &Mode{Warnings: warns}
	c := config.Default()
	c.Atmoz = true
	c.Defaults.Flatten = false
	// As OpenSSH's put: a nightly backup or a scanner that writes the same
	// name must not leave numbered copies.
	c.Defaults.OnConflict = string(vfs.ConflictOverwrite)
	if o.UsersFile != "" {
		c.Inlined = append(c.Inlined, config.InlinedFile{Path: absPath(o.UsersFile), What: "the atmoz users file", Secret: true})
	}
	mounts := 0
	var errs []error
	for _, s := range specs {
		w := where(s.Source, s.User)
		home := filepath.Join(o.Home, s.User)
		u := &config.User{Access: map[string]string{}}
		keys, files, kw, err := readKeys(filepath.Join(home, ".ssh", "keys"))
		mode.Warnings = append(mode.Warnings, kw...)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", w, err))
			continue
		}
		u.AuthorizedKeys = keys
		for _, f := range files {
			c.Inlined = append(c.Inlined, config.InlinedFile{Path: f, What: "a key file of " + s.User})
		}
		dirs, dw, err := userDirs(s, home, o.Discover)
		mode.Warnings = append(mode.Warnings, dw...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, d := range dirs {
			mounts++
			name := "atmoz" + strconv.Itoa(mounts)
			path := filepath.Join(home, d)
			m := c.AddMount(name, path)
			m.Create, m.Display = true, d
			u.Access[name] = "full"
			if err := makeDir(home, path); err != nil {
				c.Unavailable = append(c.Unavailable, name)
				mode.Warnings = append(mode.Warnings, fmt.Sprintf("%s: directory %s cannot be created (%v), so it is unavailable to %s; give it a volume of its own (-v HOST_DIR:%s), or let %s create it in %s (chown)",
					w, d, err, s.User, path, runningUser(), home))
			}
		}
		if len(dirs) == 0 {
			fix := "name directories in the spec (" + s.User + ":pass:::upload)"
			if o.Discover {
				fix += " or mount them under " + home
			}
			mode.Warnings = append(mode.Warnings, w+": no directories, so the user logs in to an empty read-only root, as in atmoz; "+fix)
		}
		switch {
		case s.Hash != "":
			u.PasswordHash = s.Hash
		case s.Password != "":
			if u.PasswordHash, err = auth.HashPassword([]byte(s.Password)); err != nil {
				errs = append(errs, fmt.Errorf("%s: hashing the password: %w", w, err))
				continue
			}
		case len(keys) == 0:
			mode.Warnings = append(mode.Warnings, w+": no password and no keys in "+filepath.Join(home, ".ssh", "keys")+string(filepath.Separator)+", so the user cannot log in")
		}
		if u.PasswordHash != "" && !c.Auth.HasMethod(auth.MethodPassword) {
			c.Auth.Methods = append(c.Auth.Methods, auth.MethodPassword)
		}
		c.Users[s.User] = u
		mode.Users[s.Source.Kind]++
		mode.IDs = mode.IDs || s.IDs
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	mode.Config = c
	return mode, nil
}

// blank matches the lines atmoz skips in its users file: blank ones and
// comments (its reArgSkip).
var blank = regexp.MustCompile(`^([ \t]*#.*|[ \t]*)$`)

// fileInputs returns the specs of the users file at path: one per line,
// without a final carriage return.
func fileInputs(path string, data []byte) []input {
	var inputs []input
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if blank.MatchString(line) {
			continue
		}
		inputs = append(inputs, input{line, Source{Kind: File, Path: path, Pos: i + 1}})
	}
	return inputs
}

// argInputs returns the specs given as arguments.
func argInputs(args []string) []input {
	inputs := make([]input, len(args))
	for i, a := range args {
		inputs[i] = input{a, Source{Kind: Arg, Pos: i + 1}}
	}
	return inputs
}

// envInputs returns the specs of $SFTP_USERS. atmoz splits it at spaces
// and reads only its first line; gosftpd splits it at any white space, so
// that a line break separates specs instead of dropping the rest.
func envInputs(env string) []input {
	fields := strings.Fields(env)
	inputs := make([]input, len(fields))
	for i, e := range fields {
		inputs[i] = input{e, Source{Kind: Env, Pos: i + 1}}
	}
	return inputs
}

// collect parses the inputs, in order, and skips a user given again, with a
// warning. It returns every error, joined.
func collect(inputs []input, home string) ([]Spec, []string, error) {
	var (
		specs []Spec
		warns []string
		errs  []error
	)
	first := map[string]Source{}
	for _, in := range inputs {
		s, err := Parse(in.raw, in.src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Also for a spec skipped below: its password stays visible.
		warns = append(warns, s.Warnings(home)...)
		if prev, ok := first[s.User]; ok {
			warns = append(warns, fmt.Sprintf("%s: user %s is already defined by %s; skipped, as atmoz skips it", where(s.Source, ""), s.User, prev))
			continue
		}
		first[s.User] = s.Source
		specs = append(specs, s)
	}
	return specs, warns, errors.Join(errs...)
}

// userDirs returns the user's directories: those the spec names, then, with
// discover, those that exist directly under home, by name. A discovered
// directory whose name is not a valid mount name is skipped with a
// warning, .ssh without one; two whose names differ only in case are an
// error.
func userDirs(s Spec, home string, discover bool) ([]string, []string, error) {
	dirs := slices.Clone(s.Dirs)
	if !discover {
		return dirs, nil, nil
	}
	w := where(s.Source, s.User)
	des, err := os.ReadDir(home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return dirs, nil, nil
	case err != nil:
		return dirs, []string{fmt.Sprintf("%s: the directories in %s cannot be listed (%v); only those of the spec are served", w, home, err)}, nil
	}
	var warns []string
	for _, de := range des {
		name := de.Name()
		switch {
		case !de.IsDir() || name == ".ssh":
			continue
		case !vfs.ValidMountName(name):
			warns = append(warns, fmt.Sprintf("%s: directory %q in %s is skipped: not a valid name; %s", w, name, home, nameRule))
			continue
		}
		if prev, ok := foldFind(dirs, name); ok {
			if prev == name {
				continue
			}
			return nil, warns, &Error{Source: s.Source, User: s.User, Msg: fmt.Sprintf("directories %q and %q (in %s) differ only in case", prev, name, home)}
		}
		dirs = append(dirs, name)
	}
	return dirs, warns, nil
}

// makeDir makes the directory path of a user whose home is home, as atmoz
// does at start, both as a mount creates its directory (0750 with the
// default umask): clients never see the home itself, only the synthetic
// root.
func makeDir(home, path string) error {
	fi, err := os.Stat(path)
	switch {
	case err == nil && fi.IsDir():
		return nil
	case err == nil:
		return fmt.Errorf("%s is not a directory", path)
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	perm := 0o777 &^ vfs.DefaultUmask
	if err := os.MkdirAll(home, perm); err != nil {
		return err
	}
	if err := os.Mkdir(path, perm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// runningUser names the user gosftpd runs as, for a fix.
func runningUser() string {
	if uid := os.Geteuid(); uid >= 0 {
		return "uid " + strconv.Itoa(uid)
	}
	return "the user gosftpd runs as"
}

// readKeys reads every file in dir, a user's .ssh/keys/, as an
// authorized_keys file, after the permission check of trusted files, and
// returns its usable lines, to be inlined, and the files read. Names that
// start with '.' are skipped, as atmoz's glob skips them; a line that
// cannot be used is skipped with a warning.
func readKeys(dir string) (lines, files, warns []string, err error) {
	des, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil, nil
	case err != nil:
		return nil, nil, nil, err
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		data, err := readTrusted(path, "a key file")
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, path)
		_, ws := auth.ParseAuthorizedKeys(data, path)
		warns = append(warns, ws...)
		for line := range bytes.SplitSeq(data, []byte("\n")) {
			if keys, _ := auth.ParseAuthorizedKeys(line, path); len(keys) > 0 {
				lines = append(lines, string(bytes.TrimSpace(line)))
			}
		}
	}
	return lines, files, warns, nil
}

// readTrusted reads path, the users file or a key file: a regular file
// that only its owner, root or the user running gosftpd, can change
// (ROADMAP §6.5).
func readTrusted(path, what string) ([]byte, error) {
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: %w", what, err)
	case fi.IsDir():
		return nil, fmt.Errorf("%s %s is a directory: Docker creates one when the host file of a bind mount does not exist; check the host path of -v", what, path)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s %s is not a regular file", what, path)
	}
	if err := config.CheckOwner(path); err != nil {
		return nil, fmt.Errorf("%s %w", what, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: %w", what, err)
	case len(data) > maxFileSize:
		return nil, fmt.Errorf("%s %s is larger than %d bytes", what, path, maxFileSize)
	}
	return data, nil
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
