// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/o-kolomoiets/go-sftp-server/internal/atmoz"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// Atmoz mode (ADR 0012) serves the users of atmoz/sftp user specs, as the
// atmoz/sftp image does: given as arguments to the root command (what
// docker run IMAGE foo:pass:::upload passes), in $SFTP_USERS, or in a users
// file. In the image, which sets GOSFTPD_ATMOZ_IMAGE=1, three of atmoz's
// container conventions apply too: the default users file, the directories
// under /home/<user>, and the host keys in /etc/ssh. The paths are
// variables for tests.
var (
	atmozUsersFile = "/etc/sftp/users.conf"
	atmozHome      = atmoz.Home
	atmozHostKeys  = []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key"}
	imageStateDir  = "/var/lib/gosftpd"
)

// atmozNoReload is why SIGHUP changes nothing in atmoz mode.
const atmozNoReload = "atmoz mode reads the users, their keys and their directories once, at start, as atmoz does; restart the container to apply a change (docker restart)"

// atmozFlags are the flags of serve that apply in atmoz mode; the root
// command takes them with user specs.
var atmozFlags = []string{"users-conf", "listen", "host-key", "state-dir", "read-only", "on-conflict", "allow-root", "log-level", "log-format", "audit-output"}

// serveMode is what serve serves.
type serveMode int

const (
	modeFile      serveMode = iota // a configuration file
	modeDir                        // --dir, without one
	modeEphemeral                  // --ephemeral
	modeAtmoz                      // atmoz user specs
)

// inImage reports whether gosftpd runs in its container image.
func inImage(getenv func(string) string) bool { return getenv(envImage) == "1" }

// mountedEmpty reports an /etc/gosftpd without config.toml in the image:
// the base image has no such directory, so it is a mount whose host path
// is wrong or was missing. It never leads to atmoz mode: a mistyped
// configuration mount added during a migration, with SFTP_USERS still set,
// would start the old plaintext-password users.
func mountedEmpty(getenv func(string) string) bool {
	return inImage(getenv) && isDir(imageConfigDir)
}

// implicitSources names the atmoz sources that are read without a flag,
// and only in atmoz mode: $SFTP_USERS when it holds anything, and in the
// image its users file when it exists.
func implicitSources(getenv func(string) string) []string {
	var srcs []string
	if strings.TrimSpace(getenv(atmoz.EnvUsers)) != "" {
		srcs = append(srcs, "$"+atmoz.EnvUsers)
	}
	if inImage(getenv) && exists(atmozUsersFile) {
		srcs = append(srcs, atmozUsersFile)
	}
	return srcs
}

// selectMode decides what serve serves and returns the warnings about
// sources it ignores (ADR 0012, "Mode selection"). --config and
// $GOSFTPD_CONFIG stay strict: a path that does not exist is an error with
// a hint, never atmoz mode, so that a mistyped path cannot start the old
// plaintext-password users. Atmoz mode starts with specs as arguments, a
// configuration file found then being ignored, or when serve finds no
// configuration file, neither --dir nor --ephemeral is given, and
// --users-conf or an implicit source may provide users. The implicit
// sources are ignored in the other modes, with a warning that never shows
// their value.
func selectMode(flags *pflag.FlagSet, o serveOptions, getenv func(string) string) (serveMode, []string, error) {
	ignored := func(reason string) []string {
		srcs := implicitSources(getenv)
		warns := make([]string, len(srcs))
		for i, src := range srcs {
			warns[i] = src + " is ignored: " + reason
		}
		return warns
	}
	usersConf := flags.Changed("users-conf")
	switch {
	case o.ephemeral:
		// --users-conf is one of ephemeralConflicts.
		return modeEphemeral, ignored("--ephemeral serves its own user, test"), nil
	case len(o.specs) > 0:
		path, err := config.Find("", getenv)
		switch {
		case err == nil:
			return modeAtmoz, []string{"the configuration file " + path + " is ignored: atmoz user specs are given as arguments"}, nil
		case errors.Is(err, config.ErrNotFound) && !mountedEmpty(getenv):
			return modeAtmoz, nil, nil
		}
		return 0, nil, findError(err, getenv)
	case len(o.dirs) > 0:
		if usersConf {
			return 0, nil, usageError{errors.New("--users-conf and --dir cannot be used together: atmoz mode starts only without --dir")}
		}
		return modeDir, ignored("--dir serves without users"), nil
	}
	path, err := config.Find(o.config, getenv)
	switch {
	case err == nil && usersConf:
		return 0, nil, usageError{fmt.Errorf("--users-conf cannot be used with a configuration file (%s): atmoz mode starts only without one", path)}
	case err == nil:
		return modeFile, ignored("serve uses the configuration file " + path), nil
	case errors.Is(err, config.ErrNotFound) && !mountedEmpty(getenv) && (usersConf || len(implicitSources(getenv)) > 0):
		return modeAtmoz, nil, nil
	}
	// No file and no users: loadConfig reports the error with its hint.
	return modeFile, nil, nil
}

// atmozMode is a serve in atmoz mode.
type atmozMode struct {
	// warnings are logged once the logger exists.
	warnings []string
	users    [3]int // per atmoz.Kind
	ids      bool   // a spec gives a uid or a gid
}

// newAtmoz builds the configuration of atmoz mode: the users of the atmoz
// sources, the host keys, and the flags that apply.
func newAtmoz(flags *pflag.FlagSet, o serveOptions, getenv func(string) string) (*config.Config, *atmozMode, error) {
	for _, f := range []struct{ name, why string }{
		{"authorized-keys", "a user's keys are the files in " + filepath.Join(atmozHome, "USER", ".ssh", "keys") + string(filepath.Separator)},
		{"user", "the users are those of the user specs"},
	} {
		if flags.Changed(f.name) {
			return nil, nil, usageError{fmt.Errorf("--%s cannot be used in atmoz mode: %s", f.name, f.why)}
		}
	}
	if err := checkFlagValues(flags, o); err != nil {
		return nil, nil, err
	}
	if err := checkSpecPaths(flags, o); err != nil {
		return nil, nil, err
	}
	image := inImage(getenv)
	a := &atmozMode{}
	opts := atmoz.Options{Args: o.specs, Env: getenv(atmoz.EnvUsers), Home: atmozHome, Discover: image}
	switch {
	case flags.Changed("users-conf"):
		opts.UsersFile = absPath(o.usersConf)
		if image && exists(atmozUsersFile) && opts.UsersFile != atmozUsersFile {
			a.warnings = append(a.warnings, atmozUsersFile+" is ignored: --users-conf names the users file")
		}
	case image && exists(atmozUsersFile):
		opts.UsersFile = atmozUsersFile
	}
	m, err := atmoz.Build(opts)
	switch {
	case errors.Is(err, atmoz.ErrNoUsers) && flags.Changed("users-conf"):
		return nil, nil, configError{fmt.Errorf("--users-conf: %s holds no user specs (lines of user:pass[:e][:uid[:gid[:dir1[,dir2]...]]])", opts.UsersFile)}
	case errors.Is(err, atmoz.ErrNoUsers):
		// No configuration file and no users: the hint, as without sources.
		return nil, nil, findError(config.ErrNotFound, getenv)
	case err != nil:
		return nil, nil, configError{err}
	}
	a.warnings = append(a.warnings, m.Warnings...)
	a.users, a.ids = m.Users, m.IDs
	c := m.Config
	if flags.Changed("read-only") && o.readOnly {
		for _, mt := range c.Mounts {
			mt.ReadOnly = true
		}
	}
	if flags.Changed("on-conflict") {
		c.Defaults.OnConflict = o.onConflict
		for _, mt := range c.Mounts {
			mt.OnConflict = o.onConflict
		}
	}
	if err := atmozHostKeyFiles(c, flags, o, image); err != nil {
		return nil, nil, err
	}
	applyOverrides(c, flags, o, getenv)
	return c, a, nil
}

// checkSpecPaths refuses a path flag of atmoz mode whose value looks like
// an atmoz user spec and names nothing: most likely a spec that the flag
// took when its own value was missing. Its message names the flag only, as
// the path may hold a password (ADR 0012); a state directory or an audit
// log would otherwise be created under that name, and logged.
//
// On Windows an absolute path starts with a drive letter and ':', which
// atmoz's test cannot tell from a spec of a one-letter user name whose
// password starts with a slash or a backslash: it is not shown either,
// and the message says why and how to see it.
func checkSpecPaths(flags *pflag.FlagSet, o serveOptions) error {
	for _, f := range []struct {
		name  string
		paths []string
	}{
		{"users-conf", []string{o.usersConf}},
		{"host-key", o.hostKeys},
		{"state-dir", []string{o.stateDir}},
		{"audit-output", []string{o.auditOutput}},
	} {
		if !flags.Changed(f.name) {
			continue
		}
		for _, p := range f.paths {
			if !atmoz.LooksLikeSpec(p) || exists(p) {
				continue
			}
			if driveLetterPath(p) {
				return usageError{fmt.Errorf("--%s: the path does not exist (not shown: its drive letter makes it look like an atmoz user spec, which may hold a password; give the path without the drive letter to see it)", f.name)}
			}
			return usageError{fmt.Errorf("--%s: the path does not exist (not shown: it looks like an atmoz user spec; give --%s its own value, before the specs)", f.name, f.name)}
		}
	}
	return nil
}

// driveLetterPath reports whether p is an absolute path that starts with a
// drive letter, such as C:\data (only on Windows).
func driveLetterPath(p string) bool {
	v := filepath.VolumeName(p)
	return len(v) == 2 && v[1] == ':' && filepath.IsAbs(p)
}

// atmozHostKeyFiles sets the host keys of atmoz mode: --host-key, else a
// key generated in --state-dir, as with --dir. In the image without them,
// atmoz's host keys in /etc/ssh that exist, so that clients keep their
// known_hosts entry, else a key generated in /var/lib/gosftpd (ADR 0012).
func atmozHostKeyFiles(c *config.Config, flags *pflag.FlagSet, o serveOptions, image bool) error {
	if flags.Changed("host-key") {
		c.Server.HostKeys = absPaths(o.hostKeys)
		return nil
	}
	dir := o.stateDir
	if dir == "" && image {
		for _, k := range atmozHostKeys {
			if exists(k) {
				c.Server.HostKeys = append(c.Server.HostKeys, k)
			}
		}
		if len(c.Server.HostKeys) > 0 {
			return nil
		}
		dir = imageStateDir
	}
	if dir == "" {
		var err error
		if dir, err = defaultStateDir(); err != nil {
			return configError{err}
		}
	}
	c.Server.HostKeys = []string{filepath.Join(absPath(dir), hostkey.DefaultFile)}
	c.Server.HostKeyAutoGenerate = true
	return nil
}

// atmozUser returns the user of mount name in atmoz mode, where each mount
// is one user's directory, and "" otherwise.
func atmozUser(c *config.Config, name string) string {
	if !c.Atmoz {
		return ""
	}
	for user, u := range c.Users {
		if _, ok := u.Access[name]; ok {
			return user
		}
	}
	return ""
}

// logMode logs that serve runs in atmoz mode, with the users per source.
func (a *atmozMode) logMode(ctx context.Context, log *slog.Logger) {
	log.InfoContext(ctx, "atmoz mode", "users_file", a.users[atmoz.File], "arguments", a.users[atmoz.Arg], "sftp_users", a.users[atmoz.Env])
	if a.ids {
		log.InfoContext(ctx, "atmoz mode: the uid and gid of user specs are ignored", "reason", "the users are virtual; files belong to the user gosftpd runs as")
	}
}

// rootArgs checks the arguments of the root command: atmoz user specs,
// when the first passes atmoz's own test of one, and then every argument
// must (ADR 0012). Anything else is an unknown command, as before. After
// the first spec, an argument that is not one may be part of one, such as
// a word of a password with a space that the shell split off, so the
// message gives its position and names it only when it is a command.
func rootArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 || !atmoz.LooksLikeSpec(args[0]) {
		return noArgs(cmd, args)
	}
	for i, a := range args {
		if atmoz.LooksLikeSpec(a) {
			continue
		}
		var which string
		switch {
		case strings.Contains(a, ":"):
			which = fmt.Sprintf("argument %d (not shown: it contains ':')", i+1)
		case isCommand(cmd, a):
			which = fmt.Sprintf("argument %d, the command '%s',", i+1, a)
		default:
			which = fmt.Sprintf("argument %d (not shown: it may be part of a spec, such as a word of a password with a space, which needs quotes)", i+1)
		}
		return usageError{fmt.Errorf("%s is not an atmoz user spec USER:PASS[:e][:UID[:GID[:DIR[,DIR]...]]]; after the first spec every argument must be one", which)}
	}
	return nil
}

// isCommand reports whether name is a subcommand of cmd.
func isCommand(cmd *cobra.Command, name string) bool {
	for _, c := range cmd.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return true
		}
	}
	return false
}
