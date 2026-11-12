// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

type initOptions struct {
	out            string
	user           string
	authorizedKeys string
	dirs           []string
	force          bool
	stateDir       string
	listen         []string
	onConflict     string
	auditOutput    string
	readOnly       []string
	passwordLogins bool
	disconnect     bool // reload.disconnect_removed_users
	noUser         bool
	noCreate       bool
}

// initMount is a [mounts.NAME] table that init writes.
type initMount struct {
	name, path string
	readOnly   bool
}

func newInitCmd() *cobra.Command {
	var o initOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a configuration file and a host key",
		Long: `Create a commented configuration file (./gosftpd.toml by default, which
gosftpd serve finds on its own) and a host key in --state-dir. Existing
files are not overwritten without --force.

Without --dir the configuration serves ./share (created on first start).
The user from --user (default: your login name) gets full access with the
keys from --authorized-keys (default: ~/.ssh/authorized_keys, if it exists).
With --no-user the file has no user: add users with gosftpd user add
--write, which puts them in users.d/ next to the file.

With --force, init checks the new file together with the users it includes,
as gosftpd config validate --check-fs does, and refuses to write it if it is
invalid, leaving the old file as it was. A valid file replaces the old one
through a temporary file and a rename. users.d/ and the host key are kept.`,
		Example: `  gosftpd init
  gosftpd init --user alice --dir inbox=/srv/sftp/inbox --out /etc/gosftpd/config.toml
  gosftpd init --force --no-user --dir inbox=/srv/sftp/inbox --read-only inbox --password-logins`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.out, "out", config.LocalFile, "configuration file to write")
	f.StringVar(&o.user, "user", "", "user name (default: your login name)")
	f.StringVar(&o.authorizedKeys, "authorized-keys", "", "authorized_keys file for the user (default ~/.ssh/authorized_keys)")
	f.StringArrayVar(&o.dirs, "dir", nil, "directory to serve, as PATH or NAME=PATH (repeatable; default ./share)")
	f.StringVar(&o.stateDir, "state-dir", "", "directory for the generated host key (default <user config dir>/gosftpd)")
	f.StringArrayVar(&o.listen, "listen", nil, "address to listen on, as HOST:PORT or :PORT (repeatable; default :2022)")
	f.StringVar(&o.onConflict, "on-conflict", string(vfs.ConflictRename), "when an upload targets an existing file: rename, reject, overwrite or version")
	f.StringVar(&o.auditOutput, "audit-output", "stdout", "audit log destination: stdout or a file path, whose directory is created (mode 0700) if it is missing")
	f.StringArrayVar(&o.readOnly, "read-only", nil, "make the mount NAME of a --dir read-only (repeatable)")
	f.BoolVar(&o.passwordLogins, "password-logins", false, "allow password logins as well as keys (auth.methods = [\"publickey\", \"password\"])")
	f.BoolVar(&o.disconnect, "disconnect-removed-users", false, "on reload, close the connections of users who were removed or disabled")
	f.BoolVar(&o.noUser, "no-user", false, "add no user; needs --dir, and a --dir with '=' must then start with a valid mount name")
	f.BoolVar(&o.noCreate, "no-create", false, "never create the --dir directories: each must exist, and a missing one is an error at start")
	f.BoolVar(&o.force, "force", false, "overwrite an existing configuration file, if the new one passes the checks of config validate --check-fs")
	return cmd
}

func runInit(w, errOut io.Writer, o initOptions) (err error) {
	name, err := initUser(o)
	if err != nil {
		return err
	}
	if err := checkInitFlags(o); err != nil {
		return err
	}
	if len(o.dirs) == 0 {
		o.dirs = []string{"share"}
	}
	if len(o.listen) == 0 {
		o.listen = []string{":2022"}
	}
	mounts, err := initMounts(o)
	if err != nil {
		return err
	}

	keysFile := ""
	if !o.noUser {
		keysFile = o.authorizedKeys
		if keysFile == "" {
			if home, err := os.UserHomeDir(); err == nil {
				if p := filepath.Join(home, ".ssh", "authorized_keys"); fileExists(p) {
					keysFile = p
				}
			}
		} else if !fileExists(keysFile) {
			return usageError{fmt.Errorf("--authorized-keys %s does not exist", keysFile)}
		}
		if keysFile != "" {
			keysFile = absPath(keysFile)
		} else if o.force {
			// Without --force the file gets a placeholder for the key, to
			// be replaced by hand. That makes it invalid, which the check
			// of --force would report as a problem of a file it did not
			// write.
			return usageError{fmt.Errorf("no authorized_keys file for %s: with --force, pass --authorized-keys FILE, or --no-user and add users with gosftpd user add --write (a file with a key placeholder is not valid)", name)}
		}
	}

	stateDir := o.stateDir
	if stateDir == "" {
		if stateDir, err = defaultStateDir(); err != nil {
			return configError{err}
		}
	}
	keyPath := filepath.Join(absPath(stateDir), hostkey.DefaultFile)

	auditOut, auditDir, err := initAuditOutput(o.auditOutput)
	if err != nil {
		return err
	}
	data := initFile(o, name, keysFile, keyPath, auditOut, mounts)

	// The audit log's directory is created first, so that a failure
	// leaves no file that names a directory that does not exist. If init
	// fails before the file is written, it is removed again.
	written, madeAuditDir := false, false
	defer func() {
		if err != nil && !written && madeAuditDir {
			_ = os.Remove(auditDir) // only if still empty
		}
	}()
	if auditDir != "" {
		if err := os.Mkdir(auditDir, 0o700); err != nil {
			return configError{fmt.Errorf("--audit-output: %w", err)}
		}
		madeAuditDir = true
		if err := os.Chmod(auditDir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the x bit; set so, not subject to the umask
			return err
		}
	}

	// users.d exists from the start, with the mode user add --write gives
	// it: under Landlock, an include directory that is missing at start
	// needs a restart for its first file (ADR 0011).
	usersDir := filepath.Join(filepath.Dir(o.out), "users.d")
	var madeUsersDir bool
	if o.force {
		madeUsersDir, err = replaceConfig(errOut, o.out, data, usersDir)
		if err != nil {
			return err
		}
		written = true
	} else {
		if err := writeNew(o.out, data); err != nil {
			return err
		}
		written = true
		cfg, err := os.Stat(o.out)
		if err != nil {
			return err
		}
		if madeUsersDir, err = makeUsersDir(usersDir, cfg); err != nil {
			return err
		}
	}

	k, generated, err := hostkey.LoadOrGenerate(keyPath)
	if err != nil {
		return configError{fmt.Errorf("host key: %w", err)}
	}
	state := "existing"
	if generated {
		state = "generated"
	}

	fmt.Fprintf(w, "Created %s\n", o.out)
	if name != "" {
		fmt.Fprintf(w, "  user %s, full access to %d mount(s)\n", name, len(mounts))
	} else {
		fmt.Fprintf(w, "  no user (--no-user), %d mount(s)\n", len(mounts))
	}
	for _, m := range mounts {
		ro := ""
		if m.readOnly {
			ro = " (read-only)"
		}
		fmt.Fprintf(w, "  mount %s -> %s%s\n", m.name, m.path, ro)
	}
	if madeUsersDir {
		fmt.Fprintf(w, "Created %s%c for gosftpd user add --write\n", usersDir, filepath.Separator)
	}
	if madeAuditDir {
		fmt.Fprintf(w, "Created %s%c for the audit log\n", auditDir, filepath.Separator)
	}
	fmt.Fprintf(w, "Host key (%s): %s\n  %s\n", state, keyPath, hostkey.Fingerprint(k.PublicKey()))
	if name != "" && keysFile == "" {
		fmt.Fprintf(w, "\nNo authorized_keys found: paste your public key into %s first.\n", o.out)
	}
	cfgFlag := ""
	if o.out != config.LocalFile {
		cfgFlag = " --config " + o.out // not the file that serve finds by itself
	}
	fmt.Fprintf(w, "\nNext steps:\n")
	fmt.Fprintf(w, "  gosftpd user add NAME --key FILE --access %s=upload --write%s\n", mounts[0].name, cfgFlag)
	fmt.Fprintf(w, "  gosftpd config validate --check-fs%s\n", cfgFlag)
	fmt.Fprintf(w, "  gosftpd serve%s\n", cfgFlag)
	return nil
}

// initUser returns the name of the user init adds, "" with --no-user.
func initUser(o initOptions) (string, error) {
	if o.noUser {
		for _, f := range [][2]string{{"user", o.user}, {"authorized-keys", o.authorizedKeys}} {
			if f[1] != "" {
				return "", usageError{fmt.Errorf("--%s and --no-user cannot be used together", f[0])}
			}
		}
		if len(o.dirs) == 0 {
			// Or init would share ./share in the current directory.
			return "", usageError{errors.New("--no-user needs at least one --dir")}
		}
		return "", nil
	}
	name := o.user
	if name == "" {
		name = defaultUserName()
	}
	if !auth.ValidUserName(name) {
		return "", usageError{fmt.Errorf("--user %q: use lowercase letters, digits, '.', '_' and '-' (max 32)", name)}
	}
	return name, nil
}

// checkInitFlags checks the values of --listen and --on-conflict, so that
// init never writes a file that config validate would refuse for them.
func checkInitFlags(o initOptions) error {
	for i, addr := range o.listen {
		_, port, err := net.SplitHostPort(addr)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 0 || n > 65535 {
			return usageError{fmt.Errorf("--listen %q: want HOST:PORT or :PORT, with a port number from 0 to 65535", addr)}
		}
		if slices.Contains(o.listen[:i], addr) {
			return usageError{fmt.Errorf("--listen %q is given twice", addr)}
		}
	}
	if _, err := vfs.ParseConflictPolicy(o.onConflict); err != nil {
		return usageError{fmt.Errorf("--on-conflict: %w", err)}
	}
	return nil
}

// initMounts turns the --dir values into mounts, with --read-only and,
// with --no-create, a check that each directory exists.
//
// A value is NAME=PATH when the part before the first '=' is a valid mount
// name. Otherwise the whole value is a path, named after its last element:
// paths may contain '=', and init has always read them so. With --no-user,
// which the GUI passes with names that people type, such a value is
// refused instead: a name with a character a mount name cannot have
// (Фото=/srv/photos) would otherwise share a directory nobody meant.
func initMounts(o initOptions) ([]initMount, error) {
	var mounts []initMount
	seen := map[string]bool{}
	for _, d := range o.dirs {
		n, p, ok := strings.Cut(d, "=")
		if ok && !vfs.ValidMountName(n) && o.noUser {
			return nil, usageError{fmt.Errorf("--dir %q: %q is not a valid mount name (letters, digits, '.', '_', '-', spaces, starting with a letter or digit); with --no-user the part before '=' is always the name", d, n)}
		}
		if !ok || !vfs.ValidMountName(n) {
			n, p = "", d
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, usageError{fmt.Errorf("--dir %q: %w", d, err)}
		}
		if n == "" {
			n = filepath.Base(abs)
		}
		switch {
		case !vfs.ValidMountName(n):
			return nil, usageError{fmt.Errorf("--dir %q: %q is not a valid mount name; name it with --dir NAME=PATH (letters, digits, '.', '_', '-', spaces)", d, n)}
		case seen[strings.ToLower(n)]:
			return nil, usageError{fmt.Errorf("--dir %q: the mount name %q is used twice; name them with --dir NAME=PATH", d, n)}
		}
		if o.noCreate {
			switch fi, err := os.Stat(abs); {
			case errors.Is(err, fs.ErrNotExist):
				return nil, usageError{fmt.Errorf("--dir %q: %s does not exist, and with --no-create it is never created", d, abs)}
			case err != nil:
				return nil, usageError{fmt.Errorf("--dir %q: %w", d, err)}
			case !fi.IsDir():
				return nil, usageError{fmt.Errorf("--dir %q: %s is not a directory", d, abs)}
			}
		}
		seen[strings.ToLower(n)] = true
		mounts = append(mounts, initMount{name: n, path: abs})
	}
	for _, ro := range o.readOnly {
		i := slices.IndexFunc(mounts, func(m initMount) bool { return m.name == ro })
		if i < 0 {
			names := make([]string, len(mounts))
			for j, m := range mounts {
				names[j] = strconv.Quote(m.name)
			}
			return nil, usageError{fmt.Errorf("--read-only %q: no --dir has this mount name (the names are %s)", ro, strings.Join(names, ", "))}
		}
		mounts[i].readOnly = true
	}
	return mounts, nil
}

// initAuditOutput returns what init writes as audit.output for the value
// of --audit-output, and the directory it creates for the file: "" when
// the directory exists or the log goes to stdout.
func initAuditOutput(v string) (out, mkdir string, err error) {
	switch v {
	case "":
		return "", "", usageError{errors.New("--audit-output: want stdout or a file path")}
	case "stdout":
		return v, "", nil
	}
	out = absPath(v)
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		return "", "", usageError{fmt.Errorf("--audit-output %s is a directory; name a file in it", out)}
	}
	dir := filepath.Dir(out)
	switch fi, err := os.Stat(dir); {
	case errors.Is(err, fs.ErrNotExist):
		return out, dir, nil
	case err != nil:
		return "", "", configError{fmt.Errorf("--audit-output: %w", err)}
	case !fi.IsDir():
		return "", "", usageError{fmt.Errorf("--audit-output: %s is not a directory", dir)}
	}
	return out, "", nil
}

// initFile returns the commented configuration file that init writes.
func initFile(o initOptions, name, keysFile, keyPath, auditOut string, mounts []initMount) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# gosftpd configuration, created by gosftpd init.\n")
	fmt.Fprintf(&b, "# Reference of every key: gosftpd config example --full\n")
	fmt.Fprintf(&b, "# Check it with: gosftpd config validate --check-fs\n")
	fmt.Fprintf(&b, "config_version = %d\n", config.Version)
	fmt.Fprintf(&b, "include = [\"users.d/*.toml\"]  # gosftpd user add --write puts users there\n\n")
	fmt.Fprintf(&b, "[server]\nlisten = %s\n", tomlStrings(o.listen))
	fmt.Fprintf(&b, "host_keys = %s\n", tomlStrings([]string{keyPath}))
	fmt.Fprintf(&b, "host_key_auto_generate = true\n\n")
	if o.passwordLogins {
		fmt.Fprintf(&b, "[auth]\n# A user logs in with a password only if it has a password_hash.\n")
		fmt.Fprintf(&b, "methods = %s\n\n", tomlStrings([]string{auth.MethodPublicKey, auth.MethodPassword}))
	}
	fmt.Fprintf(&b, "[defaults]\non_conflict = %s  # rename | reject | overwrite | version\n", tomlString(o.onConflict))
	access := make([]string, 0, len(mounts))
	for _, m := range mounts {
		fmt.Fprintf(&b, "\n[mounts.%s]\npath = %s\n", tomlKey(m.name), tomlString(m.path))
		if o.noCreate {
			fmt.Fprintf(&b, "create = false  # a missing directory is an error at start, not created again\n")
		} else {
			fmt.Fprintf(&b, "create = true\n")
		}
		if m.readOnly {
			fmt.Fprintf(&b, "read_only = true\n")
		}
		access = append(access, tomlKey(m.name)+" = \"full\"")
	}
	fmt.Fprintf(&b, "\n# Add users with: gosftpd user add NAME --key FILE --access MOUNT=upload --write\n")
	if name != "" {
		fmt.Fprintf(&b, "[users.%s]\n", tomlKey(name))
		if keysFile != "" {
			fmt.Fprintf(&b, "authorized_keys_file = %s\n", tomlString(keysFile))
		} else {
			fmt.Fprintf(&b, "authorized_keys = [\"<paste your public key, e.g. ~/.ssh/id_ed25519.pub>\"]\n")
		}
		fmt.Fprintf(&b, "access = { %s }\n", strings.Join(access, ", "))
	}
	fmt.Fprintf(&b, "\n[audit]\noutput = %s\n", tomlString(auditOut))
	if o.disconnect {
		fmt.Fprintf(&b, "\n[reload]\n# A reload closes the connections of users it removes or disables.\n")
		fmt.Fprintf(&b, "disconnect_removed_users = true\n")
	}
	return []byte(b.String())
}

// replaceConfig writes data to path for init --force: to a temporary file
// in the same directory, renamed to path only once the new configuration,
// with the files it includes, passes the checks of config validate
// --check-fs. It creates usersDir before the check, as init does, and
// reports whether it did. On a failure path stays as it was, and what
// replaceConfig created is removed.
func replaceConfig(errOut io.Writer, path string, data []byte, usersDir string) (madeUsersDir bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	old, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return false, err
	case old.Mode()&fs.ModeSymlink != 0:
		// The rename would replace the link, not the file it points to;
		// and the includes are found next to the link.
		return false, usageError{fmt.Errorf("%s is a symbolic link, which --force would replace with a file; give the path of the file it points to", path)}
	case !old.Mode().IsRegular():
		return false, usageError{fmt.Errorf("%s is not a regular file", path)}
	}
	tmp, err := writeTemp(abs, data, old)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
			if madeUsersDir {
				_ = os.Remove(usersDir)
				madeUsersDir = false
			}
		}
	}()
	fi, err := os.Stat(tmp)
	if err != nil {
		return false, err
	}
	// Before the check: Landlock takes a missing include directory for
	// one that needs a restart.
	if madeUsersDir, err = makeUsersDir(usersDir, fi); err != nil {
		return madeUsersDir, err
	}
	if err = checkNewConfig(errOut, tmp, abs); err != nil {
		return madeUsersDir, err
	}
	return madeUsersDir, os.Rename(tmp, abs)
}

// writeTemp writes data to a new temporary file next to path and returns
// its name. The file gets mode 0600, as writeNew gives it, and, where the
// platform allows, the owner and group of like, the file it is to replace
// (nil for none), as writing over that file would keep them. Its name is
// that of writeUsersFile's temporary files: no include pattern picks it up,
// and Landlock's preview takes it for a temporary file of path.
func writeTemp(path string, data []byte, like fs.FileInfo) (string, error) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(b[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		if cerr := f.Chmod(0o600); cerr != nil && !errors.Is(cerr, errors.ErrUnsupported) {
			err = cerr
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if like != nil {
		chownLike(tmp, like)
	}
	return tmp, nil
}

// checkNewConfig loads tmp, the new configuration file that is to become
// path, with the files it includes, and runs the checks of config validate
// --check-fs on it, without the environment: they are about the file. It
// prints the warnings as validate does and returns the problems.
func checkNewConfig(errOut io.Writer, tmp, path string) error {
	c, err := config.Load(tmp)
	if err != nil {
		return notWritten(path, err)
	}
	// Messages name the file as it will be. Files keeps tmp, for the
	// checks of its mode and owner, which the rename keeps.
	c.File = path
	for _, u := range c.Users {
		if u.From == tmp {
			u.From = path
		}
	}
	warns, err := checkConfig(c, true)
	if err == nil {
		var more []string
		_, more, err = c.Authenticator()
		warns = append(warns, more...)
		if err == nil {
			_, more, err = loadHostKeys(c.Server.HostKeys, hostKeyOptions{generate: c.Server.HostKeyAutoGenerate, certs: c.Server.HostCertificates, inspect: true})
			warns = append(warns, more...)
		}
		if err == nil {
			more, err = previewLandlock(c)
			warns = append(warns, more...)
		}
	}
	for _, w := range warns {
		fmt.Fprintln(errOut, "warning:", strings.ReplaceAll(w, tmp, path))
	}
	if err != nil {
		return notWritten(path, err)
	}
	return nil
}

// notWritten is a problem of the new configuration file path, which init
// --force therefore did not write.
func notWritten(path string, err error) error {
	where := path + " (not written)"
	if pe, ok := errors.AsType[problemsError](err); ok {
		return configError{problemsError{where, pe.err}}
	}
	return configError{fmt.Errorf("%s: %w", where, err)}
}

// writeNew writes a new 0600 file, refusing to replace an existing one
// (replaceConfig does that, for --force).
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return usageError{fmt.Errorf("%s already exists; use --force to overwrite it", path)}
	}
	if err != nil {
		return err
	}
	// 0600 regardless of the umask: the permission check of serve refuses
	// group-writable configuration.
	if err := f.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var invalidUserChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// defaultUserName derives a valid user name from the login name.
func defaultUserName() string {
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	if i := strings.LastIndexAny(name, `\/`); i >= 0 { // DOMAIN\user on Windows
		name = name[i+1:]
	}
	name = strings.Trim(invalidUserChars.ReplaceAllString(strings.ToLower(name), "-"), "-._")
	if len(name) > 32 {
		name = name[:32]
	}
	if !auth.ValidUserName(name) {
		return "user"
	}
	return name
}
