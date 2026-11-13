// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Add, change, list, disable and remove users",
		Args:  noArgs,
		RunE:  showHelp,
	}
	cmd.AddCommand(newUserAddCmd(), newUserSetCmd(), newUserListCmd(), newHashPasswordCmd(),
		newUserEditCmd("disable", config.DisableUser), newUserEditCmd("enable", config.EnableUser), newUserEditCmd("remove", config.RemoveUser))
	return cmd
}

type userAddOptions struct {
	keys          []string
	principals    []string
	passwordHash  string
	passwordStdin bool
	access        []string
	expires       string
	allowFrom     []string
	write         bool
	force         bool
	config        string
	host          string
}

func newUserAddCmd() *cobra.Command {
	var o userAddOptions
	cmd := &cobra.Command{
		Use:   "add NAME --key FILE|KEY|--password-hash HASH|--password-stdin --access MOUNT=PERMISSIONS...",
		Short: "Add a user, or print its [users.NAME] block",
		Long: `Print a [users.NAME] block to add to the configuration file. With --write,
write it to users.d/NAME.toml instead (the directory of the configuration's
include = ["users.d/*.toml"]), after checking the configuration with the
new user, and print the connection details to send to the user. The main
configuration file is never rewritten. A running server applies the new
file on reload (systemctl reload gosftpd, or kill -HUP).

A user needs a --key or a password, unless the configuration trusts CAs
(auth.trusted_user_ca_keys) and --write is given: the user then logs in
with a certificate for its name, or for a --principal. The password is a
--password-hash from user hash-password, or, with --password-stdin, the
first line of standard input, hashed as user hash-password does; neither
the password nor its hash is then an argument, which other local users
could read.

Permissions are a preset (read, upload, readwrite, full) or a list of flags
(list, read, write, overwrite, delete, rename, mkdir, rmdir, setstat).`,
		Example: `  gosftpd user add partner --key partner.pub --access inbox=upload --expires 720h --write
  gosftpd user add partner --key partner.pub --access inbox=upload >> gosftpd.toml
  gosftpd user add alice --key "ssh-ed25519 AAAA... alice@laptop" --access home=full --access public=read
  gosftpd user add bob --principal bob@corp.example --access inbox=upload --write
  printf '%s\n' "$PASSWORD" | gosftpd user add carol --password-stdin --access inbox=upload --write`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return usageError{err}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.passwordStdin {
				if o.passwordHash != "" {
					return usageError{errors.New("--password-hash and --password-stdin cannot be used together")}
				}
				h, err := stdinPassword(cmd.InOrStdin())
				if err != nil {
					return err
				}
				o.passwordHash = h
			}
			block, err := userBlock(args[0], o, time.Now())
			if err != nil {
				return usageError{err}
			}
			if !o.write {
				_, err = fmt.Fprint(cmd.OutOrStdout(), block)
				return err
			}
			return writeUser(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], block, o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.write, "write", false, "write users.d/NAME.toml instead of printing the block")
	f.StringVar(&o.config, "config", "", "with --write: configuration file (default: the one serve would use)")
	f.StringVar(&o.host, "host", "", "with --write: host name in the connection details (default: from listen, or this host's name)")
	f.BoolVar(&o.force, "force", false, "with --write: write a user that could not log in (disabled, expired, no usable key or password)")
	f.StringArrayVar(&o.keys, "key", nil, "public key, or a file with public keys (repeatable)")
	f.StringArrayVar(&o.principals, "principal", nil, "certificate principal for trusted CAs, instead of the user name (repeatable)")
	f.StringVar(&o.passwordHash, "password-hash", "", "password hash from 'gosftpd user hash-password'")
	f.BoolVar(&o.passwordStdin, "password-stdin", false, "read the password from the first line of standard input, instead of --password-hash")
	f.StringArrayVar(&o.access, "access", nil, "MOUNT=PERMISSIONS (repeatable)")
	f.StringVar(&o.expires, "expires", "", "account expiry: a duration from now (72h) or a date (2026-12-31, RFC 3339)")
	f.StringArrayVar(&o.allowFrom, "allow-from", nil, "allowed client address or CIDR block (repeatable)")
	return cmd
}

// userBlock renders the TOML block for user add.
func userBlock(name string, o userAddOptions, now time.Time) (string, error) {
	if !auth.ValidUserName(name) {
		return "", fmt.Errorf("invalid user name %q: use lowercase letters, digits, '.', '_' and '-' (max 32)", name)
	}
	if len(o.keys) == 0 && o.passwordHash == "" && !o.write {
		return "", errors.New("at least one --key, a --password-hash or --password-stdin is required (with --write, a user of a configuration that trusts CAs may have none of them)")
	}
	if slices.Contains(o.principals, "") {
		return "", errors.New("--principal: empty principal")
	}
	if o.passwordHash != "" {
		if _, err := auth.ParsePasswordHash(o.passwordHash); err != nil {
			return "", fmt.Errorf("--password-hash: %w", err)
		}
	}
	if len(o.access) == 0 {
		return "", errors.New("at least one --access MOUNT=PERMISSIONS is required")
	}
	var keys []string
	for _, k := range o.keys {
		lines, err := keyLines(k)
		if err != nil {
			return "", err
		}
		keys = append(keys, lines...)
	}

	mounts, perms, err := parseAccess(o.access)
	if err != nil {
		return "", err
	}
	access := make([]string, len(mounts))
	for i, mount := range mounts {
		access[i] = tomlKey(mount) + " = " + tomlString(perms[mount])
	}

	for _, a := range o.allowFrom {
		if _, err := auth.ParsePrefix(a); err != nil {
			return "", fmt.Errorf("--allow-from: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n[users.%s]\n", tomlKey(name))
	if len(keys) > 0 {
		fmt.Fprintf(&b, "authorized_keys = %s\n", tomlStrings(keys))
	}
	if len(o.principals) > 0 {
		fmt.Fprintf(&b, "principals = %s\n", tomlStrings(o.principals))
	}
	if o.passwordHash != "" {
		fmt.Fprintf(&b, "password_hash = %s\n", tomlString(o.passwordHash))
	}
	if len(o.allowFrom) > 0 {
		fmt.Fprintf(&b, "allow_from = %s\n", tomlStrings(o.allowFrom))
	}
	if o.expires != "" {
		t, err := parseExpires(o.expires, now)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "expires = %s\n", t.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "access = { %s }\n", strings.Join(access, ", "))
	return b.String(), nil
}

// writeUser writes the block of user name to its own file, after checking
// the whole configuration with it.
func writeUser(out, errOut io.Writer, name, block string, o userAddOptions) error {
	c, err := loadConfig(o.config, os.Getenv)
	if err != nil {
		return err
	}
	if prev, ok := c.Users[name]; ok {
		return usageError{fmt.Errorf("user %q already exists in %s", name, prev.From)}
	}
	path, err := c.UsersFile(name)
	if err != nil {
		return usageError{err}
	}
	data := []byte("# Written by gosftpd user add on " + time.Now().UTC().Format(time.RFC3339) + ".\n" + strings.TrimPrefix(block, "\n"))
	users, err := config.ParseUsers(path, data)
	if err != nil {
		return err
	}
	u := users[name]
	u.From = path
	c.Users[name] = u
	c.Files = append(c.Files, path)
	warns, err := checkConfig(c, false)
	if err != nil {
		return err
	}
	printUserWarnings(errOut, name, warns)
	if !c.CanLogIn(name) && !o.force {
		return usageError{fmt.Errorf("%s could not log in (see the warnings); pass --force to write it anyway", name)}
	}
	cfg, err := os.Stat(c.File)
	if err != nil {
		return err
	}
	if err := writeUsersFile(path, data, usersFileMode(cfg), cfg, true); err != nil {
		return fmt.Errorf("user add: %w", err)
	}
	fmt.Fprintf(out, "Wrote %s. Apply it with: systemctl reload gosftpd (or kill -HUP the server).\n\n", path)
	_, err = fmt.Fprint(out, partnerInstructions(c, name, o.host))
	return err
}

// printUserWarnings prints the warnings of the configuration about user
// name.
func printUserWarnings(errOut io.Writer, name string, warns []string) {
	prefix := "users." + tomlKey(name)
	for _, w := range warns {
		if strings.HasPrefix(w, prefix+".") || strings.HasPrefix(w, prefix+" ") || strings.HasPrefix(w, prefix+":") {
			fmt.Fprintln(errOut, "warning:", w)
		}
	}
}

// parseAccess checks the values of --access, MOUNT=PERMISSIONS with each
// mount once, and returns the mounts in the order given and their
// permissions.
func parseAccess(values []string) ([]string, map[string]string, error) {
	mounts := make([]string, 0, len(values))
	perms := make(map[string]string, len(values))
	for _, a := range values {
		mount, perm, ok := strings.Cut(a, "=")
		if !ok || !vfs.ValidMountName(mount) {
			return nil, nil, fmt.Errorf("--access %q: want MOUNT=PERMISSIONS, e.g. inbox=upload", a)
		}
		if _, dup := perms[mount]; dup {
			return nil, nil, fmt.Errorf("--access: mount %q given twice", mount)
		}
		if _, err := vfs.ParsePerm(perm); err != nil {
			return nil, nil, fmt.Errorf("--access %q: %w", a, err)
		}
		mounts = append(mounts, mount)
		perms[mount] = perm
	}
	return mounts, perms, nil
}

// stdinPassword reads the password of --password-stdin, the first line of
// in, and returns its hash, as user hash-password --stdin does.
func stdinPassword(in io.Reader) (string, error) {
	pw, err := readPassword(in, io.Discard, true)
	if err != nil {
		return "", usageError{fmt.Errorf("--password-stdin: %w", err)}
	}
	defer clear(pw)
	h, err := auth.HashPassword(pw)
	if err != nil {
		return "", usageError{fmt.Errorf("--password-stdin: %w", err)}
	}
	return h, nil
}

type userSetOptions struct {
	access        []string
	noAccess      bool
	passwordStdin bool
	force         bool
	config        string
}

func newUserSetCmd() *cobra.Command {
	var o userSetOptions
	cmd := &cobra.Command{
		Use:   "set NAME --access MOUNT=PERMISSIONS...|--no-access|--password-stdin",
		Short: "Change the access or the password of a user",
		Long: `Change the access or the password of a user. The user must be defined in
an included file (such as users.d/NAME.toml from user add --write): the main
configuration file is never rewritten. The rest of the file, comments
included, stays as it is.

--access replaces the whole access of the user with the mounts given, so
name every mount the user keeps. --no-access leaves the user none: it can
still log in, but sees nothing. --password-stdin sets the password to the
first line of standard input, hashed as user hash-password does; neither
the password nor its hash is then an argument, which other local users
could read.

The configuration is checked with the change before the file is written.
A user that then could not log in (no key, password or certificate
principal that auth.methods allows) is refused unless --force is given. A
running server applies the change on reload (systemctl reload gosftpd, or
kill -HUP); open connections keep the access they had until they end.

Permissions are a preset (read, upload, readwrite, full) or a list of flags
(list, read, write, overwrite, delete, rename, mkdir, rmdir, setstat).`,
		Example: `  gosftpd user set partner --access inbox=upload --access archive=read
  gosftpd user set partner --no-access
  printf '%s\n' "$PASSWORD" | gosftpd user set partner --password-stdin`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return usageError{err}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return setUser(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.access, "access", nil, "MOUNT=PERMISSIONS of the new access, which replaces the old (repeatable)")
	f.BoolVar(&o.noAccess, "no-access", false, "leave the user no access")
	f.BoolVar(&o.passwordStdin, "password-stdin", false, "set the password to the first line of standard input")
	f.BoolVar(&o.force, "force", false, "write a user that could not log in (no usable key or password)")
	f.StringVar(&o.config, "config", "", "configuration file (default: the one serve would use)")
	return cmd
}

// setUser changes the access or the password of user name in the file
// that defines it, after checking the configuration with the change.
func setUser(in io.Reader, out, errOut io.Writer, name string, o userSetOptions) error {
	switch {
	case len(o.access) > 0 && o.noAccess:
		return usageError{errors.New("--access and --no-access cannot be used together")}
	case len(o.access) == 0 && !o.noAccess && !o.passwordStdin:
		return usageError{errors.New("nothing to change: give --access MOUNT=PERMISSIONS, --no-access or --password-stdin")}
	}
	ch := config.UserChange{SetAccess: len(o.access) > 0 || o.noAccess, Access: map[string]string{}}
	if len(o.access) > 0 {
		var err error
		if _, ch.Access, err = parseAccess(o.access); err != nil {
			return usageError{err}
		}
	}
	c, err := loadConfig(o.config, os.Getenv)
	if err != nil {
		return err
	}
	u, err := includedUser(c, name)
	if err != nil {
		return err
	}
	if o.passwordStdin {
		if ch.PasswordHash, err = stdinPassword(in); err != nil {
			return err
		}
	}
	fi, err := os.Stat(u.From)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(u.From)
	if err != nil {
		return err
	}
	data, changed, err := config.SetUser(u.From, data, name, ch)
	if err != nil {
		return configError{err}
	}
	if !changed {
		_, err := fmt.Fprintf(out, "%s has this access already.\n", name)
		return err
	}
	users, err := config.ParseUsers(u.From, data)
	if err != nil {
		return configError{err}
	}
	could := c.HasLogin(name)
	next := users[name]
	next.From = u.From
	c.Users[name] = next
	warns, err := checkConfig(c, false)
	if err != nil {
		return err
	}
	printUserWarnings(errOut, name, warns)
	// Unlike user add, a disabled or expired user is no reason to refuse:
	// set does not change that, and a disabled user may lose a mount. Nor is
	// a user who could not log in before and whose access alone changes:
	// set leaves the credentials as they were, and a folder must be taken
	// from everyone before it is removed. A change that takes the login
	// away, or a password that cannot be used, is refused.
	if !c.HasLogin(name) && (could || ch.PasswordHash != "") && !o.force {
		return usageError{fmt.Errorf("%s could not log in (see the warnings); pass --force to write it anyway", name)}
	}
	if err := writeUsersFile(u.From, data, fi.Mode().Perm(), fi, false); err != nil {
		return fmt.Errorf("user set: %w", err)
	}
	accessChanged := ch.SetAccess && !maps.Equal(u.Access, ch.Access)
	what := "password"
	switch {
	case accessChanged && ch.PasswordHash != "":
		what = "access and password"
	case accessChanged:
		what = "access"
	}
	fmt.Fprintf(out, "Set the %s of %s in %s. Apply it with: systemctl reload gosftpd (or kill -HUP the server).\n", what, name, u.From)
	if accessChanged {
		fmt.Fprintln(out, "Open connections of the user keep the access they had until they end.")
	}
	return nil
}

// includedUser returns user name of c, which must be defined in an
// included file: the main configuration file is never rewritten.
func includedUser(c *config.Config, name string) (*config.User, error) {
	u, ok := c.Users[name]
	switch {
	case !ok:
		return nil, usageError{fmt.Errorf("no user %q in %s", name, c.File)}
	case u.From == c.File:
		return nil, usageError{fmt.Errorf("user %q is defined in %s itself, which gosftpd does not rewrite (its comments would be lost); change it there", name, c.File)}
	}
	return u, nil
}

func newUserEditCmd(verb string, edit config.UserEdit) *cobra.Command {
	var file string
	short := map[config.UserEdit]string{
		config.DisableUser: "Disable a user: keep it, but refuse its logins",
		config.EnableUser:  "Enable a disabled user",
		config.RemoveUser:  "Remove a user",
	}[edit]
	cmd := &cobra.Command{
		Use:   verb + " NAME",
		Short: short,
		Long: short + `.

The user must be defined in an included file (such as users.d/NAME.toml from
user add --write): the main configuration file is never rewritten. The rest
of the file, comments included, stays as it is. A running server applies
the change on reload (systemctl reload gosftpd, or kill -HUP); connections
that are open stay unless reload.disconnect_removed_users is true.`,
		Example: "  gosftpd user " + verb + " partner",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return usageError{err}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return editUser(cmd.OutOrStdout(), file, args[0], verb, edit)
		},
	}
	cmd.Flags().StringVar(&file, "config", "", "configuration file (default: the one serve would use)")
	return cmd
}

func editUser(out io.Writer, file, name, verb string, edit config.UserEdit) error {
	c, err := loadConfig(file, os.Getenv)
	if err != nil {
		return err
	}
	u, err := includedUser(c, name)
	if err != nil {
		return err
	}
	fi, err := os.Stat(u.From)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(u.From)
	if err != nil {
		return err
	}
	out2, changed, err := config.EditUser(u.From, data, name, edit)
	if err != nil {
		return configError{err}
	}
	if !changed {
		_, err := fmt.Fprintf(out, "%s is %sd already.\n", name, verb)
		return err
	}
	if users, err := config.ParseUsers(u.From, out2); err == nil && len(users) == 0 {
		err = os.Remove(u.From)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Removed %s and its file %s.", name, u.From)
	} else {
		if err := writeUsersFile(u.From, out2, fi.Mode().Perm(), fi, false); err != nil {
			return err
		}
		past := map[config.UserEdit]string{config.DisableUser: "Disabled", config.EnableUser: "Enabled", config.RemoveUser: "Removed"}[edit]
		fmt.Fprintf(out, "%s %s in %s.", past, name, u.From)
	}
	fmt.Fprintln(out, " Apply it with: systemctl reload gosftpd (or kill -HUP the server).")
	if edit != config.EnableUser && !c.Reload.DisconnectRemovedUsers {
		fmt.Fprintln(out, "Open connections of the user stay until they end; set reload.disconnect_removed_users = true to close them on reload.")
	}
	return nil
}

// keyLines returns the key itself, or the usable lines of a key file.
func keyLines(arg string) ([]string, error) {
	if looksLikeKey(arg) {
		line := strings.TrimSpace(arg)
		if _, warns := auth.ParseAuthorizedKeys([]byte(line), "--key"); len(warns) > 0 {
			return nil, errors.New(warns[0])
		}
		return []string{line}, nil
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		return nil, fmt.Errorf("--key: %w", err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if _, warns := auth.ParseAuthorizedKeys([]byte(line), fmt.Sprintf("%s:%d", arg, n)); len(warns) > 0 {
			return nil, errors.New(warns[0])
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("--key %s: %w", arg, err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("--key %s: no public keys in the file", arg)
	}
	return lines, nil
}

func looksLikeKey(s string) bool {
	s = strings.TrimSpace(s)
	for _, p := range []string{"ssh-", "ecdsa-", "sk-", "from=", "expiry-time=", "restrict", "no-", "cert-authority", "principals=", "command="} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func parseExpires(s string, now time.Time) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("--expires %q: must be in the future", s)
		}
		return now.Add(d).Truncate(time.Second), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("--expires %q: want a duration (72h) or a date (2026-12-31 or RFC 3339)", s)
}

func newUserListCmd() *cobra.Command {
	var (
		file   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the configured users",
		Long: `List the configured users, sorted by name: their access, the number of
their keys, their certificate principals for trusted CAs, whether they have
a password, their expiry and their status (active, expired or disabled).
"off" marks keys, principals or a password that auth.methods leaves out; a
key count ending in "+?" leaves out an authorized_keys_file that could not
be read.

With --json it prints a JSON array instead, one object per user, with the
same information: name, access (mount name to permissions), keys,
keys_unreadable, keys_off, principals, principals_off, password (true or
false), password_off, expires (RFC 3339 in UTC, or null) and status.`,
		Example: `  gosftpd user list
  gosftpd user list --json`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(file, os.Getenv)
			if err != nil {
				return err
			}
			users := listUsers(c, time.Now())
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(users)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "USER\tACCESS\tKEYS\tCERT\tPASSWORD\tEXPIRES\tSTATUS")
			for _, u := range users {
				fmt.Fprintln(w, u.row())
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&file, "config", "", "configuration file (default: the one serve would use)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as a JSON array")
	return cmd
}

// userInfo is a user as user list shows it: a row of the table, and an
// object of the --json array, whose field names stay.
type userInfo struct {
	Name           string            `json:"name"`
	Access         map[string]string `json:"access"`
	Keys           int               `json:"keys"`
	KeysUnreadable bool              `json:"keys_unreadable"`
	KeysOff        bool              `json:"keys_off"`
	Principals     []string          `json:"principals"`
	PrincipalsOff  bool              `json:"principals_off"`
	Password       bool              `json:"password"`
	PasswordOff    bool              `json:"password_off"`
	Expires        *string           `json:"expires"`
	Status         string            `json:"status"`
}

// listUsers returns the users of c, sorted by name.
func listUsers(c *config.Config, now time.Time) []userInfo {
	keysOn, pwOn := c.Auth.HasMethod(auth.MethodPublicKey), c.Auth.HasMethod(auth.MethodPassword)
	users := make([]userInfo, 0, len(c.Users))
	for _, name := range slices.Sorted(maps.Keys(c.Users)) {
		u := c.Users[name]
		info := userInfo{
			Name:       name,
			Access:     maps.Clone(u.Access),
			Keys:       len(u.AuthorizedKeys),
			KeysOff:    !keysOn,
			Principals: c.CertificatePrincipals(name),
			Password:   u.PasswordHash != "",
			Status:     "active",
		}
		if info.Access == nil {
			info.Access = map[string]string{}
		}
		if u.AuthorizedKeysFile != "" {
			data, err := os.ReadFile(u.AuthorizedKeysFile)
			if err != nil {
				info.KeysUnreadable = true
			} else {
				ks, _ := auth.ParseAuthorizedKeys(data, u.AuthorizedKeysFile)
				info.Keys += len(ks)
			}
		}
		if info.Principals == nil {
			info.Principals = []string{}
			info.PrincipalsOff = c.Auth.TrustsCAs() && !keysOn
		}
		info.PasswordOff = info.Password && !pwOn
		if u.Expires != nil {
			s := u.Expires.UTC().Format(time.RFC3339)
			info.Expires = &s
			if u.Expires.Before(now) {
				info.Status = "expired"
			}
		}
		if u.Disabled {
			info.Status = "disabled"
		}
		users = append(users, info)
	}
	return users
}

// row returns the user's row of the table, its columns separated by tabs.
func (u userInfo) row() string {
	access := make([]string, 0, len(u.Access))
	for _, m := range slices.Sorted(maps.Keys(u.Access)) {
		access = append(access, m+"="+u.Access[m])
	}
	keys := strconv.Itoa(u.Keys)
	switch {
	case u.KeysOff:
		keys = "off" // auth.methods
	case u.KeysUnreadable:
		keys += "+?"
	}
	cert := "-" // principals for trusted CAs
	switch {
	case len(u.Principals) > 0:
		cert = strings.Join(u.Principals, ",")
	case u.PrincipalsOff:
		cert = "off"
	}
	password := "-"
	switch {
	case u.PasswordOff:
		password = "off"
	case u.Password:
		password = "yes"
	}
	expires := "-"
	if u.Expires != nil {
		expires = *u.Expires
	}
	return strings.Join([]string{u.Name, strings.Join(access, ", "), keys, cert, password, expires, u.Status}, "\t")
}

func newHashPasswordCmd() *cobra.Command {
	var fromStdin bool
	cmd := &cobra.Command{
		Use:   "hash-password [--stdin]",
		Short: "Print the hash of a password for password_hash",
		Long: `Read a password and print its argon2id hash, for password_hash in a
[users.NAME] table or for user add --password-hash. On a terminal the
password is asked twice without echo; with --stdin the first line of
standard input is used.

Password logins also need auth.methods = ["publickey", "password"].`,
		Example: `  gosftpd user hash-password
  printf '%s\n' "$PASSWORD" | gosftpd user hash-password --stdin`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr(), fromStdin)
			if err != nil {
				return usageError{err}
			}
			h, err := auth.HashPassword(pw)
			if err != nil {
				return usageError{err}
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), h)
			return err
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the password from the first line of standard input")
	return cmd
}

// readPassword reads the first line of in, or asks twice on a terminal.
func readPassword(in io.Reader, prompt io.Writer, fromStdin bool) ([]byte, error) {
	if fromStdin {
		line, err := bufio.NewReader(io.LimitReader(in, auth.MaxPasswordLen+2)).ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		return line, nil
	}
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, errors.New("standard input is not a terminal; pass --stdin to read the password from it")
	}
	ask := func(label string) ([]byte, error) {
		fmt.Fprint(prompt, label)
		pw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(prompt)
		return pw, err
	}
	pw, err := ask("Password: ")
	if err != nil {
		return nil, err
	}
	again, err := ask("Repeat password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pw, again) {
		return nil, errors.New("the passwords do not match")
	}
	return pw, nil
}
