// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
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
}

func newInitCmd() *cobra.Command {
	var o initOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a configuration file and a host key",
		Long: `Create a commented configuration file (./gosftpd.toml by default, which
gosftpd serve finds on its own) and a host key. Existing files are not
overwritten without --force.

Without --dir the configuration serves ./share (created on first start).
The user from --user (default: your login name) gets full access with the
keys from --authorized-keys (default: ~/.ssh/authorized_keys, if it exists).`,
		Example: `  gosftpd init
  gosftpd init --user alice --dir inbox=/srv/sftp/inbox --out /etc/gosftpd/config.toml`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd.OutOrStdout(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.out, "out", config.LocalFile, "configuration file to write")
	f.StringVar(&o.user, "user", "", "user name (default: your login name)")
	f.StringVar(&o.authorizedKeys, "authorized-keys", "", "authorized_keys file for the user (default ~/.ssh/authorized_keys)")
	f.StringArrayVar(&o.dirs, "dir", nil, "directory to serve, as PATH or NAME=PATH (repeatable; default ./share)")
	f.BoolVar(&o.force, "force", false, "overwrite an existing configuration file")
	return cmd
}

func runInit(w io.Writer, o initOptions) error {
	name := o.user
	if name == "" {
		name = defaultUserName()
	}
	if !auth.ValidUserName(name) {
		return usageError{fmt.Errorf("--user %q: use lowercase letters, digits, '.', '_' and '-' (max 32)", name)}
	}
	if len(o.dirs) == 0 {
		o.dirs = []string{"share"}
	}
	type mount struct{ name, path string }
	var mounts []mount
	seen := map[string]bool{}
	for _, d := range o.dirs {
		n, p, ok := strings.Cut(d, "=")
		if !ok || !vfs.ValidMountName(n) {
			n, p = "", d
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return usageError{fmt.Errorf("--dir %q: %w", d, err)}
		}
		if n == "" {
			n = filepath.Base(abs)
		}
		switch {
		case !vfs.ValidMountName(n):
			return usageError{fmt.Errorf("--dir %q: %q is not a valid mount name; name it with --dir NAME=PATH (letters, digits, '.', '_', '-', spaces)", d, n)}
		case seen[strings.ToLower(n)]:
			return usageError{fmt.Errorf("--dir %q: the mount name %q is used twice; name them with --dir NAME=PATH", d, n)}
		}
		seen[strings.ToLower(n)] = true
		mounts = append(mounts, mount{n, abs})
	}

	keysFile := o.authorizedKeys
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
	}

	stateDir, err := defaultStateDir()
	if err != nil {
		return configError{err}
	}
	keyPath := filepath.Join(stateDir, hostkey.DefaultFile)

	var b strings.Builder
	fmt.Fprintf(&b, "# gosftpd configuration, created by gosftpd init.\n")
	fmt.Fprintf(&b, "# Reference of every key: gosftpd config example --full\n")
	fmt.Fprintf(&b, "# Check it with: gosftpd config validate --check-fs\n")
	fmt.Fprintf(&b, "config_version = %d\n\n", config.Version)
	fmt.Fprintf(&b, "[server]\nlisten = [\":2022\"]\n")
	fmt.Fprintf(&b, "host_keys = %s\n", tomlStrings([]string{keyPath}))
	fmt.Fprintf(&b, "host_key_auto_generate = true\n\n")
	fmt.Fprintf(&b, "[defaults]\non_conflict = \"rename\"  # rename | reject | overwrite\n")
	var access []string
	for _, m := range mounts {
		fmt.Fprintf(&b, "\n[mounts.%s]\npath = %s\ncreate = true\n", tomlKey(m.name), tomlString(m.path))
		access = append(access, tomlKey(m.name)+" = \"full\"")
	}
	fmt.Fprintf(&b, "\n# Add users with: gosftpd user add NAME --key FILE --access MOUNT=upload\n")
	fmt.Fprintf(&b, "[users.%s]\n", tomlKey(name))
	if keysFile != "" {
		fmt.Fprintf(&b, "authorized_keys_file = %s\n", tomlString(keysFile))
	} else {
		fmt.Fprintf(&b, "authorized_keys = [\"<paste your public key, e.g. ~/.ssh/id_ed25519.pub>\"]\n")
	}
	fmt.Fprintf(&b, "access = { %s }\n\n", strings.Join(access, ", "))
	fmt.Fprintf(&b, "[audit]\noutput = \"stdout\"\n")

	if err := writeNew(o.out, []byte(b.String()), o.force); err != nil {
		return err
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
	fmt.Fprintf(w, "  user %s, full access to %d mount(s)\n", name, len(mounts))
	for _, m := range mounts {
		fmt.Fprintf(w, "  mount %s -> %s\n", m.name, m.path)
	}
	fmt.Fprintf(w, "Host key (%s): %s\n  %s\n", state, keyPath, hostkey.Fingerprint(k.PublicKey()))
	if keysFile == "" {
		fmt.Fprintf(w, "\nNo authorized_keys found: paste your public key into %s first.\n", o.out)
	}
	fmt.Fprintf(w, "\nNext steps:\n")
	fmt.Fprintf(w, "  gosftpd user add NAME --key FILE --access %s=upload >> %s\n", mounts[0].name, o.out)
	fmt.Fprintf(w, "  gosftpd config validate --check-fs\n")
	fmt.Fprintf(w, "  gosftpd serve\n")
	return nil
}

// writeNew writes a 0600 file, refusing to replace an existing one unless
// force is set.
func writeNew(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return usageError{fmt.Errorf("%s already exists; use --force to overwrite it", path)}
	}
	if err != nil {
		return err
	}
	// 0600 regardless of the umask or of an existing file's mode: the
	// permission check of serve refuses group-writable configuration.
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
