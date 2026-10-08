// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Prepare and list users",
		Args:  noArgs,
	}
	cmd.AddCommand(newUserAddCmd(), newUserListCmd())
	return cmd
}

type userAddOptions struct {
	keys      []string
	access    []string
	expires   string
	allowFrom []string
}

func newUserAddCmd() *cobra.Command {
	var o userAddOptions
	cmd := &cobra.Command{
		Use:   "add NAME --key FILE|KEY --access MOUNT=PERMISSIONS...",
		Short: "Print a [users.NAME] block to add to the configuration",
		Long: `Print a [users.NAME] block to add to the configuration file (or to a file in
users.d/ if the configuration includes it). Nothing is written to disk.

Permissions are a preset (read, upload, readwrite, full) or a list of flags
(list, read, write, overwrite, delete, rename, mkdir, rmdir, setstat).`,
		Example: `  gosftpd user add partner --key partner.pub --access inbox=upload --expires 720h >> gosftpd.toml
  gosftpd user add alice --key "ssh-ed25519 AAAA... alice@laptop" --access home=full --access public=read`,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return usageError{err}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			block, err := userBlock(args[0], o, time.Now())
			if err != nil {
				return usageError{err}
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), block)
			return err
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.keys, "key", nil, "public key, or a file with public keys (repeatable)")
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
	if len(o.keys) == 0 {
		return "", errors.New("at least one --key is required")
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

	var access []string
	seen := map[string]bool{}
	for _, a := range o.access {
		mount, perm, ok := strings.Cut(a, "=")
		if !ok || !vfs.ValidMountName(mount) {
			return "", fmt.Errorf("--access %q: want MOUNT=PERMISSIONS, e.g. inbox=upload", a)
		}
		if seen[mount] {
			return "", fmt.Errorf("--access: mount %q given twice", mount)
		}
		seen[mount] = true
		if _, err := vfs.ParsePerm(perm); err != nil {
			return "", fmt.Errorf("--access %q: %w", a, err)
		}
		access = append(access, tomlKey(mount)+" = "+tomlString(perm))
	}

	for _, a := range o.allowFrom {
		if _, err := auth.ParsePrefix(a); err != nil {
			return "", fmt.Errorf("--allow-from: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n[users.%s]\n", name)
	fmt.Fprintf(&b, "authorized_keys = %s\n", tomlStrings(keys))
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
	for _, p := range []string{"ssh-", "ecdsa-", "sk-", "from=", "expiry-time=", "restrict", "no-"} {
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
	var file string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the configured users",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(file, os.Getenv)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(c.Users))
			for name := range c.Users {
				names = append(names, name)
			}
			slices.Sort(names)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "USER\tACCESS\tKEYS\tEXPIRES\tSTATUS")
			now := time.Now()
			for _, name := range names {
				u := c.Users[name]
				var access []string
				for _, m := range slices.Sorted(maps.Keys(u.Access)) {
					access = append(access, m+"="+u.Access[m])
				}
				keys := strconv.Itoa(len(u.AuthorizedKeys))
				if u.AuthorizedKeysFile != "" {
					data, err := os.ReadFile(u.AuthorizedKeysFile)
					if err != nil {
						keys += "+?"
					} else {
						ks, _ := auth.ParseAuthorizedKeys(data, u.AuthorizedKeysFile)
						keys = strconv.Itoa(len(u.AuthorizedKeys) + len(ks))
					}
				}
				expires, status := "-", "active"
				if u.Expires != nil {
					expires = u.Expires.UTC().Format(time.RFC3339)
					if u.Expires.Before(now) {
						status = "expired"
					}
				}
				if u.Disabled {
					status = "disabled"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, strings.Join(access, ", "), keys, expires, status)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&file, "config", "", "configuration file (default: the one serve would use)")
	return cmd
}
