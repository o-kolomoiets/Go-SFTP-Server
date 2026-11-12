// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Check, show and create configuration files",
		Args:  noArgs,
		RunE:  showHelp,
	}
	cmd.AddCommand(newConfigValidateCmd(), newConfigShowCmd(), newConfigExampleCmd())
	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	var (
		file    string
		checkFS bool
	)
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the configuration and print every problem",
		Long: `Check the configuration and print every problem. Exit code 2 means the
configuration is invalid. With --check-fs, also check that mount directories,
host keys (with their next and previous keys and certificates),
authorized_keys files, the trusted CA keys and the revocation list exist
and have safe permissions, and read the keys, as serve does at startup. On
Linux it also prints the warnings serve gives when it applies Landlock:
files that need a restart once they are replaced by rename.`,
		Example: `  gosftpd config validate
  gosftpd config validate --check-fs --config /etc/gosftpd/config.toml`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(file, os.Getenv)
			if err != nil {
				return err
			}
			applyEnv(c, os.Getenv)
			warns, err := checkConfig(c, checkFS)
			if err == nil && checkFS {
				var keyWarns []string
				_, keyWarns, err = c.Authenticator()
				warns = append(warns, keyWarns...)
				if err == nil {
					_, keyWarns, err = loadHostKeys(c.Server.HostKeys, hostKeyOptions{generate: c.Server.HostKeyAutoGenerate, certs: c.Server.HostCertificates, inspect: true})
					warns = append(warns, keyWarns...)
				}
				if err != nil {
					err = configError{err}
				}
				if err == nil {
					// What serve would warn about once it applies
					// Landlock (ADR 0011).
					var llWarns []string
					llWarns, err = previewLandlock(c)
					warns = append(warns, llWarns...)
				}
			}
			for _, w := range warns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: OK (%d mounts, %d users)\n", c.File, len(c.Mounts), len(c.Users))
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "config", "", "configuration file (default: the one serve would use)")
	cmd.Flags().BoolVar(&checkFS, "check-fs", false, "also check paths, keys and file permissions")
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	var (
		file   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration with all defaults",
		Long: `Print the effective configuration, as serve would use it: every key with
its value or default, the users of included files, and what
$GOSFTPD_LISTEN, $GOSFTPD_LOG_LEVEL and $GOSFTPD_LOG_FORMAT override. Exit
code 2 means the configuration is invalid.

With --json, print one JSON object instead, with the path of the file and
these keys under their names in the file: the mounts (path, read_only,
create, on_conflict), server.listen, server.host_keys, auth.methods,
defaults.on_conflict, audit.output and reload.disconnect_removed_users.
It leaves out the users and the hooks, and so every password hash, key and
webhook URL; gosftpd user list --json lists the users. Later versions may
add keys, never remove or rename one.`,
		Example: `  gosftpd config show
  gosftpd config show --json --config /etc/gosftpd/config.toml`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(file, os.Getenv)
			if err != nil {
				return err
			}
			applyEnv(c, os.Getenv)
			if _, err := checkConfig(c, false); err != nil {
				return err
			}
			if asJSON {
				return writeConfigShowJSON(cmd.OutOrStdout(), c)
			}
			data, err := c.Encode()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "# Effective configuration from %s\n", c.File)
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	cmd.Flags().StringVar(&file, "config", "", "configuration file (default: the one serve would use)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the mounts and main settings as JSON, without users")
	return cmd
}

// configShowJSON is what config show --json prints (ADR 0013): the part of
// the effective configuration that the desktop GUI reads, with the names
// and values of the keys that config show prints. Fields may be added
// later, never removed or renamed (the M6 compatibility contract).
//
// The users are left out: user list --json describes them, and so no
// password hash, key or allow_from is printed. The hooks are left out
// too: a webhook URL or an exec argument can hold a token.
type configShowJSON struct {
	File   string `json:"file"`
	Server struct {
		Listen   []string `json:"listen"`
		HostKeys []string `json:"host_keys"`
	} `json:"server"`
	Auth struct {
		Methods []string `json:"methods"`
	} `json:"auth"`
	Defaults struct {
		OnConflict string `json:"on_conflict"`
	} `json:"defaults"`
	Mounts map[string]configShowMount `json:"mounts"`
	Audit  struct {
		Output string `json:"output"`
	} `json:"audit"`
	Reload struct {
		DisconnectRemovedUsers bool `json:"disconnect_removed_users"`
	} `json:"reload"`
}

// configShowMount is a mount of configShowJSON. OnConflict is the mount's
// own value, which is [defaults]' unless the mount sets it.
type configShowMount struct {
	Path       string `json:"path"`
	ReadOnly   bool   `json:"read_only"`
	Create     bool   `json:"create"`
	OnConflict string `json:"on_conflict"`
}

// newConfigShowJSON describes c, which Validate has accepted.
func newConfigShowJSON(c *config.Config) configShowJSON {
	var j configShowJSON
	j.File = c.File
	// Copies that are never nil, so that an empty list is [], not null.
	j.Server.Listen = append([]string{}, c.Server.Listen...)
	j.Server.HostKeys = append([]string{}, c.Server.HostKeys...)
	j.Auth.Methods = append([]string{}, c.Auth.Methods...)
	j.Defaults.OnConflict = c.Defaults.OnConflict
	j.Mounts = make(map[string]configShowMount, len(c.Mounts))
	for name, m := range c.Mounts {
		j.Mounts[name] = configShowMount{Path: m.Path, ReadOnly: m.ReadOnly, Create: m.Create, OnConflict: m.OnConflict}
	}
	j.Audit.Output = c.Audit.Output
	j.Reload.DisconnectRemovedUsers = c.Reload.DisconnectRemovedUsers
	return j
}

// writeConfigShowJSON writes the object of config show --json, indented as
// version --json is, with a newline after it. '&', '<' and '>' in paths
// are written as they are.
func writeConfigShowJSON(w io.Writer, c *config.Config) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(newConfigShowJSON(c))
}

func newConfigExampleCmd() *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "example",
		Short: "Print an example configuration",
		Long: `Print a minimal working configuration, or with --full a reference of every
key with its default value.`,
		Example: `  gosftpd config example > /etc/gosftpd/config.toml`,
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := cmd.OutOrStdout().Write(config.Example(full))
			return err
		},
	}
	cmd.Flags().BoolVar(&full, "full", false, "print the reference of every key")
	return cmd
}
