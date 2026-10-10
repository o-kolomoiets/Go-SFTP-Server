// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
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
and have safe permissions, and read the keys, as serve does at startup.`,
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
	var file string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration with all defaults",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(file, os.Getenv)
			if err != nil {
				return err
			}
			applyEnv(c, os.Getenv)
			if _, err := checkConfig(c, false); err != nil {
				return err
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
	return cmd
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
