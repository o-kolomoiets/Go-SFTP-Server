// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

func newHostkeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hostkey",
		Short: "Create and inspect host keys",
		Args:  noArgs,
		RunE:  showHelp,
	}
	cmd.AddCommand(newHostkeyShowCmd(), newHostkeyGenerateCmd())
	return cmd
}

func newHostkeyGenerateCmd() *cobra.Command {
	var typ, out string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Create a new host key (never overwrites an existing one)",
		Example: `  gosftpd hostkey generate
  gosftpd hostkey generate --type ecdsa --out /var/lib/gosftpd/ssh_host_ecdsa_key`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				dir, err := defaultStateDir()
				if err != nil {
					return configError{err}
				}
				out = filepath.Join(dir, "ssh_host_"+typ+"_key")
			}
			k, err := hostkey.GenerateType(out, typ)
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					return configError{fmt.Errorf("%s already exists; remove it first to replace the key", out)}
				}
				return configError{err}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", hostkey.Fingerprint(k.PublicKey()), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", hostkey.TypeED25519, "key type: ed25519, ecdsa (P-256) or rsa (3072 bits)")
	cmd.Flags().StringVar(&out, "out", "", "private key file to create (default <user config dir>/gosftpd/ssh_host_TYPE_key)")
	return cmd
}

func newHostkeyShowCmd() *cobra.Command {
	var path, stateDir, knownHosts string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the host key fingerprint and public key",
		Example: `  gosftpd hostkey show
  gosftpd hostkey show --known-hosts sftp.example.org:2022`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				if stateDir == "" {
					var err error
					if stateDir, err = defaultStateDir(); err != nil {
						return configError{err}
					}
				}
				path = filepath.Join(stateDir, hostkey.DefaultFile)
			}
			k, err := hostkey.Load(path)
			if err != nil {
				return configError{err}
			}
			pub := k.PublicKey()
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s %s\n", hostkey.Fingerprint(pub), path)
			fmt.Fprint(w, string(ssh.MarshalAuthorizedKey(pub)))
			if knownHosts != "" {
				host, port, err := splitHostPort(knownHosts)
				if err != nil {
					return usageError{err}
				}
				fmt.Fprintln(w, hostkey.KnownHostsLine(host, port, pub))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "host-key", "", "host private key file (default: the one in the state directory)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "state directory (default <user config dir>/gosftpd)")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "also print a known_hosts line for HOST:PORT")
	return cmd
}

func splitHostPort(s string) (string, int, error) {
	if !strings.Contains(s, ":") {
		return s, 22, nil
	}
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("--known-hosts: %w", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("--known-hosts: invalid port %q", p)
	}
	return host, port, nil
}
