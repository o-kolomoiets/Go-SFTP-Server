// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"os"
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
		Short: "Inspect host keys",
		Args:  noArgs,
	}
	cmd.AddCommand(newHostkeyShowCmd())
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
					cfg, err := os.UserConfigDir()
					if err != nil {
						return configError{err}
					}
					stateDir = filepath.Join(cfg, "gosftpd")
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
