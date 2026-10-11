// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

func newHostkeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hostkey",
		Short: "Create, inspect and rotate host keys",
		Args:  noArgs,
		RunE:  showHelp,
	}
	cmd.AddCommand(newHostkeyShowCmd(), newHostkeyGenerateCmd(), newHostkeyRotateCmd())
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
	var sel keySelection
	var knownHosts string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the host key fingerprints and public keys",
		Long: `Print the fingerprint and public key of a host key, with its next and
previous keys and their certificates when there are any (ADR 0008). The
first lines describe the current key: fingerprint and path, public key and,
with --known-hosts, its known_hosts line. With --config, print every
configured host key. Public keys are read from the ".pub" files when the
private keys are not readable.`,
		Example: `  gosftpd hostkey show
  gosftpd hostkey show --config /etc/gosftpd/config.toml --known-hosts sftp.example.org:2022`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var (
				host string
				port int
			)
			if knownHosts != "" {
				var err error
				if host, port, err = splitHostPort(knownHosts); err != nil {
					return usageError{err}
				}
			}
			paths, c, err := sel.resolve(false)
			if err != nil {
				return err
			}
			o := hostKeyOptions{lenient: true, inspect: true, certsIfPresent: true}
			if c != nil {
				o.certs, o.generate = c.Server.HostCertificates, c.Server.HostKeyAutoGenerate
			}
			off := c != nil && !c.Server.HostCertificates
			keys, warns, err := loadHostKeys(paths, o)
			for _, w := range warns {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning:", w)
			}
			if err != nil {
				return configError{err}
			}
			w := cmd.OutOrStdout()
			if len(keys) == 0 {
				fmt.Fprintln(w, "no host key yet: gosftpd serve creates it at start (host_key_auto_generate)")
			}
			for i, k := range keys {
				if i > 0 {
					fmt.Fprintln(w)
				}
				showKey(w, "", &k.cur, host, port, off)
				if k.next != nil {
					showKey(w, "next ", k.next, host, port, off)
				}
				if k.old != nil {
					showKey(w, "previous ", k.old, host, port, off)
				}
			}
			return nil
		},
	}
	sel.flags(cmd)
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "also print known_hosts lines for HOST:PORT")
	return cmd
}

// showKey prints a key file: fingerprint and path, public key, known_hosts
// line and certificate. off says that certificates are not served.
func showKey(w io.Writer, role string, kf *hostKeyFile, host string, port int, off bool) {
	note, certNote := "", ""
	switch role {
	case "next ":
		note = " (next key: announced; used for key exchange after rotate --finish)"
		certNote = " (served after rotate --finish)"
	case "previous ":
		note = " (previous key: announced until rotate --retire)"
		certNote = " (not served)"
	}
	if off {
		certNote = " (not served: server.host_certificates is off)"
	}
	fmt.Fprintf(w, "%s %s%s\n", hostkey.Fingerprint(kf.pub), kf.path, note)
	fmt.Fprint(w, string(ssh.MarshalAuthorizedKey(kf.pub)))
	if host != "" {
		fmt.Fprintln(w, hostkey.KnownHostsLine(host, port, kf.pub))
	}
	if kf.cert != nil {
		fmt.Fprintf(w, "%scertificate %s%s: %s\n", role, hostkey.Cert(kf.path), certNote, describeCert(kf.cert))
		if host != "" {
			fmt.Fprintf(w, "@cert-authority %s", hostkey.KnownHostsLine(host, port, kf.cert.SignatureKey)+"\n")
		}
	}
}

// keySelection selects host keys: --config, --host-key or --state-dir.
type keySelection struct {
	path, stateDir, file string
}

func (s *keySelection) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&s.path, "host-key", "", "host private key file (default: the one in the state directory)")
	cmd.Flags().StringVar(&s.stateDir, "state-dir", "", "state directory (default <user config dir>/gosftpd)")
	cmd.Flags().StringVar(&s.file, "config", "", "configuration file: its host keys (with --host-key, one of them)")
}

// resolve returns the selected host key files and, with --config, the
// configuration. With one, it requires exactly one key.
func (s *keySelection) resolve(one bool) ([]string, *config.Config, error) {
	if s.file == "" {
		if s.path != "" {
			return []string{absPath(s.path)}, nil, nil
		}
		dir := s.stateDir
		if dir == "" {
			var err error
			if dir, err = defaultStateDir(); err != nil {
				return nil, nil, configError{err}
			}
		}
		return []string{filepath.Join(absPath(dir), hostkey.DefaultFile)}, nil, nil
	}
	if s.stateDir != "" {
		return nil, nil, usageError{errors.New("--state-dir and --config cannot be used together")}
	}
	c, err := loadConfig(s.file, os.Getenv)
	if err != nil {
		return nil, nil, err
	}
	paths := c.Server.HostKeys
	if s.path != "" {
		p := absPath(s.path)
		if !slices.Contains(paths, p) {
			return nil, nil, usageError{fmt.Errorf("%s is not one of the host keys of %s (%s)", p, c.File, strings.Join(paths, ", "))}
		}
		paths = []string{p}
	}
	switch {
	case len(paths) == 0:
		return nil, nil, configError{fmt.Errorf("%s configures no host keys", c.File)}
	case one && len(paths) > 1:
		return nil, nil, usageError{fmt.Errorf("%s configures %d host keys; choose one with --host-key: %s", c.File, len(paths), strings.Join(paths, ", "))}
	}
	return paths, c, nil
}

func newHostkeyRotateCmd() *cobra.Command {
	var (
		sel                             keySelection
		typ, knownHosts                 string
		finish, rollback, retire, abort bool
	)
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Replace a host key in steps, without breaking clients",
		Long: `Replace a host key P in steps, so that OpenSSH clients learn the new key
before it is used (ADR 0008). Reload gosftpd after each step (systemctl
reload gosftpd, or kill -HUP).

  rotate            create the next key, P.next: announced to clients after
                    login, not used for key exchange yet
  rotate --finish   after the transition period: P.next becomes P; the
                    previous key is kept as P.old and stays announced
  rotate --retire   delete P.old: clients then forget it

rotate --rollback undoes --finish (before --retire); rotate --abort deletes
P.next. Run it as the owner of P or as root. Servers reached under one name
must announce the same keys: create P.next once and copy it, with
P.next.pub, to each of them.`,
		Example: `  gosftpd hostkey rotate --config /etc/gosftpd/config.toml
  gosftpd hostkey rotate --finish --host-key /var/lib/gosftpd/ssh_host_ed25519_key`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			steps := 0
			for _, on := range []bool{finish, rollback, retire, abort} {
				if on {
					steps++
				}
			}
			if steps > 1 {
				return usageError{errors.New("--finish, --rollback, --retire and --abort cannot be combined")}
			}
			if typ != "" && steps > 0 {
				return usageError{errors.New("--type only applies when a rotation starts")}
			}
			var (
				host string
				port int
			)
			if knownHosts != "" {
				var err error
				if host, port, err = splitHostPort(knownHosts); err != nil {
					return usageError{err}
				}
			}
			paths, c, err := sel.resolve(true)
			if err != nil {
				return err
			}
			p := paths[0]
			w := cmd.OutOrStdout()
			again := func(step string) string { return "gosftpd hostkey rotate " + step + " --host-key " + commandArg(p) }
			prepare, err := keyOwner(p)
			if err != nil {
				return configError{err}
			}
			// The files that a step changed besides the keys, and what
			// it reports, also when it fails.
			report := func(changes []string, err error) error {
				for _, ch := range changes {
					fmt.Fprintln(w, ch)
				}
				if err != nil {
					return configError{err}
				}
				return nil
			}
			switch {
			case abort:
				if err := report(hostkey.AbortRotation(p, prepare)); err != nil {
					return err
				}
				fmt.Fprintf(w, "deleted the next key %s\nreload gosftpd to stop announcing it\n", hostkey.Next(p))
				return nil
			case retire:
				if err := report(hostkey.RetireRotation(p, prepare)); err != nil {
					return err
				}
				fmt.Fprintf(w, "deleted the previous key %s\nreload gosftpd: OpenSSH clients forget it at their next login\n", hostkey.Old(p))
				return nil
			case rollback:
				// The previous key's certificate becomes P's (the file is
				// written anew); a bad one does not block going back.
				hadOld := false
				if old, err := hostkey.Load(hostkey.Old(p)); err == nil {
					hadOld = true
					if _, err := os.Stat(hostkey.Cert(hostkey.Old(p))); err == nil {
						if _, err := hostkey.LoadCertificate(hostkey.Cert(hostkey.Old(p)), old.PublicKey()); err != nil {
							fmt.Fprintf(w, "warning: host certificate %v; the server will not serve it\n", err)
						}
					}
				}
				if err := report(hostkey.RollbackRotation(p, prepare)); err != nil {
					return err
				}
				if !hadOld {
					fmt.Fprintf(w, "there is no previous key: %s is the host key and %s the next key, as after a rollback\n", p, hostkey.Next(p))
				} else {
					fmt.Fprintf(w, "%s is the host key again; the newer key is the next key %s\n", p, hostkey.Next(p))
				}
				fmt.Fprintln(w, "reload gosftpd: both stay announced")
				return nil
			case finish:
				if err := checkFinish(p, c, w); err != nil {
					return configError{err}
				}
				f, err := hostkey.FinishRotation(p, prepare)
				if err != nil {
					return configError{err}
				}
				printFinished(w, p, f, c, again)
				return nil
			}
			if typ != "" && c != nil {
				if err := typeTaken(c, p, typ); err != nil {
					return configError{err}
				}
			}
			k, changes, err := hostkey.StartRotation(p, typ, prepare)
			if err != nil {
				if errors.Is(err, fs.ErrExist) {
					err = fmt.Errorf("%s already exists", hostkey.Next(p))
				}
				return report(changes, err)
			}
			_ = report(changes, nil)
			printStarted(w, p, k.PublicKey(), c, host, port, again)
			return nil
		},
	}
	sel.flags(cmd)
	cmd.Flags().StringVar(&typ, "type", "", "type of the new key: ed25519, ecdsa (P-256) or rsa (3072 bits); default: the type of the current key")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "also print the known_hosts line of the new key for HOST:PORT")
	cmd.Flags().BoolVar(&finish, "finish", false, "make the next key the host key")
	cmd.Flags().BoolVar(&rollback, "rollback", false, "undo --finish")
	cmd.Flags().BoolVar(&retire, "retire", false, "delete the previous key")
	cmd.Flags().BoolVar(&abort, "abort", false, "delete the next key")
	return cmd
}

// checkFinish checks the next key before it becomes P, as the server will
// load it: owner, type and certificate. As root it first gives the key P's
// owner.
func checkFinish(p string, c *config.Config, w io.Writer) error {
	next := hostkey.Next(p)
	key, err := hostkey.Load(next)
	if err != nil {
		return nil //nolint:nilerr // FinishRotation reports it, or completes an interrupted finish
	}
	if err := chownKeyLike(next, p); err != nil {
		return err
	}
	if err := sameOwner(next, p, false); err != nil {
		return err
	}
	if c != nil {
		for _, other := range c.Server.HostKeys {
			if other == p {
				continue
			}
			if k, err := hostPublicKey(other); err == nil && k.Type() == key.PublicKey().Type() {
				return fmt.Errorf("%s is of type %s, like the host key %s: only one of them would be used", next, k.Type(), other)
			}
		}
	}
	if err := checkCertFile(next, key.PublicKey(), p); err != nil {
		if c != nil && !c.Server.HostCertificates {
			fmt.Fprintf(w, "warning: %v\n", err)
			return nil
		}
		return fmt.Errorf("%w; fix or remove it first", err)
	}
	return nil
}

// checkCertFile checks the certificate of key file f, which holds key, if
// there is one, as the server will: its owner (root or like's), its mode
// and its content.
func checkCertFile(f string, key ssh.PublicKey, like string) error {
	cf := hostkey.Cert(f)
	fi, err := os.Stat(cf)
	if err != nil {
		return nil //nolint:nilerr // no certificate
	}
	if fi.Mode().Perm()&0o022 != 0 && runtime.GOOS != "windows" {
		return fmt.Errorf("host certificate %s is writable by group or others", cf)
	}
	if err := sameOwner(cf, like, true); err != nil {
		return err
	}
	if _, err := hostkey.LoadCertificate(cf, key); err != nil {
		return fmt.Errorf("host certificate %w", err)
	}
	return nil
}

// typeTaken refuses a new key of a type that another configured host key,
// or its next key, has: x/crypto would use only one of them.
func typeTaken(c *config.Config, p, typ string) error {
	want := map[string]string{hostkey.TypeED25519: ssh.KeyAlgoED25519, hostkey.TypeECDSA: ssh.KeyAlgoECDSA256, hostkey.TypeRSA: ssh.KeyAlgoRSA}[typ]
	for _, other := range c.Server.HostKeys {
		if other == p {
			continue
		}
		for _, f := range []string{other, hostkey.Next(other)} {
			if key, err := hostPublicKey(f); err == nil && key.Type() == want {
				return fmt.Errorf("host key %s is already of type %s; to stop using a key type, remove its key from server.host_keys instead", f, typ)
			}
		}
	}
	return nil
}

func printStarted(w io.Writer, p string, key ssh.PublicKey, c *config.Config, host string, port int, again func(string) string) {
	fmt.Fprintf(w, "created the next host key %s\n", hostkey.Next(p))
	fmt.Fprintf(w, "  %s\n", keyLabel(key))
	if host != "" {
		fmt.Fprintf(w, "  known_hosts: %s\n", hostkey.KnownHostsLine(host, port, key))
	}
	if cert, err := readCertificate(hostkey.Cert(p)); err == nil {
		fmt.Fprintln(w, "certify it like the current key:")
		fmt.Fprintf(w, "  ssh-keygen -s CA_KEY -h -I %s -n %s -V -5m:+52w %s\n", commandArg(cert.KeyId), commandArg(strings.Join(cert.ValidPrincipals, ",")), commandArg(hostkey.Next(p)+".pub"))
	} else if c != nil && c.Server.HostCertificates {
		fmt.Fprintln(w, "certify it:")
		fmt.Fprintf(w, "  ssh-keygen -s CA_KEY -h -I KEY_ID -n HOST_NAMES -V -5m:+52w %s\n", commandArg(hostkey.Next(p)+".pub"))
	}
	fmt.Fprintln(w, "next steps:")
	if c != nil && !c.Server.AnnounceHostKeys {
		fmt.Fprintln(w, "  1. server.announce_host_keys is off: no client learns the key by itself; turn it on, or")
		fmt.Fprintln(w, "  2. give the fingerprint or known_hosts line to every user before the cutover")
		fmt.Fprintf(w, "  3. then run %s, and reload\n", again("--finish"))
		return
	}
	fmt.Fprintln(w, "  1. reload gosftpd (systemctl reload gosftpd, or kill -HUP): OpenSSH clients learn the key at their next login")
	fmt.Fprintln(w, "  2. give the fingerprint to users of other clients (PuTTY, WinSCP, FileZilla, paramiko, rclone)")
	fmt.Fprintf(w, "  3. once clients have it (audit event conn.hostkeys_proved), run %s, and reload\n", again("--finish"))
}

// commandArg quotes s for a command line the user copies: for a POSIX
// shell, or in double quotes on Windows when it needs any.
func commandArg(s string) string {
	if runtime.GOOS != "windows" {
		return shellQuote(s)
	}
	if s == "" || strings.ContainsAny(s, " \t&()[]{}^=;!'+,`~%") {
		return `"` + s + `"`
	}
	return s
}

func printFinished(w io.Writer, p string, f *hostkey.Finished, c *config.Config, again func(string) string) {
	for _, ch := range f.Changes {
		fmt.Fprintln(w, ch)
	}
	announced := c == nil || c.Server.AnnounceHostKeys
	switch {
	case f.Age > 0 && announced:
		fmt.Fprintf(w, "the next key replaced %s; it was announced for up to %s\n", p, f.Age.Round(time.Minute))
	case f.Age > 0:
		fmt.Fprintf(w, "the next key replaced %s\n", p)
	default:
		fmt.Fprintf(w, "completed the rotation of %s\n", p)
	}
	fmt.Fprintf(w, "  host key: %s\n", keyLabel(f.New.PublicKey()))
	fmt.Fprintf(w, "  previous key: %s, kept as %s\n", keyLabel(f.Old.PublicKey()), hostkey.Old(p))
	if !f.Certified && (exists(hostkey.Cert(hostkey.Old(p))) || c != nil && c.Server.HostCertificates) {
		fmt.Fprintf(w, "warning: the new key has no certificate (%s); clients that trust only the CA cannot verify it\n", hostkey.Cert(p))
	}
	fmt.Fprintln(w, "next steps:")
	if !announced {
		fmt.Fprintln(w, "  1. reload gosftpd: the new key is used for key exchange; clients that do not have it see a changed host key")
		fmt.Fprintf(w, "  2. if something goes wrong: %s, and reload\n", again("--rollback"))
		fmt.Fprintf(w, "  3. later: %s, and reload\n", again("--retire"))
		return
	}
	fmt.Fprintln(w, "  1. reload gosftpd: the new key is used for key exchange; the previous key stays announced")
	fmt.Fprintf(w, "  2. if something goes wrong: %s, and reload\n", again("--rollback"))
	fmt.Fprintf(w, "  3. later: %s, and reload; OpenSSH clients then forget the previous key\n", again("--retire"))
}

// readCertificate reads a certificate file without checking it.
func readCertificate(path string) (*ssh.Certificate, error) {
	key, err := readPublicKey(path)
	if err != nil {
		return nil, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return cert, nil
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
