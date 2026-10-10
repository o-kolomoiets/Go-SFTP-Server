// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// usersFileMode returns the mode for a file of users next to the
// configuration file cfg: what cfg allows, at most rw for the owner and r
// for the group, so that the checks of CheckFS pass.
func usersFileMode(cfg fs.FileInfo) fs.FileMode {
	return cfg.Mode().Perm()&0o640 | 0o600
}

// usersDirMode is the mode of a new directory for users files: the group
// may list it if it may read the configuration file.
func usersDirMode(cfg fs.FileInfo) fs.FileMode {
	if cfg.Mode().Perm()&0o040 != 0 {
		return 0o750
	}
	return 0o700
}

// writeUsersFile writes data to path through a temporary file in the same
// directory, so that a reload never reads half a file. The file gets mode
// and, where the platform allows, the owner and group of like (the main
// configuration file, or the file it replaces). With exclusive, an existing
// path is an error.
func writeUsersFile(path string, data []byte, mode fs.FileMode, like fs.FileInfo, exclusive bool) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		chownLike(dir, like)
		// Not subject to the umask: the server's group must be able to
		// list the directory, or the include would find nothing.
		if err := os.Chmod(dir, usersDirMode(like)); err != nil {
			return err
		}
	}
	if exclusive {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists", path)
		}
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	// Not *.toml, so that no include pattern picks it up meanwhile.
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(b[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode) // not subject to the umask
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		chownLike(tmp, like)
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// partnerInstructions describes how user name connects: host, port, host
// key fingerprints and the command line, ready to send.
func partnerInstructions(c *config.Config, name, host string) string {
	port := 22
	listenHost := ""
	if len(c.Server.Listen) > 0 {
		if h, p, err := net.SplitHostPort(c.Server.Listen[0]); err == nil {
			listenHost = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
	}
	if host == "" {
		host = listenHost
		if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
			if h, err := os.Hostname(); err == nil && h != "" {
				host = h
			} else {
				host = "<server>"
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Connection details for %s:\n", name)
	fmt.Fprintf(&b, "  host:    %s\n  port:    %d\n  user:    %s\n", host, port, name)
	for _, path := range c.Server.HostKeys {
		key, err := hostPublicKey(path)
		if err != nil {
			fmt.Fprintf(&b, "  host key: unknown (%v); see gosftpd hostkey show --host-key %s\n", err, path)
			continue
		}
		fmt.Fprintf(&b, "  host key: %s %s\n", strings.ToUpper(strings.TrimPrefix(key.Type(), "ssh-")), hostkey.Fingerprint(key))
		fmt.Fprintf(&b, "  known_hosts: %s\n", hostkey.KnownHostsLine(host, port, key))
	}
	portFlag := ""
	if port != 22 {
		portFlag = fmt.Sprintf("-P %d ", port)
	}
	dest := host
	if strings.Contains(host, ":") {
		dest = "[" + host + "]" // an IPv6 address
	}
	fmt.Fprintf(&b, "  connect: sftp %s%s@%s\n", portFlag, name, dest)
	if ps := c.CertificatePrincipals(name); len(ps) > 0 {
		fmt.Fprintf(&b, "  certificate: sign the user's key with a trusted CA, for the principal %s:\n", strings.Join(ps, " or "))
		fmt.Fprintf(&b, "    ssh-keygen -s CA_KEY -I %s -n %s -V +52w id_ed25519.pub\n", name, ps[0])
	}
	fmt.Fprintln(&b, "Check the host key fingerprint on the first connection.")
	return b.String()
}

// hostPublicKey reads the public part of a host key: from the private key,
// or, if that is not readable by this user, from "<path>.pub".
func hostPublicKey(path string) (ssh.PublicKey, error) {
	if s, err := hostkey.Load(path); err == nil {
		return s.PublicKey(), nil
	}
	data, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return key, err
}
