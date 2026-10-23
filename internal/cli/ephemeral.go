// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// serve --ephemeral (ADR 0012): a throwaway server for tests. It makes a
// directory of its own, DIR, with os.MkdirTemp, which holds the client key
// and, without --dir, the data in DIR/data; one user, test, logs in with a
// random password or that key; the host key lives only in memory. Once it
// serves, one JSON line on stdout gives the connection details. At exit it
// deletes the key and DIR/data.
const (
	ephemeralUser    = "test"
	ephemeralListen  = "127.0.0.1:0"
	ephemeralKey     = "id_ed25519"
	ephemeralData    = "data"
	ephemeralPattern = "gosftpd-ephemeral-"
	// ephemeralPasswordBytes random bytes make the password, base64url.
	ephemeralPasswordBytes = 24
	// ephemeralNoReload is why SIGHUP changes nothing.
	ephemeralNoReload = "serve --ephemeral does not reload: a new configuration would change the password, the client key and the host key"
)

// ephemeralConflicts are the flags that --ephemeral cannot be used with:
// it makes the user, the keys and the configuration itself.
var ephemeralConflicts = []string{"config", "users-conf", "authorized-keys", "user", "host-key", "state-dir"}

// ephemeral is a running serve --ephemeral.
type ephemeral struct {
	dir  string   // DIR
	root *os.Root // DIR, through which the key and the data are removed
	// held is DIR held open for its Landlock rule, which lets gosftpd
	// remove the key and the data (sandbox.Options.Ephemeral).
	held     *os.File
	heldInfo sandbox.MountDir
	data     string // the data directory: DIR/data, or --dir
	ownData  bool   // data is DIR/data, deleted at exit
	password string
	hostKey  ssh.Signer
	// warnings are logged once the logger exists.
	warnings []string
	log      *slog.Logger // set once it exists
	// landlocked is set when Landlock was applied: DIR itself then
	// stays.
	landlocked bool
}

// newEphemeral checks the flags of serve --ephemeral and makes DIR, the
// client key, the password, the host key and the configuration. Wrong
// flags create nothing; any later error removes DIR again.
func newEphemeral(flags *pflag.FlagSet, o serveOptions, getenv func(string) string) (_ *config.Config, _ *ephemeral, err error) {
	if err := checkEphemeralFlags(flags, o); err != nil {
		return nil, nil, err
	}
	if err := checkFlagValues(flags, o); err != nil {
		return nil, nil, err
	}
	var data *vfs.MountSpec
	if len(o.dirs) == 1 {
		specs, err := parseDirs(o.dirs, false)
		if err != nil {
			return nil, nil, usageError{err}
		}
		data = &specs[0]
	}

	dir, err := os.MkdirTemp("", ephemeralPattern)
	if err != nil {
		return nil, nil, fmt.Errorf("--ephemeral: %w", err)
	}
	e := &ephemeral{dir: absPath(dir)}
	defer func() {
		if err != nil {
			e.discard()
		}
	}()
	if e.root, err = os.OpenRoot(e.dir); err != nil {
		return nil, nil, err
	}
	if e.held, err = e.root.Open("."); err != nil {
		return nil, nil, err
	}
	if e.heldInfo, err = sandbox.HeldDir(e.held); err != nil {
		return nil, nil, err
	}
	clientKey, err := e.writeClientKey()
	if err != nil {
		return nil, nil, err
	}
	hash, err := e.newPassword()
	if err != nil {
		return nil, nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if e.hostKey, err = ssh.NewSignerFromKey(priv); err != nil {
		return nil, nil, err
	}
	if data == nil {
		if err := e.root.Mkdir(ephemeralData, 0o700); err != nil {
			return nil, nil, err
		}
		data = &vfs.MountSpec{Name: ephemeralData, Path: filepath.Join(e.dir, ephemeralData)}
		e.ownData = true
	}
	e.data = data.Path

	c := config.Default()
	c.EphemeralDir = e.dir
	c.Auth.Methods = []string{auth.MethodPublicKey, auth.MethodPassword}
	c.Defaults.OnConflict = o.onConflict
	c.AddMount(data.Name, data.Path).ReadOnly = o.readOnly
	c.Users[ephemeralUser] = &config.User{
		AuthorizedKeys: []string{clientKey},
		PasswordHash:   hash,
		Access:         map[string]string{data.Name: "full"},
	}
	applyOverrides(c, flags, o, getenv)
	// The details describe exactly this one listener.
	c.Server.Listen = []string{ephemeralListen}
	if flags.Changed("listen") {
		c.Server.Listen = []string{o.listen}
	}
	if getenv(config.EnvConfig) != "" {
		e.warnings = append(e.warnings, "$"+config.EnvConfig+" is ignored with --ephemeral, which uses no configuration file")
	}
	if getenv(config.EnvListen) != "" {
		e.warnings = append(e.warnings, "$"+config.EnvListen+" is ignored with --ephemeral, which listens on --listen, by default "+ephemeralListen)
	}
	return c, e, nil
}

// checkEphemeralFlags refuses the flags that --ephemeral replaces, a
// second --dir or --listen, and the audit log on stdout.
func checkEphemeralFlags(flags *pflag.FlagSet, o serveOptions) error {
	for _, name := range ephemeralConflicts {
		if flags.Changed(name) {
			return usageError{fmt.Errorf("--ephemeral and --%s cannot be used together", name)}
		}
	}
	switch {
	case len(o.dirs) > 1:
		return usageError{errors.New("--ephemeral serves one directory: give --dir once")}
	case o.listenCount > 1:
		return usageError{errors.New("--ephemeral describes one listener: give --listen once")}
	case flags.Changed("audit-output") && isStdout(o.auditOutput):
		return usageError{errors.New("--audit-output stdout cannot be used with --ephemeral, whose stdout carries only the connection details; the audit log goes to stderr, or to a file you name")}
	}
	return nil
}

// writeClientKey writes a new ed25519 client key, 0600, as DIR/id_ed25519
// in OpenSSH's format, and returns its authorized_keys line.
func (e *ephemeral) writeClientKey() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "gosftpd --ephemeral")
	if err != nil {
		return "", err
	}
	f, err := e.root.OpenFile(ephemeralKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(pem.EncodeToMemory(block))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// newPassword sets a random password and returns its argon2id hash, which
// only memory holds.
func (e *ephemeral) newPassword() (string, error) {
	b := make([]byte, ephemeralPasswordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	e.password = base64.RawURLEncoding.EncodeToString(b)
	return auth.HashPassword([]byte(e.password))
}

// hostKeys returns the host key, which has no file.
func (e *ephemeral) hostKeys() hostKeys {
	return hostKeys{{cur: hostKeyFile{signer: e.hostKey, pub: e.hostKey.PublicKey(), generated: true}}}
}

// heldDir returns DIR as held open for the sandbox step; nil without
// --ephemeral.
func (e *ephemeral) heldDir() *sandbox.MountDir {
	if e == nil {
		return nil
	}
	return &e.heldInfo
}

// ephemeralDetails is the line serve --ephemeral prints. Fields may be
// added later, never removed or renamed (the M6 compatibility contract).
type ephemeralDetails struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	User               string `json:"user"`
	Password           string `json:"password"`
	PrivateKeyPath     string `json:"private_key_path"`
	Dir                string `json:"dir"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	KnownHosts         string `json:"known_hosts"`
	PID                int    `json:"pid"`
	Version            string `json:"version"`
}

// details describes the server listening on addr.
func (e *ephemeral) details(addr net.Addr) ephemeralDetails {
	host, port := detailsHost(addr)
	pub := e.hostKey.PublicKey()
	return ephemeralDetails{
		Host:               host,
		Port:               port,
		User:               ephemeralUser,
		Password:           e.password,
		PrivateKeyPath:     filepath.Join(e.dir, ephemeralKey),
		Dir:                e.data,
		HostKeyFingerprint: hostkey.Fingerprint(pub),
		KnownHosts:         hostkey.KnownHostsLine(host, port, pub),
		PID:                os.Getpid(),
		Version:            version.Get().Version,
	}
}

// detailsHost returns the host and port of the details: the listener's,
// with 127.0.0.1 for an unspecified address.
func detailsHost(addr net.Addr) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr.String())
	port, _ := strconv.Atoi(portStr)
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
		return "127.0.0.1", port
	}
	return host, port
}

// announce writes the details of the server listening on addr to w, as one
// line in one write.
func (e *ephemeral) announce(w io.Writer, addr net.Addr) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b) // a newline after the object
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e.details(addr)); err != nil { //nolint:gosec // G117: the password is in the line by design, for the test that started gosftpd
		return err
	}
	if _, err := w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("writing the connection details: %w", err)
	}
	return nil
}

// remove deletes, once the server has stopped, the client key and, unless
// --dir named it, the data directory, through DIR held open; then DIR,
// without Landlock. Under Landlock DIR stays, empty: removing it would
// need remove_dir on $TMPDIR (ADR 0012).
func (e *ephemeral) remove(ctx context.Context) error {
	var errs []error
	if err := e.root.Remove(ephemeralKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	if e.ownData {
		if err := e.root.RemoveAll(ephemeralData); err != nil {
			errs = append(errs, err)
		}
	}
	_ = e.held.Close()
	_ = e.root.Close()
	if len(errs) == 0 && !e.landlocked {
		if err := os.Remove(e.dir); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("--ephemeral: cleaning up %s: %w", e.dir, err)
	}
	if e.log != nil {
		if e.landlocked {
			e.log.InfoContext(ctx, "removed the client key and the data; under Landlock the empty directory stays", "dir", e.dir)
		} else {
			e.log.InfoContext(ctx, "removed the client key, the data and the directory", "dir", e.dir)
		}
	}
	return nil
}

// discard removes DIR after a failed start, before any sandbox.
func (e *ephemeral) discard() {
	if e.held != nil {
		_ = e.held.Close()
	}
	if e.root != nil {
		_ = e.root.Close()
	}
	_ = os.RemoveAll(e.dir)
}
