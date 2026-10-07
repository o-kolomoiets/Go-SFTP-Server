// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/server"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

const shutdownTimeout = 30 * time.Second

type serveOptions struct {
	dirs           []string
	authorizedKeys string
	hostKeys       []string
	stateDir       string
	listen         string
	readOnly       bool
	onConflict     string
	user           string
	logLevel       string
	logFormat      string
	auditOutput    string
}

func newServeCmd() *cobra.Command {
	var o serveOptions
	cmd := &cobra.Command{
		Use:   "serve --dir [NAME=]PATH...",
		Short: "Serve directories over SFTP",
		Example: `  gosftpd serve --dir ./share
  gosftpd serve --dir inbox=/srv/inbox --dir docs=/srv/docs --read-only`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), o, cmd.ErrOrStderr(), cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.dirs, "dir", nil, "directory to serve, as PATH or NAME=PATH (repeatable)")
	f.StringVar(&o.authorizedKeys, "authorized-keys", "", "authorized_keys file (default ~/.ssh/authorized_keys)")
	f.StringArrayVar(&o.hostKeys, "host-key", nil, "host private key file (repeatable; default: generated in the state directory)")
	f.StringVar(&o.stateDir, "state-dir", "", "directory for generated host keys (default <user config dir>/gosftpd)")
	f.StringVar(&o.listen, "listen", ":2022", "address to listen on")
	f.BoolVar(&o.readOnly, "read-only", false, "refuse all modifications")
	f.StringVar(&o.onConflict, "on-conflict", "rename", "when an upload targets an existing file: rename, reject or overwrite")
	f.StringVar(&o.user, "user", "", "accept only this SSH user name (default: any)")
	f.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	f.StringVar(&o.logFormat, "log-format", "text", "text or json")
	f.StringVar(&o.auditOutput, "audit-output", "stdout", "audit log destination: stdout or a file path")
	return cmd
}

func runServe(ctx context.Context, o serveOptions, stderr, stdout io.Writer) error {
	log, err := newLogger(stderr, o.logLevel, o.logFormat)
	if err != nil {
		return usageError{err}
	}
	policy, err := vfs.ParseConflictPolicy(o.onConflict)
	if err != nil {
		return usageError{err}
	}
	specs, err := parseDirs(o.dirs, o.readOnly)
	if err != nil {
		return usageError{err}
	}
	authn, keysFile, err := loadAuthorizedKeys(o.authorizedKeys, o.user, log)
	if err != nil {
		return configError{err}
	}
	keys, keyInfo, err := loadHostKeys(o.hostKeys, o.stateDir)
	if err != nil {
		return configError{err}
	}

	mounts, err := vfs.Open(specs, vfs.Options{OnConflict: policy, Flatten: true})
	if err != nil {
		return configError{err}
	}
	defer mounts.Close()

	auditOut, closeAudit, err := openAudit(o.auditOutput, stdout)
	if err != nil {
		return configError{err}
	}
	defer closeAudit()
	al := audit.New(auditOut, log)

	srv, err := server.New(server.Config{HostKeys: keys, Auth: authn, Mounts: mounts, Audit: al, Log: log})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	signal.Ignore(syscall.SIGHUP) // reload comes in v0.4; until then HUP must not kill the server

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", o.listen)
	if err != nil {
		return err
	}
	printBanner(stderr, ln.Addr(), keys, keyInfo, authn, keysFile, o.user, mounts)
	al.Event("server.start", slog.String("version", version.Get().Version), slog.String("listen", ln.Addr().String()))

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	stop() // a second signal terminates immediately
	log.InfoContext(ctx, "shutting down", "timeout", shutdownTimeout)
	<-served
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.WarnContext(ctx, "closed connections that did not finish in time")
	}
	al.Event("server.stop")
	return nil
}

func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("--log-format: unknown format %q (want text or json)", format)
	}
}

// parseDirs turns --dir values into mounts. "NAME=PATH" names a mount;
// otherwise the name is the last path component.
func parseDirs(dirs []string, readOnly bool) ([]vfs.MountSpec, error) {
	if len(dirs) == 0 {
		return nil, errors.New("at least one --dir is required, e.g. gosftpd serve --dir ./share")
	}
	specs := make([]vfs.MountSpec, 0, len(dirs))
	for _, d := range dirs {
		name, p, ok := strings.Cut(d, "=")
		if !ok || !vfs.ValidMountName(name) {
			name, p = "", d
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("--dir %q: %w", d, err)
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("--dir %q: %w", d, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("--dir %q: not a directory", d)
		}
		if name == "" {
			name = filepath.Base(abs)
		}
		specs = append(specs, vfs.MountSpec{Name: name, Path: abs, ReadOnly: readOnly})
	}
	return specs, nil
}

func loadAuthorizedKeys(file, user string, log *slog.Logger) (*auth.Authenticator, string, error) {
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", errors.New("no --authorized-keys given and no home directory")
		}
		file = filepath.Join(home, ".ssh", "authorized_keys")
		if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("no --authorized-keys given and %s does not exist", file)
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	keys, warnings := auth.ParseAuthorizedKeys(data, file)
	for _, w := range warnings {
		log.Warn("skipping authorized_keys line", "detail", w)
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("%s contains no usable keys", file)
	}
	return auth.New(user, keys), file, nil
}

// loadHostKeys loads --host-key files, or loads/generates the default ed25519
// key in the state directory. info describes where the key came from.
func loadHostKeys(paths []string, stateDir string) (keys []ssh.Signer, info string, err error) {
	if len(paths) > 0 {
		for _, p := range paths {
			k, err := hostkey.Load(p)
			if err != nil {
				return nil, "", err
			}
			keys = append(keys, k)
		}
		return keys, strings.Join(paths, ", "), nil
	}
	if stateDir == "" {
		cfg, err := os.UserConfigDir()
		if err != nil {
			return nil, "", fmt.Errorf("cannot find a state directory, use --state-dir: %w", err)
		}
		stateDir = filepath.Join(cfg, "gosftpd")
	}
	path := filepath.Join(stateDir, hostkey.DefaultFile)
	k, generated, err := hostkey.LoadOrGenerate(path)
	if err != nil {
		return nil, "", err
	}
	if generated {
		return []ssh.Signer{k}, path + " (generated, 0600)", nil
	}
	return []ssh.Signer{k}, path, nil
}

func openAudit(dest string, stdout io.Writer) (io.Writer, func(), error) {
	if dest == "" || dest == "stdout" {
		return stdout, func() {}, nil
	}
	// O_APPEND, unlike uploads: logrotate's copytruncate must not leave a
	// hole of zeros.
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("--audit-output: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func printBanner(w io.Writer, addr net.Addr, keys []ssh.Signer, keyInfo string, a *auth.Authenticator, keysFile, user string, mounts *vfs.Table) {
	host, port := connectHost(addr)
	fmt.Fprintln(w, version.Get())
	fmt.Fprintf(w, "host key: %s\n", keyInfo)
	for _, k := range keys {
		fmt.Fprintf(w, "  %s %s\n", strings.ToUpper(strings.TrimPrefix(k.PublicKey().Type(), "ssh-")), hostkey.Fingerprint(k.PublicKey()))
		fmt.Fprintf(w, "  known_hosts: %s\n", hostkey.KnownHostsLine(host, port, k.PublicKey()))
	}
	fmt.Fprintf(w, "auth:    publickey, %d keys from %s\n", a.Len(), keysFile)
	for _, m := range mounts.Mounts() {
		mode := "rw"
		if m.ReadOnly() {
			mode = "ro"
		}
		vpath := "/" + m.Name()
		if mounts.Flattened() {
			vpath = "/"
		}
		fmt.Fprintf(w, "mounts:  %s -> %s (%s, on_conflict=%s)\n", vpath, m.HostPath(), mode, mounts.Policy())
	}
	fmt.Fprintf(w, "listen:  %s\n", addr)
	if user == "" {
		user = "<user>"
	}
	fmt.Fprintf(w, "connect: sftp -P %d %s@%s\n", port, user, host)
}

// connectHost picks a host name for the connect hints.
func connectHost(addr net.Addr) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr.String())
	port, _ := strconv.Atoi(portStr)
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		if h, err := os.Hostname(); err == nil && h != "" {
			return h, port
		}
		return "localhost", port
	}
	return host, port
}
