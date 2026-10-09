// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/sdnotify"
	"github.com/o-kolomoiets/go-sftp-server/internal/server"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

type serveOptions struct {
	config         string
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
	allowRoot      bool
}

func newServeCmd() *cobra.Command {
	var o serveOptions
	cmd := &cobra.Command{
		Use:   "serve [--config FILE | --dir [NAME=]PATH...]",
		Short: "Serve directories over SFTP",
		Long: `Serve directories over SFTP.

With --dir, gosftpd runs without a configuration file: every SSH user name
is accepted with the keys from --authorized-keys and gets full access to the
directories. Otherwise the configuration file is --config, $GOSFTPD_CONFIG,
./gosftpd.toml, /etc/gosftpd/config.toml or <user config dir>/gosftpd/config.toml,
whichever comes first.

Flags override the environment ($GOSFTPD_LISTEN, $GOSFTPD_LOG_LEVEL,
$GOSFTPD_LOG_FORMAT), which overrides the configuration file.`,
		Example: `  gosftpd serve --dir ./share
  gosftpd serve --dir inbox=/srv/inbox --dir docs=/srv/docs --read-only
  gosftpd serve --config /etc/gosftpd/config.toml`,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cmd.Flags(), o, os.Getenv, cmd.ErrOrStderr(), cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.config, "config", "", "configuration file")
	f.StringArrayVar(&o.dirs, "dir", nil, "directory to serve without a configuration file, as PATH or NAME=PATH (repeatable)")
	f.StringVar(&o.authorizedKeys, "authorized-keys", "", "with --dir: authorized_keys file (default ~/.ssh/authorized_keys)")
	f.StringVar(&o.user, "user", "", "with --dir: accept only this SSH user name (default: any)")
	f.StringVar(&o.stateDir, "state-dir", "", "with --dir: directory for the generated host key (default <user config dir>/gosftpd)")
	f.StringArrayVar(&o.hostKeys, "host-key", nil, "host private key file (repeatable)")
	f.StringVar(&o.listen, "listen", ":2022", "address to listen on")
	f.BoolVar(&o.readOnly, "read-only", false, "refuse all modifications on every mount")
	f.StringVar(&o.onConflict, "on-conflict", "rename", "when an upload targets an existing file: rename, reject, overwrite or version")
	f.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	f.StringVar(&o.logFormat, "log-format", "text", "text or json")
	f.StringVar(&o.auditOutput, "audit-output", "stdout", "audit log destination: stdout or a file path")
	f.BoolVar(&o.allowRoot, "allow-root", false, "run even as root (not recommended: run as a dedicated user)")
	return cmd
}

// buildConfig assembles the configuration: a file, or zero-config with
// --dir; then the environment; then flags that were set explicitly. For a
// reload it also returns where the environment or a flag overrides a value
// of the file, since editing that value then has no effect.
func buildConfig(flags *pflag.FlagSet, o serveOptions, getenv func(string) string, reload bool) (*config.Config, []string, error) {
	var (
		c   *config.Config
		err error
	)
	if err := checkFlagValues(flags, o); err != nil {
		return nil, nil, err
	}
	if len(o.dirs) > 0 {
		if o.config != "" {
			return nil, nil, usageError{errors.New("--dir and --config cannot be used together")}
		}
		if c, err = zeroConfig(o, reload); err != nil {
			return nil, nil, err
		}
	} else {
		for _, name := range []string{"authorized-keys", "user", "state-dir"} {
			if flags.Changed(name) {
				return nil, nil, usageError{fmt.Errorf("--%s only applies with --dir; with a configuration file set it there", name)}
			}
		}
		if c, err = loadConfig(o.config, getenv); err != nil {
			return nil, nil, err
		}
		if flags.Changed("read-only") && o.readOnly {
			for _, m := range c.Mounts {
				m.ReadOnly = true
			}
		}
		if flags.Changed("on-conflict") {
			for _, m := range c.Mounts {
				m.OnConflict = o.onConflict
			}
		}
		if flags.Changed("host-key") {
			c.Server.HostKeys = absPaths(o.hostKeys)
		}
	}
	masked := applyEnv(c, getenv)
	if flags.Changed("listen") {
		c.Server.Listen = []string{o.listen}
	}
	if flags.Changed("log-level") {
		masked = override(c, masked, "log.level", "--log-level", &c.Log.Level, o.logLevel)
	}
	if flags.Changed("log-format") {
		c.Log.Format = o.logFormat
	}
	if flags.Changed("audit-output") {
		out := o.auditOutput
		if out != "stdout" {
			out = absPath(out)
		}
		masked = override(c, masked, "audit.output", "--audit-output", &c.Audit.Output, out)
	}
	if !reload {
		masked = nil
	}
	return c, masked, nil
}

// applyEnv applies the environment variables that override the file. It
// returns where they hide a value of the file that a reload would apply.
func applyEnv(c *config.Config, getenv func(string) string) (masked []string) {
	if v := getenv(config.EnvListen); v != "" {
		c.Server.Listen = strings.Split(v, ",")
	}
	if v := getenv(config.EnvLogLevel); v != "" {
		masked = override(c, masked, "log.level", "$"+config.EnvLogLevel, &c.Log.Level, v)
	}
	if v := getenv(config.EnvLogFormat); v != "" {
		c.Log.Format = v
	}
	return masked
}

// override sets *field to value, set by by, and notes a different value of
// the file in masked.
func override(c *config.Config, masked []string, key, by string, field *string, value string) []string {
	if c.File != "" && *field != value {
		masked = append(masked, fmt.Sprintf("%s = %q in %s has no effect: %s overrides it", key, *field, c.File, by))
	}
	*field = value
	return masked
}

// checkFlagValues reports bad flag values under the flag's name rather than
// as a configuration key.
func checkFlagValues(flags *pflag.FlagSet, o serveOptions) error {
	if flags.Changed("on-conflict") || len(o.dirs) > 0 {
		if _, err := vfs.ParseConflictPolicy(o.onConflict); err != nil {
			return usageError{fmt.Errorf("--on-conflict: %w", err)}
		}
	}
	if _, _, err := newLogger(io.Discard, o.logLevel, o.logFormat); err != nil {
		return usageError{fmt.Errorf("--%w", err)}
	}
	return nil
}

// loadConfig finds and loads the configuration file.
func loadConfig(explicit string, getenv func(string) string) (*config.Config, error) {
	path, err := config.Find(explicit, getenv)
	if errors.Is(err, config.ErrNotFound) {
		return nil, usageError{fmt.Errorf("no configuration file found (looked for %s); create one with 'gosftpd init' or serve a directory with --dir",
			strings.Join(config.SearchPaths(), ", "))}
	}
	if err != nil {
		return nil, configError{err}
	}
	c, err := config.Load(path)
	if err != nil {
		return nil, configError{err}
	}
	return c, nil
}

// zeroConfig builds the configuration of serve --dir. On reload, a missing
// default authorized_keys file is left to BuildAuthenticator, which then
// refuses every login.
func zeroConfig(o serveOptions, reload bool) (*config.Config, error) {
	c := config.Default()
	c.Defaults.OnConflict = o.onConflict
	specs, err := parseDirs(o.dirs)
	if err != nil {
		return nil, usageError{err}
	}
	for _, s := range specs {
		if _, dup := c.Mounts[s.Name]; dup {
			return nil, usageError{fmt.Errorf("two --dir have the name %q; name them with --dir NAME=PATH", s.Name)}
		}
		m := c.AddMount(s.Name, s.Path)
		m.ReadOnly = o.readOnly
	}

	keys := o.authorizedKeys
	if keys == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, configError{errors.New("no --authorized-keys given and no home directory")}
		}
		keys = filepath.Join(home, ".ssh", "authorized_keys")
		if _, err := os.Stat(keys); err != nil && !reload {
			return nil, configError{fmt.Errorf("no --authorized-keys given and %s does not exist; add your public key there or pass --authorized-keys FILE", keys)}
		}
	}
	c.AnyUser = &config.ZeroConfigUser{Name: o.user, AuthorizedKeysFile: absPath(keys)}

	if len(o.hostKeys) > 0 {
		c.Server.HostKeys = absPaths(o.hostKeys)
	} else {
		dir := o.stateDir
		if dir == "" {
			if dir, err = defaultStateDir(); err != nil {
				return nil, configError{err}
			}
		}
		c.Server.HostKeys = []string{filepath.Join(absPath(dir), hostkey.DefaultFile)}
		c.Server.HostKeyAutoGenerate = true
	}
	return c, nil
}

func defaultStateDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find a state directory, use --state-dir: %w", err)
	}
	return filepath.Join(dir, "gosftpd"), nil
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func absPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = absPath(p)
	}
	return out
}

// problemsError lists every validation error, one per line.
type problemsError struct {
	file string
	err  error
}

func (e problemsError) Error() string {
	var lines []string
	if joined, ok := e.err.(interface{ Unwrap() []error }); ok {
		for _, err := range joined.Unwrap() {
			lines = append(lines, err.Error())
		}
	} else {
		lines = []string{e.err.Error()}
	}
	where := "configuration"
	if e.file != "" {
		where = e.file
	}
	noun := "problems"
	if len(lines) == 1 {
		noun = "problem"
	}
	return fmt.Sprintf("%s: %d %s:\n  %s", where, len(lines), noun, strings.Join(lines, "\n  "))
}

func (e problemsError) Unwrap() error { return e.err }

// checkConfig validates c (and the filesystem with checkFS) and returns the
// warnings.
func checkConfig(c *config.Config, checkFS bool) ([]string, error) {
	warns, err := c.Validate()
	if err != nil {
		return warns, configError{problemsError{c.File, err}}
	}
	if checkFS {
		fsWarns, err := c.CheckFS()
		warns = append(warns, fsWarns...)
		if err != nil {
			return warns, configError{problemsError{c.File, err}}
		}
	}
	return warns, nil
}

func runServe(ctx context.Context, flags *pflag.FlagSet, o serveOptions, getenv func(string) string, stderr, stdout io.Writer) error {
	// SIGHUP reloads. Its default action would kill the process, so it is
	// caught from the start; a signal during startup waits for the loop.
	hup, injected := ctx.Value(hupKey{}).(<-chan os.Signal)
	if !injected {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		// Ignored, not reset, once serving ends: a reload sent during the
		// drain must not kill the process.
		defer signal.Ignore(syscall.SIGHUP)
		hup = ch
	}

	if err := checkFlagValues(flags, o); err != nil {
		return err
	}
	if err := checkRoot(o.allowRoot, os.Geteuid()); err != nil {
		return err
	}
	c, _, err := buildConfig(flags, o, getenv, false)
	if err != nil {
		return err
	}
	warns, err := checkConfig(c, true)
	if err != nil {
		return err
	}
	log, level, err := newLogger(stderr, c.Log.Level, c.Log.Format)
	if err != nil {
		return configError{err}
	}
	for _, w := range warns {
		log.WarnContext(ctx, "configuration", "detail", w)
	}

	authn, keyFiles, keyWarns, err := c.BuildAuthenticator(config.AuthOptions{})
	if err != nil {
		return configError{err}
	}
	for _, w := range keyWarns {
		log.WarnContext(ctx, "skipping authorized key", "detail", w)
	}
	keys, keyInfo, err := loadHostKeys(c.Server.HostKeys, c.Server.HostKeyAutoGenerate)
	if err != nil {
		return configError{err}
	}
	specs, err := c.MountSpecs()
	if err != nil {
		return configError{err}
	}
	mounts, err := vfs.Open(specs, vfs.Options{Flatten: c.Defaults.Flatten})
	if err != nil {
		return configError{err}
	}

	out, err := openAuditOutput(c.Audit.Output, stdout)
	if err != nil {
		_ = mounts.Close()
		return configError{err}
	}
	defer out.Close()
	al, err := audit.NewWithOptions(out, log, c.AuditOptions())
	if err != nil {
		_ = mounts.Close()
		return configError{err}
	}

	cfg := serverConfig(c, authn, mounts)
	cfg.HostKeys, cfg.Audit, cfg.Log, cfg.CryptoPolicy = keys, al, log, c.Server.CryptoPolicy
	srv, err := server.New(cfg)
	if err != nil {
		_ = mounts.Close()
		return err
	}
	r := &running{
		flags: flags, opts: o, getenv: getenv, log: log, level: level, out: out, al: al, srv: srv,
		c: c, mounts: mounts, keys: keyFiles,
	}
	if c.File != "" {
		// A reload reads this file again, not the first one found then.
		r.opts.config = absPath(c.File)
	}
	defer r.release()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var listeners []net.Listener
	// TCP keepalive finds dead peers before the SSH handshake too; after it,
	// keepalive@openssh.com requests do (keepalive_interval).
	lc := net.ListenConfig{KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: time.Minute, Interval: 15 * time.Second, Count: 4}}
	for _, addr := range c.Server.Listen {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	printBanner(stderr, bannerInfo{c: c, listeners: listeners, keys: keys, keyInfo: keyInfo, auth: authn, mounts: mounts})
	addrs := make([]string, len(listeners))
	for i, ln := range listeners {
		addrs[i] = ln.Addr().String()
	}
	al.Event("server.start", slog.String("version", version.Get().Version), slog.String("listen", strings.Join(addrs, ",")))

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var background sync.WaitGroup
	defer background.Wait() // after cancel
	background.Go(func() { cleanTemp(serveCtx, r.currentMounts, log) })
	background.Go(func() { r.reloadLoop(serveCtx, hup) })
	served := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func() { served <- srv.Serve(serveCtx, ln) }()
	}
	if err := sdnotify.Ready(); err != nil {
		log.DebugContext(ctx, "sd_notify", "err", err)
	}
	var serveErr error
	pending := len(listeners)
	select {
	case serveErr = <-served:
		pending--
	case <-ctx.Done():
	}
	if err := sdnotify.Stopping(); err != nil {
		log.DebugContext(ctx, "sd_notify", "err", err)
	}
	cancel()
	stop()            // a second signal terminates immediately
	background.Wait() // no reload runs during the shutdown
	timeout := r.shutdownTimeout()
	log.InfoContext(ctx, "shutting down", "timeout", timeout)
	for range pending {
		<-served
	}
	sctx, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancelShutdown()
	if err := srv.Shutdown(sctx); err != nil {
		log.WarnContext(ctx, "closed connections that did not finish in time")
	}
	r.release()
	al.Event("server.stop")
	return serveErr
}

// serverConfig returns the reloadable part of the server configuration.
func serverConfig(c *config.Config, authn *auth.Authenticator, mounts *vfs.Table) server.Config {
	return server.Config{
		Auth:                  authn,
		Mounts:                mounts,
		Grants:                c.Grants,
		Methods:               c.Auth.Methods,
		Bans:                  c.Bans(),
		HandshakeTimeout:      time.Duration(c.Server.HandshakeTimeout),
		IdleTimeout:           offIfZero(c.Server.IdleTimeout),
		KeepaliveInterval:     offIfZero(c.Server.KeepaliveInterval),
		MaxConnections:        c.Limits.MaxConnections,
		MaxConnectionsPerIP:   c.Limits.MaxConnectionsPerIP,
		MaxPreauthConnections: c.Limits.MaxPreauthConnections,
		MaxSessionsPerConn:    c.Limits.MaxSessionsPerConn,
		MaxOpenHandles:        c.Limits.MaxOpenHandles,
		MaxAuthTries:          c.Limits.MaxAuthTries,
		DisconnectRevoked:     c.Reload.DisconnectRemovedUsers,
	}
}

// checkRoot refuses to serve as root unless allowed: a confinement bug
// would then expose the whole host.
func checkRoot(allow bool, euid int) error {
	if euid != 0 || allow {
		return nil
	}
	return usageError{errors.New("refusing to run as root: run gosftpd as a dedicated unprivileged user (for example 'gosftpd'), or pass --allow-root if you really mean it")}
}

// offIfZero maps a configured 0 ("off") to the server's negative "off".
func offIfZero(d config.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return time.Duration(d)
}

// newLogger returns the operational logger and its level, which a reload
// can change.
func newLogger(w io.Writer, level, format string) (*slog.Logger, *slog.LevelVar, error) {
	lv, err := parseLevel(level)
	if err != nil {
		return nil, nil, err
	}
	v := new(slog.LevelVar)
	v.Set(lv)
	opts := &slog.HandlerOptions{Level: v}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), v, nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), v, nil
	default:
		return nil, nil, fmt.Errorf("log-format: unknown format %q (want text or json)", format)
	}
}

func parseLevel(level string) (slog.Level, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return 0, fmt.Errorf("log-level: %w", err)
	}
	return lv, nil
}

// parseDirs turns --dir values into mounts. "NAME=PATH" names a mount;
// otherwise the name is the last path component.
func parseDirs(dirs []string) ([]vfs.MountSpec, error) {
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
		if filepath.Base(abs) == vfs.UserPlaceholder {
			return nil, fmt.Errorf("--dir %q: per-user directories ({user}) need a configuration file", d)
		}
		specs = append(specs, vfs.MountSpec{Name: name, Path: abs})
	}
	return specs, nil
}

// loadHostKeys loads the host keys, generating missing ones as ed25519 when
// autoGenerate is set. info describes where the keys came from.
func loadHostKeys(paths []string, autoGenerate bool) (keys []ssh.Signer, info []string, err error) {
	for _, p := range paths {
		var (
			k         ssh.Signer
			generated bool
		)
		if autoGenerate {
			k, generated, err = hostkey.LoadOrGenerate(p)
		} else {
			k, err = hostkey.Load(p)
		}
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, k)
		if generated {
			info = append(info, p+" (generated, 0600)")
		} else {
			info = append(info, p)
		}
	}
	return keys, info, nil
}

type bannerInfo struct {
	c         *config.Config
	listeners []net.Listener
	keys      []ssh.Signer
	keyInfo   []string
	auth      *auth.Authenticator
	mounts    *vfs.Table
}

func printBanner(w io.Writer, b bannerInfo) {
	host, port := connectHost(b.listeners[0].Addr())
	fmt.Fprintln(w, version.Get())
	if b.c.File != "" {
		fmt.Fprintf(w, "config:  %s\n", b.c.File)
	}
	for i, k := range b.keys {
		fmt.Fprintf(w, "host key: %s\n", b.keyInfo[i])
		fmt.Fprintf(w, "  %s %s\n", strings.ToUpper(strings.TrimPrefix(k.PublicKey().Type(), "ssh-")), hostkey.Fingerprint(k.PublicKey()))
		fmt.Fprintf(w, "  known_hosts: %s\n", hostkey.KnownHostsLine(host, port, k.PublicKey()))
	}
	user := "<user>"
	if z := b.c.AnyUser; z != nil {
		fmt.Fprintf(w, "auth:    publickey, %d keys from %s\n", b.auth.Len(), z.AuthorizedKeysFile)
		if z.Name != "" {
			user = z.Name
		}
	} else {
		fmt.Fprintf(w, "auth:    %s, %d users, %d keys\n", strings.Join(b.c.Auth.Methods, ", "), len(b.c.Users), b.auth.Len())
	}
	for _, m := range b.mounts.Mounts() {
		mode := "rw"
		if m.ReadOnly() {
			mode = "ro"
		}
		vpath := "/" + m.Name()
		if b.mounts.Flattened() {
			vpath = "/"
		}
		o := m.Options()
		atomic := ""
		if o.AtomicUploads {
			atomic = ", atomic_uploads"
		}
		fmt.Fprintf(w, "mounts:  %s -> %s (%s, on_conflict=%s%s)\n", vpath, m.HostPath(), mode, o.OnConflict, atomic)
	}
	addrs := make([]string, len(b.listeners))
	for i, ln := range b.listeners {
		addrs[i] = ln.Addr().String()
	}
	fmt.Fprintf(w, "listen:  %s\n", strings.Join(addrs, ", "))
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

// cleanTemp removes temporary files of interrupted uploads at start and
// then every TempMaxAge/4 until ctx is done, in the mount table current at
// each pass.
func cleanTemp(ctx context.Context, current func() *vfs.Table, log *slog.Logger) {
	tick := time.NewTicker(vfs.TempMaxAge / 4)
	defer tick.Stop()
	for {
		if mounts := current(); mounts != nil {
			if n := mounts.CleanTemp(); n > 0 {
				log.InfoContext(ctx, "removed temporary files of interrupted uploads", "count", n, "older_than", vfs.TempMaxAge)
			}
			_ = mounts.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
