// SPDX-License-Identifier: Apache-2.0

// Package server accepts SSH connections and serves the "sftp" subsystem.
// Shell, exec, port forwarding and every other channel or request type are
// refused.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/sftpd"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// Defaults (ROADMAP §7.5).
const (
	DefaultHandshakeTimeout  = 30 * time.Second
	DefaultIdleTimeout       = 15 * time.Minute
	DefaultKeepaliveInterval = 30 * time.Second
	DefaultMaxConnections    = 256
	DefaultMaxPerSource      = 16
	DefaultMaxPreauth        = 64
	DefaultMaxSessions       = 4
	DefaultMaxAuthTries      = 6
	serverVersion            = "SSH-2.0-gosftpd"
	maxClientVersionLen      = 128
)

// Config configures a Server.
type Config struct {
	HostKeys []ssh.Signer
	Auth     *auth.Authenticator
	Mounts   *vfs.Table
	// Grants returns the mounts an authenticated user may access; nil
	// grants every mount with all permissions (zero-config).
	Grants func(user string) []vfs.Grant
	Audit  *audit.Logger
	Log    *slog.Logger

	// Methods lists the enabled login methods, auth.MethodPublicKey and
	// auth.MethodPassword; empty means public keys only.
	Methods []string
	// Bans refuses sources that keep failing to log in; nil disables bans.
	Bans *auth.BanTable
	// CryptoPolicy is PolicyModern (default) or PolicyCompat.
	CryptoPolicy string

	// Zero values take the defaults. A negative IdleTimeout or
	// KeepaliveInterval disables it.
	HandshakeTimeout      time.Duration
	IdleTimeout           time.Duration
	KeepaliveInterval     time.Duration
	MaxConnections        int
	MaxConnectionsPerIP   int // per IPv4 address or IPv6 /64
	MaxPreauthConnections int
	MaxSessionsPerConn    int
	MaxOpenHandles        int // per SFTP session, default sftpd.DefaultMaxHandles
	MaxAuthTries          int
}

// Server serves SFTP over SSH.
type Server struct {
	cfg     Config
	sshCfg  *ssh.ServerConfig
	limits  *limiter
	rejects rejectLog

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case len(cfg.HostKeys) == 0:
		return nil, errors.New("no host keys")
	case cfg.Auth == nil, cfg.Mounts == nil:
		return nil, errors.New("authenticator and mounts are required")
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.Discard()
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	setDefault(&cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	setDefaultOrOff(&cfg.IdleTimeout, DefaultIdleTimeout)
	setDefaultOrOff(&cfg.KeepaliveInterval, DefaultKeepaliveInterval)
	setDefault(&cfg.MaxConnections, DefaultMaxConnections)
	setDefault(&cfg.MaxConnectionsPerIP, DefaultMaxPerSource)
	setDefault(&cfg.MaxPreauthConnections, DefaultMaxPreauth)
	setDefault(&cfg.MaxSessionsPerConn, DefaultMaxSessions)
	setDefault(&cfg.MaxAuthTries, DefaultMaxAuthTries)
	algos, err := policy(cfg.CryptoPolicy)
	if err != nil {
		return nil, err
	}
	if cfg.Grants == nil {
		mounts := cfg.Mounts
		cfg.Grants = func(string) []vfs.Grant { return mounts.FullAccess() }
	}

	sc := &ssh.ServerConfig{
		Config:                  ssh.Config{KeyExchanges: algos.kex, Ciphers: algos.ciphers, MACs: algos.macs},
		PublicKeyAuthAlgorithms: ssh.SupportedAlgorithms().PublicKeyAuths,
		MaxAuthTries:            cfg.MaxAuthTries,
		ServerVersion:           serverVersion,
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{auth.MethodPublicKey}
	}
	for _, m := range cfg.Methods {
		switch m {
		case auth.MethodPublicKey:
			sc.PublicKeyCallback = cfg.Auth.PublicKey
		case auth.MethodPassword:
			sc.PasswordCallback = cfg.Auth.Password
		default:
			return nil, fmt.Errorf("unknown authentication method %q", m)
		}
	}
	for _, k := range cfg.HostKeys {
		sc.AddHostKey(k)
	}
	return &Server{
		cfg:    cfg,
		sshCfg: sc,
		limits: newLimiter(cfg.MaxConnections, cfg.MaxConnectionsPerIP, cfg.MaxPreauthConnections),
		conns:  make(map[net.Conn]struct{}),
	}, nil
}

// setDefault replaces a zero or negative value with def.
func setDefault[T int | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// setDefaultOrOff replaces zero with def and a negative value with zero,
// which turns the setting off.
func setDefaultOrOff(v *time.Duration, def time.Duration) {
	switch {
	case *v == 0:
		*v = def
	case *v < 0:
		*v = 0
	}
}

// Serve accepts connections on ln until ctx is canceled or ln fails. It
// closes ln. In-flight connections keep running; see Shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.cfg.Log.WarnContext(ctx, "accept failed, retrying", "err", err, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0
		if adm := s.admit(c); adm != nil {
			s.wg.Go(func() { s.serveConn(c, adm) })
		}
	}
}

// admit applies bans and connection limits to a new connection. It closes
// a refused connection, before the SSH handshake, and returns nil.
func (s *Server) admit(c net.Conn) *admission {
	ip, isIP := auth.SourceAddr(c.RemoteAddr())
	var src netip.Prefix
	if isIP {
		src = auth.SourceKey(ip)
	}
	var (
		reason string
		adm    *admission
	)
	switch {
	case !s.cfg.Audit.Healthy():
		reason = rejectAudit
	case isIP && s.cfg.Bans != nil && s.cfg.Bans.Banned(ip):
		reason = rejectBanned
	default:
		adm, reason = s.limits.admit(src)
	}
	if adm != nil {
		return adm
	}
	_ = c.Close()
	if reason == rejectAudit {
		s.cfg.Log.Warn("refusing connection: audit log unavailable", "remote_addr", c.RemoteAddr().String())
		return nil
	}
	s.cfg.Log.Debug("connection refused", "remote_addr", c.RemoteAddr().String(), "reason", reason)
	if ok, suppressed := s.rejects.allow(time.Now()); ok {
		attrs := []slog.Attr{
			slog.String("remote_addr", c.RemoteAddr().String()),
			slog.String("local_addr", c.LocalAddr().String()),
			slog.String("reason", reason),
		}
		if suppressed > 0 {
			attrs = append(attrs, slog.Int("suppressed", suppressed))
		}
		s.cfg.Audit.Event("conn.reject", attrs...)
	}
	return nil
}

// Shutdown waits for in-flight connections to finish; when ctx expires it
// closes the remaining ones and returns ctx.Err(). Call it after Serve has
// returned.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	<-done
	return ctx.Err()
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func newID() string { return fmt.Sprintf("%016x", rand.Uint64()) } //nolint:gosec // G404: correlation IDs, not secrets

// ServeConn handles one connection until it closes, with the same bans and
// limits as Serve.
func (s *Server) ServeConn(c net.Conn) {
	if adm := s.admit(c); adm != nil {
		s.serveConn(c, adm)
	}
}

func (s *Server) serveConn(c net.Conn, adm *admission) {
	defer adm.release()
	connID := newID()
	log := s.cfg.Log.With("conn_id", connID, "remote_addr", c.RemoteAddr().String())
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic while serving connection", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	defer c.Close()
	s.track(c, true)
	defer s.track(c, false)

	al := s.cfg.Audit.With("conn_id", connID, "remote_addr", c.RemoteAddr().String(), "local_addr", c.LocalAddr().String())

	ca := s.newConnAuth(c, al)
	cfg := ca.config()

	start := time.Now()
	if err := c.SetDeadline(start.Add(s.cfg.HandshakeTimeout)); err != nil {
		return
	}
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	adm.authenticated()
	if err != nil {
		log.Debug("handshake failed", "err", err)
		if ca.accepted.Load() {
			u, _ := ca.attemptedUser.Load().(string)
			al.Event("auth.failure", slog.String("user", u), slog.Int("attempts", int(ca.failures.Load())))
			ca.closedWithoutLogin()
			al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", "error"))
		}
		return
	}
	defer sconn.Close()
	// This fails if the client already left: the SSH mux closes c when it
	// reads EOF. The login is audited all the same.
	_ = c.SetDeadline(time.Time{})

	name, ok := auth.UserFrom(sconn.Permissions)
	if !ok {
		log.Error("authenticated connection without a user")
		return
	}
	al = al.With("user", name)
	log = log.With("user", name)
	success := []slog.Attr{slog.String("auth_method", sconn.Permissions.Extensions[auth.ExtMethod])}
	if fp := sconn.Permissions.Extensions[auth.ExtFingerprint]; fp != "" {
		success = append(success, slog.String("key_fp", fp))
	}
	al.Event("auth.success", append(success, slog.Int("failed_attempts", int(ca.failures.Load())))...)

	go ssh.DiscardRequests(reqs)
	act := &activity{}
	act.touch(time.Now())
	var closeReason atomic.Value
	done := make(chan struct{})
	defer close(done)
	go watch(sconn, act, s.cfg.IdleTimeout, s.cfg.KeepaliveInterval, done, func(reason string) {
		closeReason.Store(reason)
		log.Info("closing connection", "reason", reason)
		_ = sconn.Close()
	})
	s.serveChannels(chans, name, act, al, log)
	result, _ := closeReason.Load().(string)
	if result == "" {
		result = "ok"
	}
	al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", result))
}

// connAuth is the authentication state of one connection. Its callbacks
// record attempts, count failures toward bans and refuse a change of user
// name within the connection (as sshd does); they never grant anything.
type connAuth struct {
	s    *Server
	al   *audit.Logger
	ip   netip.Addr
	isIP bool

	user          pinnedUser
	accepted      atomic.Bool
	failures      atomic.Int32 // every failed attempt
	keyFailures   atomic.Int32 // failed attempts other than passwords
	attemptedUser atomic.Value
}

func (s *Server) newConnAuth(c net.Conn, al *audit.Logger) *connAuth {
	ca := &connAuth{s: s, al: al}
	ca.ip, ca.isIP = auth.SourceAddr(c.RemoteAddr())
	return ca
}

// config returns the server configuration for the connection.
func (ca *connAuth) config() *ssh.ServerConfig {
	cfg := *ca.s.sshCfg
	if pk := cfg.PublicKeyCallback; pk != nil {
		cfg.PublicKeyCallback = func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !ca.user.same(md.User()) {
				return nil, errUserChanged
			}
			return pk(md, key)
		}
	}
	if cfg.PasswordCallback != nil {
		cfg.PasswordCallback = func(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if !ca.user.same(md.User()) {
				ca.fail()
				return nil, errUserChanged
			}
			// A connection opened before its source was banned guesses
			// no further.
			if ca.banned() {
				return nil, errBanned
			}
			perms, wait, err := ca.s.cfg.Auth.CheckPassword(md, password)
			if err != nil {
				// Count before the wait, so that the source's other
				// connections see a ban as early as possible.
				ca.fail()
				time.Sleep(wait)
			}
			return perms, err
		}
	}
	cfg.PreAuthConnCallback = func(pc ssh.ServerPreAuthConn) {
		ca.accepted.Store(true)
		v := string(pc.ClientVersion())
		if len(v) > maxClientVersionLen {
			v = v[:maxClientVersionLen]
		}
		ca.al.Event("conn.accept", slog.String("client_version", v))
	}
	cfg.AuthLogCallback = func(md ssh.ConnMetadata, method string, err error) {
		ca.user.same(md.User()) // the first request, often "none", fixes the name
		if method == "none" || err == nil {
			return
		}
		ca.failures.Add(1)
		ca.attemptedUser.Store(md.User())
		// Wrong passwords were counted by the callback, each at once. Other
		// failures, including passwords sent while the method is off,
		// count once per connection.
		if method != auth.MethodPassword || ca.s.sshCfg.PasswordCallback == nil {
			ca.keyFailures.Add(1)
		}
	}
	return &cfg
}

func (ca *connAuth) banned() bool {
	return ca.isIP && ca.s.cfg.Bans != nil && ca.s.cfg.Bans.Banned(ca.ip)
}

// closedWithoutLogin counts rejected keys once: an SSH agent offers all of
// its keys, so their number says nothing.
func (ca *connAuth) closedWithoutLogin() {
	if ca.keyFailures.Load() > 0 {
		ca.fail()
	}
}

// fail counts one failure against the connection's source.
func (ca *connAuth) fail() {
	bans := ca.s.cfg.Bans
	if bans == nil || !ca.isIP || !bans.Fail(ca.ip) {
		return
	}
	src := auth.SourceKey(ca.ip).String()
	ca.s.cfg.Log.Warn("banning source after repeated login failures", "source", src, "duration", bans.Duration())
	ca.al.Event("auth.ban", slog.String("source", src), slog.Int64("duration_ms", bans.Duration().Milliseconds()))
}

func (s *Server) serveChannels(chans <-chan ssh.NewChannel, user string, act *activity, al *audit.Logger, log *slog.Logger) {
	var (
		sessions sync.WaitGroup
		active   atomic.Int32
	)
	defer sessions.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "only SFTP sessions are allowed")
			continue
		}
		if int(active.Load()) >= s.cfg.MaxSessionsPerConn {
			_ = nc.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		active.Add(1)
		sessions.Go(func() {
			defer active.Add(-1)
			s.serveSession(activeChannel{ch, act}, creqs, user, al, log)
		})
	}
}

// serveSession answers channel requests: only one "subsystem sftp" is
// accepted; shell, exec, pty-req, env and the rest are refused.
func (s *Server) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, user string, al *audit.Logger, log *slog.Logger) {
	var done chan struct{}
	for req := range reqs {
		if req.Type == "subsystem" && done == nil && isSFTP(req.Payload) {
			_ = req.Reply(true, nil)
			done = make(chan struct{})
			go func() {
				defer close(done)
				s.serveSFTP(ch, user, al, log)
			}()
			continue
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
	if done != nil {
		<-done
	} else {
		_ = ch.Close()
	}
}

func isSFTP(payload []byte) bool {
	var p struct{ Name string }
	return ssh.Unmarshal(payload, &p) == nil && p.Name == "sftp"
}

func (s *Server) serveSFTP(ch ssh.Channel, user string, al *audit.Logger, log *slog.Logger) {
	sessionID := newID()
	al = al.With("session_id", sessionID)
	log = log.With("session_id", sessionID)
	start := time.Now()
	al.Event("session.start")

	vs, unavailable := s.cfg.Mounts.Session(user, s.cfg.Grants(user))
	for _, err := range unavailable {
		reason := "mount_unavailable"
		switch {
		case errors.Is(err, vfs.ErrHomeNotDir):
			reason = "home_not_dir"
		case errors.Is(err, vfs.ErrHomeMissing):
			reason = "home_missing"
		}
		mount := ""
		if me, ok := errors.AsType[*vfs.MountError](err); ok {
			mount = me.Mount
		}
		log.Warn("mount unavailable for this session", "mount", mount, "err", err)
		al.Event("fs.denied", slog.String("mount", mount), slog.String("reason", reason), slog.String("result", "denied"))
	}

	h := sftpd.New(vs, al, log, s.cfg.MaxOpenHandles)
	rs := sftp.NewRequestServer(ch, h.Handlers(), sftp.WithStartDirectory("/"))
	err := rs.Serve()

	// Without exit-status OpenSSH scp reports failure even after a complete
	// transfer. It must be sent before the channel is closed.
	var code uint32
	if err != nil && !errors.Is(err, io.EOF) {
		code = 1
		log.Debug("sftp session ended with error", "err", err)
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
	_ = rs.Close()
	_ = ch.Close()
	_ = vs.Close()
	al.Event("session.end", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.Int("exit_status", int(code)))
}

var (
	errUserChanged = errors.New("the user name may not change within a connection")
	errBanned      = errors.New("source banned")
)

// pinnedUser is the user name of a connection's first authentication
// request.
type pinnedUser struct {
	mu   sync.Mutex
	name string
	set  bool
}

// same pins name if no name is pinned yet and reports whether name is the
// pinned one.
func (p *pinnedUser) same(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.set {
		p.name, p.set = name, true
	}
	return p.name == name
}
