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

// Config configures a Server. New fixes HostKeys, CryptoPolicy, Audit and
// Log; Reload changes the rest.
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

	// DisconnectRevoked makes Reload close the connections whose login the
	// new configuration would refuse (reload.disconnect_removed_users).
	DisconnectRevoked bool
}

// Server serves SFTP over SSH.
type Server struct {
	hostKeys []ssh.Signer
	algos    algorithms
	audit    *audit.Logger
	log      *slog.Logger
	limits   *limiter
	rejects  rejectLog

	// snap is the configuration for new logins (see snapshot).
	snap atomic.Pointer[snapshot]
	rmu  sync.Mutex     // serializes Reload
	bans *auth.BanTable // kept across reloads while bans stay on; guarded by rmu

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	live  map[*liveConn]struct{} // logged-in connections
}

// snapshot is the reloadable configuration. A connection takes its
// transport settings (handshake timeout, MaxAuthTries, offered methods)
// from the snapshot current at accept; every authentication attempt checks
// the current one; and once logged in, the connection holds the then
// current snapshot, and a reference to its mount table, for its life.
type snapshot struct {
	cfg                 Config // with defaults
	ssh                 *ssh.ServerConfig
	publicKey, password bool // enabled methods
	bans                *auth.BanTable
}

// New validates cfg and returns a Server. The caller keeps cfg.Mounts open
// while it is the current table (see Reload).
func New(cfg Config) (*Server, error) {
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("no host keys")
	}
	algos, err := policy(cfg.CryptoPolicy)
	if err != nil {
		return nil, err
	}
	s := &Server{
		hostKeys: cfg.HostKeys,
		algos:    algos,
		audit:    cfg.Audit,
		log:      cfg.Log,
		conns:    make(map[net.Conn]struct{}),
		live:     make(map[*liveConn]struct{}),
	}
	if s.audit == nil {
		s.audit = audit.Discard()
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	sn, err := s.newSnapshot(cfg)
	if err != nil {
		return nil, err
	}
	c := &sn.cfg
	s.limits = newLimiter(c.MaxConnections, c.MaxConnectionsPerIP, c.MaxPreauthConnections)
	s.bans = sn.bans
	s.snap.Store(sn)
	return s, nil
}

// Reload switches new logins to cfg; HostKeys, CryptoPolicy, Audit and Log
// are ignored. Logged-in connections keep the configuration they logged in
// under; with cfg.DisconnectRevoked, those whose login cfg would refuse are
// closed, and Reload returns how many. Bans, connection counts and the
// password hashing limit carry over. The caller keeps cfg.Mounts open while
// it is the current table and may drop its reference to the previous table
// once Reload returns.
func (s *Server) Reload(cfg Config) (disconnected int, err error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	sn, err := s.newSnapshot(cfg)
	if err != nil {
		return 0, err
	}
	sn.cfg.Auth.Inherit(s.snap.Load().cfg.Auth)
	if sn.bans != nil && s.bans != nil {
		s.bans.SetOptions(sn.bans.Options())
		sn.bans = s.bans
	}
	s.bans = sn.bans
	c := &sn.cfg
	s.limits.setLimits(c.MaxConnections, c.MaxConnectionsPerIP, c.MaxPreauthConnections)
	s.snap.Store(sn)
	if c.DisconnectRevoked {
		disconnected = s.disconnectRevoked(sn)
	}
	return disconnected, nil
}

func (s *Server) newSnapshot(cfg Config) (*snapshot, error) {
	if cfg.Auth == nil || cfg.Mounts == nil {
		return nil, errors.New("authenticator and mounts are required")
	}
	setDefault(&cfg.HandshakeTimeout, DefaultHandshakeTimeout)
	setDefaultOrOff(&cfg.IdleTimeout, DefaultIdleTimeout)
	setDefaultOrOff(&cfg.KeepaliveInterval, DefaultKeepaliveInterval)
	setDefault(&cfg.MaxConnections, DefaultMaxConnections)
	setDefault(&cfg.MaxConnectionsPerIP, DefaultMaxPerSource)
	setDefault(&cfg.MaxPreauthConnections, DefaultMaxPreauth)
	setDefault(&cfg.MaxSessionsPerConn, DefaultMaxSessions)
	setDefault(&cfg.MaxAuthTries, DefaultMaxAuthTries)
	if cfg.Grants == nil {
		mounts := cfg.Mounts
		cfg.Grants = func(string) []vfs.Grant { return mounts.FullAccess() }
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{auth.MethodPublicKey}
	}
	sn := &snapshot{bans: cfg.Bans}
	for _, m := range cfg.Methods {
		switch m {
		case auth.MethodPublicKey:
			sn.publicKey = true
		case auth.MethodPassword:
			sn.password = true
		default:
			return nil, fmt.Errorf("unknown authentication method %q", m)
		}
	}
	sn.ssh = &ssh.ServerConfig{
		Config:                  ssh.Config{KeyExchanges: s.algos.kex, Ciphers: s.algos.ciphers, MACs: s.algos.macs},
		PublicKeyAuthAlgorithms: ssh.SupportedAlgorithms().PublicKeyAuths,
		MaxAuthTries:            cfg.MaxAuthTries,
		ServerVersion:           serverVersion,
	}
	for _, k := range s.hostKeys {
		sn.ssh.AddHostKey(k)
	}
	sn.cfg = cfg
	return sn, nil
}

// pin returns the current snapshot with a reference to its mount table,
// which the caller closes; nil when the table is closed (shutdown).
func (s *Server) pin() *snapshot {
	for {
		sn := s.snap.Load()
		if sn.cfg.Mounts.Acquire() {
			return sn
		}
		if s.snap.Load() == sn {
			return nil
		}
	}
}

// liveConn is a logged-in connection.
type liveConn struct {
	sconn  *ssh.ServerConn
	log    *slog.Logger
	reason atomic.Pointer[string] // why the server closed it
}

// close closes the connection; the first reason given is audited.
func (lc *liveConn) close(reason string) {
	if lc.reason.CompareAndSwap(nil, &reason) {
		lc.log.Info("closing connection", "reason", reason)
	}
	_ = lc.sconn.Close()
}

// register adds or removes a logged-in connection. A connection registers
// before it reads the current snapshot, and Reload stores a snapshot before
// it checks the registered connections: so each connection is either
// checked by Reload or logs in under the new snapshot.
func (s *Server) register(lc *liveConn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.live[lc] = struct{}{}
	} else {
		delete(s.live, lc)
	}
}

// disconnectRevoked closes the connections whose login sn would refuse.
func (s *Server) disconnectRevoked(sn *snapshot) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for lc := range s.live {
		if !sn.cfg.Auth.Recheck(lc.sconn, lc.sconn.Permissions) {
			lc.close("revoked")
			n++
		}
	}
	return n
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
			s.log.WarnContext(ctx, "accept failed, retrying", "err", err, "backoff", backoff)
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
	switch bans := s.snap.Load().bans; {
	case !s.audit.Healthy():
		reason = rejectAudit
	case isIP && bans != nil && bans.Banned(ip):
		reason = rejectBanned
	default:
		adm, reason = s.limits.admit(src)
	}
	if adm != nil {
		return adm
	}
	_ = c.Close()
	if reason == rejectAudit {
		s.log.Warn("refusing connection: audit log unavailable", "remote_addr", c.RemoteAddr().String())
		return nil
	}
	s.log.Debug("connection refused", "remote_addr", c.RemoteAddr().String(), "reason", reason)
	if ok, suppressed := s.rejects.allow(time.Now()); ok {
		attrs := []slog.Attr{
			slog.String("remote_addr", c.RemoteAddr().String()),
			slog.String("local_addr", c.LocalAddr().String()),
			slog.String("reason", reason),
		}
		if suppressed > 0 {
			attrs = append(attrs, slog.Int("suppressed", suppressed))
		}
		s.audit.Event("conn.reject", attrs...)
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
	log := s.log.With("conn_id", connID, "remote_addr", c.RemoteAddr().String())
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic while serving connection", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	defer c.Close()
	s.track(c, true)
	defer s.track(c, false)

	al := s.audit.With("conn_id", connID, "remote_addr", c.RemoteAddr().String(), "local_addr", c.LocalAddr().String())

	sn := s.snap.Load()
	ca := s.newConnAuth(c, al)
	cfg := ca.config(sn)

	start := time.Now()
	if err := c.SetDeadline(start.Add(sn.cfg.HandshakeTimeout)); err != nil {
		return
	}
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	adm.authenticated()
	closed := func(result string) {
		al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", result))
	}
	if err != nil {
		log.Debug("handshake failed", "err", err)
		if ca.accepted.Load() {
			u, _ := ca.attemptedUser.Load().(string)
			attrs := []slog.Attr{slog.String("user", u), slog.Int("attempts", int(ca.failures.Load()))}
			if re := ca.reason.Load(); re != nil {
				logRefused(log, u, re)
				attrs = append(attrs, slog.String("reason", re.Reason))
				attrs = append(attrs, keyAttrs(re.Key, re.Cert)...)
			}
			al.Event("auth.failure", attrs...)
			ca.closedWithoutLogin()
			closed("error")
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
	log = log.With("user", name)

	// The connection lives under the snapshot current now, if its login
	// passes that: a reload since the callbacks ran may have revoked it
	// (x/crypto also reuses the result of a public key query).
	lc := &liveConn{sconn: sconn, log: log}
	s.register(lc, true)
	defer s.register(lc, false)
	if sn = s.pin(); sn == nil {
		log.Warn("refusing login: the mount table is closed")
		return
	}
	defer sn.cfg.Mounts.Close()
	ext := sconn.Permissions.Extensions
	keyFields := []slog.Attr{}
	if fp := ext[auth.ExtFingerprint]; fp != "" {
		keyFields = append(keyFields, slog.String("key_fp", fp))
	}
	if serial, ok := ext[auth.ExtCertSerial]; ok {
		keyFields = append(keyFields, slog.String("cert_key_id", ext[auth.ExtCertKeyID]), slog.String("cert_serial", serial), slog.String("cert_ca_fp", ext[auth.ExtCertCA]))
	}
	if reason := sn.cfg.Auth.Refusal(sconn, sconn.Permissions); reason != "" {
		log.Info("login refused: revoked by a configuration reload", "reason", reason)
		ca.fail()
		al.Event("auth.failure", append([]slog.Attr{slog.String("user", name), slog.Int("attempts", int(ca.failures.Load())+1), slog.String("reason", reason)}, keyFields...)...)
		closed("revoked")
		return
	}
	al = al.With("user", name)
	success := append([]slog.Attr{slog.String("auth_method", ext[auth.ExtMethod])}, keyFields...)
	al.Event("auth.success", append(success, slog.Int("failed_attempts", int(ca.failures.Load())))...)

	go ssh.DiscardRequests(reqs)
	act := &activity{}
	act.touch(time.Now())
	done := make(chan struct{})
	defer close(done)
	go watch(sconn, act, sn.cfg.IdleTimeout, sn.cfg.KeepaliveInterval, done, lc.close)
	s.serveChannels(sn, chans, name, act, al, log)
	result := "ok"
	if r := lc.reason.Load(); r != nil {
		result = *r
	}
	closed(result)
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
	reason        atomic.Pointer[auth.RefusedError] // why valid credentials were refused
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

// config returns the server configuration for the connection: sn's
// transport settings, with callbacks that check the current snapshot.
func (ca *connAuth) config(sn *snapshot) *ssh.ServerConfig {
	cfg := *sn.ssh
	if sn.publicKey {
		// The key is checked when the client offers it, and again once the
		// client has proved that it holds it: x/crypto does not ask the
		// first callback again, and a reload may have come in between.
		cfg.PublicKeyCallback = func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !ca.user.same(md.User()) {
				return nil, errUserChanged
			}
			cur := ca.s.snap.Load()
			if !cur.publicKey {
				return nil, errMethodOff
			}
			perms, err := cur.cfg.Auth.KnownKey(md, key)
			ca.refused(err)
			return perms, err
		}
		cfg.VerifiedPublicKeyCallback = func(md ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			cur := ca.s.snap.Load()
			if !cur.publicKey {
				return nil, errMethodOff
			}
			perms, err := cur.cfg.Auth.VerifiedKey(md, key, perms)
			ca.refused(err)
			return perms, err
		}
	}
	if sn.password {
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
			cur := ca.s.snap.Load()
			if !cur.password {
				ca.fail()
				return nil, errMethodOff
			}
			perms, wait, err := cur.cfg.Auth.CheckPassword(md, password)
			ca.refused(err)
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
		if method != auth.MethodPassword || !sn.password {
			ca.keyFailures.Add(1)
		}
	}
	return &cfg
}

// refused records why a login with valid credentials was refused.
func (ca *connAuth) refused(err error) {
	if re, ok := errors.AsType[*auth.RefusedError](err); ok {
		ca.reason.Store(re)
	}
}

// keyAttrs are the audit fields of the key or certificate of a refused
// login.
func keyAttrs(key ssh.PublicKey, cert *ssh.Certificate) []slog.Attr {
	var attrs []slog.Attr
	if key != nil {
		attrs = append(attrs, slog.String("key_fp", ssh.FingerprintSHA256(key)))
	}
	if cert != nil {
		id, serial, ca := auth.CertAudit(cert)
		attrs = append(attrs, slog.String("cert_key_id", id), slog.String("cert_serial", serial), slog.String("cert_ca_fp", ca))
	}
	return attrs
}

// logRefused tells the operator why a login with the user's credentials
// was refused; the audit log has the reason only.
func logRefused(log *slog.Logger, user string, re *auth.RefusedError) {
	args := []any{"user", user, "reason", re.Reason}
	if re.Detail != "" {
		args = append(args, "detail", re.Detail)
	}
	if re.Cert != nil {
		id, serial, _ := auth.CertAudit(re.Cert)
		args = append(args, "cert_key_id", id, "cert_serial", serial)
	}
	log.Info("login refused", args...)
}

func (ca *connAuth) banned() bool {
	bans := ca.s.snap.Load().bans
	return ca.isIP && bans != nil && bans.Banned(ca.ip)
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
	bans := ca.s.snap.Load().bans
	if bans == nil || !ca.isIP || !bans.Fail(ca.ip) {
		return
	}
	src := auth.SourceKey(ca.ip).String()
	ca.s.log.Warn("banning source after repeated login failures", "source", src, "duration", bans.Duration())
	ca.al.Event("auth.ban", slog.String("source", src), slog.Int64("duration_ms", bans.Duration().Milliseconds()))
}

func (s *Server) serveChannels(sn *snapshot, chans <-chan ssh.NewChannel, user string, act *activity, al *audit.Logger, log *slog.Logger) {
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
		if int(active.Load()) >= sn.cfg.MaxSessionsPerConn {
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
			s.serveSession(sn, activeChannel{ch, act}, creqs, user, al, log)
		})
	}
}

// serveSession answers channel requests: only one "subsystem sftp" is
// accepted; shell, exec, pty-req, env and the rest are refused.
func (s *Server) serveSession(sn *snapshot, ch ssh.Channel, reqs <-chan *ssh.Request, user string, al *audit.Logger, log *slog.Logger) {
	var done chan struct{}
	for req := range reqs {
		if req.Type == "subsystem" && done == nil && isSFTP(req.Payload) {
			_ = req.Reply(true, nil)
			done = make(chan struct{})
			go func() {
				defer close(done)
				s.serveSFTP(sn, ch, user, al, log)
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

func (s *Server) serveSFTP(sn *snapshot, ch ssh.Channel, user string, al *audit.Logger, log *slog.Logger) {
	sessionID := newID()
	al = al.With("session_id", sessionID)
	log = log.With("session_id", sessionID)
	start := time.Now()
	al.Event("session.start")

	vs, unavailable := sn.cfg.Mounts.Session(user, sn.cfg.Grants(user))
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

	h := sftpd.New(vs, al, log, sn.cfg.MaxOpenHandles)
	rs := sftp.NewRequestServer(sftpd.NewGate(ch), h.Handlers(), sftp.WithStartDirectory("/"))
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
	errMethodOff   = errors.New("authentication method disabled by a reload")
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
