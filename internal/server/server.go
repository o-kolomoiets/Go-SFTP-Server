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
	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
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

// Config configures a Server. New fixes CryptoPolicy, Audit, Log and
// Metrics; Reload changes the rest.
type Config struct {
	// HostKeys are used for key exchange, at most one per key type.
	HostKeys []ssh.Signer
	// HostCertificates are certificates of HostKeys (ssh.NewCertSigner),
	// each offered while it is valid.
	HostCertificates []ssh.Signer
	// AnnouncedKeys are announced with HostKeys and proved on request, but
	// not used for key exchange: next and previous keys (ADR 0008).
	AnnouncedKeys []ssh.Signer
	// AnnounceHostKeys announces the host keys to OpenSSH clients after
	// login (hostkeys-00@openssh.com), so that they learn new ones.
	AnnounceHostKeys bool

	Auth   *auth.Authenticator
	Mounts *vfs.Table
	// Grants returns the mounts an authenticated user may access; nil
	// grants every mount with all permissions (zero-config).
	Grants func(user string) []vfs.Grant
	Audit  *audit.Logger
	Log    *slog.Logger
	// Metrics counts connections, logins and SFTP operations; nil counts
	// nothing.
	Metrics *obs.Metrics
	// Hooks gets the file events (ADR 0010); nil runs no hooks. It lives
	// for the process: Reload does not replace it, the caller updates it.
	Hooks *hooks.Dispatcher

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

	// TrustedProxies are the peers whose connections begin with a PROXY
	// protocol header that names the client (ADR 0011): unmapped
	// addresses and prefixes, none of length 0. A connection from another
	// peer that begins with a header is refused. Each connection is
	// classified by the configuration current at its accept.
	TrustedProxies []netip.Prefix
}

// Server serves SFTP over SSH.
type Server struct {
	algos   algorithms
	audit   *audit.Logger
	log     *slog.Logger
	metrics *obs.Metrics
	hooks   *hooks.Dispatcher
	limits  *limiter
	rejects rejectLog
	// Warnings about PROXY protocol headers, at most one a minute each.
	headerWarn, untrustedWarn warnLimit

	// snap is the configuration for new logins (see snapshot).
	snap atomic.Pointer[snapshot]
	rmu  sync.Mutex     // serializes Reload
	bans *auth.BanTable // kept across reloads while bans stay on; guarded by rmu

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	live  map[*liveConn]struct{} // logged-in connections

	now func() time.Time // the clock for host certificates
}

// snapshot is the reloadable configuration. A connection takes its
// transport settings (host keys, handshake timeout, MaxAuthTries, offered
// methods) from the snapshot current at accept, and announces its host
// keys; every authentication attempt checks the current one; and once
// logged in, the connection holds the then current snapshot, and a
// reference to its mount table, for its life.
type snapshot struct {
	cfg Config // with defaults
	// ssh has no host keys: each connection adds its own to a copy (see
	// connAuth.config).
	ssh                 *ssh.ServerConfig
	announced           []ssh.Signer // host keys, then announced-only keys
	publicKey, password bool         // enabled methods
	bans                *auth.BanTable
	trusted             []netip.Prefix // trusted proxies, masked
}

// New validates cfg and returns a Server. The caller keeps cfg.Mounts open
// while it is the current table (see Reload).
func New(cfg Config) (*Server, error) {
	algos, err := policy(cfg.CryptoPolicy)
	if err != nil {
		return nil, err
	}
	s := &Server{
		algos:   algos,
		audit:   cfg.Audit,
		log:     cfg.Log,
		metrics: cfg.Metrics,
		hooks:   cfg.Hooks,
		conns:   make(map[net.Conn]struct{}),
		live:    make(map[*liveConn]struct{}),
		now:     time.Now,
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

// Reload switches new logins to cfg, and new connections to its host
// keys; CryptoPolicy, Audit, Log and Metrics are ignored. Open connections keep
// their host keys, also for re-keying; logged-in connections keep the
// configuration they logged in under; with cfg.DisconnectRevoked, those whose login cfg would refuse are
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
	announced, err := hostKeySet(&cfg)
	if err != nil {
		return nil, err
	}
	trusted, err := checkTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	sn := &snapshot{bans: cfg.Bans, announced: announced, trusted: trusted}
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

// admit applies bans and connection limits to a new connection, without
// I/O: it runs in the accept loop. A connection from a trusted proxy is
// held to max_connections and max_preauth_connections only; the ban and
// max_connections_per_ip apply to the client its header names
// (admitClient). admit closes a refused connection, before the SSH
// handshake, and returns nil.
func (s *Server) admit(c net.Conn) *admission {
	sn := s.snap.Load()
	ip, isIP := auth.SourceAddr(c.RemoteAddr())
	trusted := isIP && sn.trusts(ip)
	var src netip.Prefix
	if isIP && !trusted {
		src = auth.SourceKey(ip)
	}
	var (
		reason string
		adm    *admission
	)
	switch {
	case !s.audit.Healthy():
		reason = rejectAudit
	case src.IsValid() && sn.bans != nil && sn.bans.Banned(ip):
		reason = rejectBanned
	default:
		adm, reason = s.limits.admit(src)
	}
	if adm != nil {
		adm.trusted = trusted
		return adm
	}
	_ = c.Close()
	s.metrics.ConnectionRefused(reason)
	// The header is not read yet: a trusted proxy's connection has the
	// proxy's address.
	peer := c.RemoteAddr().String()
	kv := []any{"remote_addr", peer}
	if trusted {
		kv = append(kv, "proxy_addr", peer)
	}
	if reason == rejectAudit {
		s.log.Warn("refusing connection: audit log unavailable", kv...)
		return nil
	}
	s.log.Debug("connection refused", append(kv, "reason", reason)...)
	attrs := []slog.Attr{slog.String("remote_addr", peer), slog.String("local_addr", c.LocalAddr().String())}
	if trusted {
		attrs = append(attrs, slog.String("proxy_addr", peer))
	}
	s.auditReject(s.audit, reason, attrs...)
	return nil
}

// auditReject writes conn.reject, refused before the SSH handshake, at
// most rejectBurst a second.
func (s *Server) auditReject(al *audit.Logger, reason string, attrs ...slog.Attr) {
	ok, suppressed := s.rejects.allow(time.Now())
	if !ok {
		return
	}
	attrs = append(attrs, slog.String("reason", reason))
	if suppressed > 0 {
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	al.Event("conn.reject", attrs...)
}

// admitClient applies the ban and max_connections_per_ip to the client a
// trusted proxy's header names, or to the proxy itself for LOCAL and
// UNKNOWN: the second phase of admission. It returns why the connection is
// refused, or "".
func (s *Server) admitClient(conn net.Conn, adm *admission) string {
	ip, isIP := auth.SourceAddr(conn.RemoteAddr())
	if !isIP {
		return ""
	}
	if bans := s.snap.Load().bans; bans != nil && bans.Banned(ip) {
		return rejectBanned
	}
	return adm.addSource(auth.SourceKey(ip))
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
	// Every admitted connection ends with exactly one result: the one of
	// conn.close, or why there was none; or, refused before the handshake
	// once a trusted proxy's header was read, with the reason.
	s.metrics.ConnectionStarted()
	result, refused := "error", ""
	defer func() {
		if refused != "" {
			s.metrics.ConnectionEndedRefused(refused)
			return
		}
		s.metrics.ConnectionEnded(result)
	}()
	connID := newID()
	peer := c.RemoteAddr().String()
	log := s.log.With("conn_id", connID, "remote_addr", peer)
	if adm.trusted {
		log = s.log.With("conn_id", connID, "proxy_addr", peer)
	}
	defer func() {
		if r := recover(); r != nil {
			log.Error("panic while serving connection", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	defer c.Close()
	s.track(c, true)
	defer s.track(c, false)

	sn := s.snap.Load()
	accepted := sn // its host keys are the connection's
	start := time.Now()
	if err := c.SetDeadline(start.Add(sn.cfg.HandshakeTimeout)); err != nil {
		return
	}
	// What SSH runs on: for a trusted proxy, the connection after its
	// header, with the client's addresses.
	conn := c
	proxyAddr := ""
	if adm.trusted {
		proxyAddr = peer
		var reason string
		conn, reason = s.proxied(c, adm, start, sn.cfg.HandshakeTimeout, connID, log)
		if conn == nil {
			if reason == "" {
				result = "no_version" // a TCP health check
			}
			refused = reason
			return
		}
		log = log.With("remote_addr", conn.RemoteAddr().String())
	}

	al := s.audit.With(connContext(connID, conn, proxyAddr)...)
	ca := s.newConnAuth(conn, al)
	cfg := ca.config(sn)
	rc := &readConn{Conn: conn}
	sconn, chans, reqs, err := ssh.NewServerConn(rc, cfg)
	adm.authenticated()
	closed := func(r string) {
		result = r
		al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", r))
	}
	if err != nil {
		log.Debug("handshake failed", "err", err)
		switch {
		case rc.header.Load():
			result = rejectUntrustedProxy
			s.auditReject(al, rejectUntrustedProxy)
			s.warnClientHeader(adm.trusted, conn, peer)
		case !ca.accepted.Load() && !rc.read.Load():
			result = "no_version" // health checks, port scanners
		case !ca.accepted.Load():
			result = "handshake_failed"
		default:
			u, _ := ca.attemptedUser.Load().(string)
			attrs := []slog.Attr{slog.String("user", u), slog.Int("attempts", int(ca.failures.Load()))}
			if re := ca.reason.Load(); re != nil {
				logRefused(log, false, u, re)
				attrs = append(attrs, slog.String("reason", re.Reason))
				attrs = append(attrs, keyAttrs(re.Key, re.Cert)...)
			}
			al.Event("auth.failure", attrs...)
			s.metrics.Login(false)
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
	if re := sn.cfg.Auth.Refused(sconn, sconn.Permissions); re != nil {
		logRefused(log, true, name, re)
		ca.fail()
		al.Event("auth.failure", append([]slog.Attr{slog.String("user", name), slog.Int("attempts", int(ca.failures.Load())+1), slog.String("reason", re.Reason)}, keyFields...)...)
		s.metrics.Login(false)
		closed("revoked")
		return
	}
	al = al.With("user", name)
	success := append([]slog.Attr{slog.String("auth_method", ext[auth.ExtMethod])}, keyFields...)
	al.Event("auth.success", append(success, slog.Int("failed_attempts", int(ca.failures.Load())))...)
	s.metrics.Login(true)

	proofs := announce(accepted, sconn, al, log)
	go proofs.serve(reqs)
	act := &activity{}
	act.touch(time.Now())
	done := make(chan struct{})
	defer close(done)
	go watch(sconn, act, sn.cfg.IdleTimeout, sn.cfg.KeepaliveInterval, done, lc.close)
	s.serveChannels(sn, chans, name, connID, act, proofs, al, log)
	end := "ok"
	if r := lc.reason.Load(); r != nil {
		end = *r
	}
	closed(end)
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

// newConnAuth returns the authentication state of a connection; c has the
// client's address, also behind a trusted proxy.
func (s *Server) newConnAuth(c net.Conn, al *audit.Logger) *connAuth {
	ca := &connAuth{s: s, al: al}
	ca.ip, ca.isIP = auth.SourceAddr(c.RemoteAddr())
	return ca
}

// config returns the server configuration for the connection: sn's
// transport settings and host keys, with the host certificates valid now,
// and callbacks that check the current snapshot.
func (ca *connAuth) config(sn *snapshot) *ssh.ServerConfig {
	// sn.ssh has no host keys, so AddHostKey fills a new array for this
	// copy. Added to a copy of a config that has keys, it would write into
	// the array the copies share: a data race, and an open connection
	// could re-key with another connection's certificate (ADR 0008).
	cfg := *sn.ssh
	for _, k := range sn.cfg.HostKeys {
		cfg.AddHostKey(k)
	}
	now := ca.s.now()
	for _, c := range sn.cfg.HostCertificates {
		if certValid(c, now) {
			cfg.AddHostKey(c)
		}
	}
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
		if method == "none" {
			return
		}
		ca.s.metrics.AuthAttempt(method, err == nil)
		if err == nil {
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
// was refused; the audit log has the reason only. afterReload says that a
// reload during the login revoked it.
func logRefused(log *slog.Logger, afterReload bool, user string, re *auth.RefusedError) {
	args := []any{"user", user, "reason", re.Reason}
	if re.Detail != "" {
		args = append(args, "detail", re.Detail)
	}
	if re.Cert != nil {
		id, serial, _ := auth.CertAudit(re.Cert)
		args = append(args, "cert_key_id", id, "cert_serial", serial)
	}
	if afterReload {
		log.Info("login refused: revoked by a configuration reload", args...)
		return
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
	ca.s.metrics.Banned()
	src := auth.SourceKey(ca.ip).String()
	ca.s.log.Warn("banning source after repeated login failures", "source", src, "duration", bans.Duration())
	ca.al.Event("auth.ban", slog.String("source", src), slog.Int64("duration_ms", bans.Duration().Milliseconds()))
}

func (s *Server) serveChannels(sn *snapshot, chans <-chan ssh.NewChannel, user, connID string, act *activity, proofs *hostKeyProofs, al *audit.Logger, log *slog.Logger) {
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
			s.serveSession(sn, activeChannel{ch, act}, creqs, user, connID, proofs, al, log)
		})
	}
}

// serveSession answers channel requests: only one "subsystem sftp" is
// accepted; shell, exec, pty-req, env and the rest are refused.
func (s *Server) serveSession(sn *snapshot, ch ssh.Channel, reqs <-chan *ssh.Request, user, connID string, proofs *hostKeyProofs, al *audit.Logger, log *slog.Logger) {
	var done chan struct{}
	for req := range reqs {
		if req.Type == "subsystem" && done == nil && isSFTP(req.Payload) {
			_ = req.Reply(true, nil)
			done = make(chan struct{})
			go func() {
				defer close(done)
				s.serveSFTP(sn, ch, user, connID, proofs, al, log)
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

func (s *Server) serveSFTP(sn *snapshot, ch ssh.Channel, user, connID string, proofs *hostKeyProofs, al *audit.Logger, log *slog.Logger) {
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

	h := sftpd.New(vs, al, log, s.metrics, sn.cfg.MaxOpenHandles)
	h.SetHooks(s.hooks, connID)
	rs := sftp.NewRequestServer(sftpd.NewGate(ch), h.Handlers(), sftp.WithStartDirectory("/"))
	err := rs.Serve()

	// The client may still be waiting for a host key proof; it would not
	// once the session ends.
	proofs.wait(proofWait)
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

// ActiveBans returns the number of sources banned now; 0 with bans off.
func (s *Server) ActiveBans() int {
	if bans := s.snap.Load().bans; bans != nil {
		return bans.Active()
	}
	return 0
}

// readConn notes whether the client sent anything: a connection closed
// before the first byte is a health check or a port scan. It fails the
// connection when the first bytes are a PROXY protocol header (headerCheck),
// from any peer, also when no proxy is trusted. It is read by one goroutine
// at a time.
type readConn struct {
	net.Conn
	read   atomic.Bool
	header atomic.Bool // the first bytes were a PROXY protocol header
	check  headerCheck
}

func (c *readConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.read.Load() {
		c.read.Store(true)
	}
	if n > 0 && c.check.scan(p[:n]) {
		c.header.Store(true)
		return 0, errClientHeader
	}
	return n, err
}

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
