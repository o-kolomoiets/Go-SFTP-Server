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

// Defaults.
const (
	DefaultHandshakeTimeout = 30 * time.Second
	DefaultMaxSessions      = 4
	DefaultMaxAuthTries     = 6
	serverVersion           = "SSH-2.0-gosftpd"
	maxClientVersionLen     = 128
)

// Modern algorithm profile (ROADMAP §7.6): no SHA-1, CBC or DSA.
var (
	kexAlgos = []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519}
	ciphers  = []string{
		ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM,
		ssh.CipherAES256CTR, ssh.CipherAES128CTR,
	}
	macs = []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM}
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

	HandshakeTimeout   time.Duration // default DefaultHandshakeTimeout
	MaxSessionsPerConn int           // default DefaultMaxSessions
	MaxOpenHandles     int           // per SFTP session, default sftpd.DefaultMaxHandles
	MaxAuthTries       int           // default DefaultMaxAuthTries
}

// Server serves SFTP over SSH.
type Server struct {
	cfg    Config
	sshCfg *ssh.ServerConfig

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
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.MaxSessionsPerConn <= 0 {
		cfg.MaxSessionsPerConn = DefaultMaxSessions
	}
	if cfg.MaxAuthTries <= 0 {
		cfg.MaxAuthTries = DefaultMaxAuthTries
	}
	if cfg.Grants == nil {
		mounts := cfg.Mounts
		cfg.Grants = func(string) []vfs.Grant { return mounts.FullAccess() }
	}

	sc := &ssh.ServerConfig{
		Config:                  ssh.Config{KeyExchanges: kexAlgos, Ciphers: ciphers, MACs: macs},
		PublicKeyCallback:       cfg.Auth.PublicKey,
		PublicKeyAuthAlgorithms: ssh.SupportedAlgorithms().PublicKeyAuths,
		MaxAuthTries:            cfg.MaxAuthTries,
		ServerVersion:           serverVersion,
	}
	for _, k := range cfg.HostKeys {
		sc.AddHostKey(k)
	}
	return &Server{cfg: cfg, sshCfg: sc, conns: make(map[net.Conn]struct{})}, nil
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
		s.wg.Go(func() { s.ServeConn(c) })
	}
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

// ServeConn handles one connection until it closes.
func (s *Server) ServeConn(c net.Conn) {
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

	if !s.cfg.Audit.Healthy() {
		log.Warn("refusing connection: audit log unavailable")
		return
	}
	al := s.cfg.Audit.With("conn_id", connID, "remote_addr", c.RemoteAddr().String(), "local_addr", c.LocalAddr().String())

	// Per-connection callbacks: they only record, they never decide.
	var (
		accepted      atomic.Bool
		failures      atomic.Int32
		attemptedUser atomic.Value
	)
	cfg := *s.sshCfg
	cfg.PreAuthConnCallback = func(pc ssh.ServerPreAuthConn) {
		accepted.Store(true)
		v := string(pc.ClientVersion())
		if len(v) > maxClientVersionLen {
			v = v[:maxClientVersionLen]
		}
		al.Event("conn.accept", slog.String("client_version", v))
	}
	cfg.AuthLogCallback = func(md ssh.ConnMetadata, method string, err error) {
		if method != "none" && err != nil {
			failures.Add(1)
			attemptedUser.Store(md.User())
		}
	}

	start := time.Now()
	if err := c.SetDeadline(start.Add(s.cfg.HandshakeTimeout)); err != nil {
		return
	}
	sconn, chans, reqs, err := ssh.NewServerConn(c, &cfg)
	if err != nil {
		log.Debug("handshake failed", "err", err)
		if accepted.Load() {
			u, _ := attemptedUser.Load().(string)
			al.Event("auth.failure", slog.String("user", u), slog.Int("attempts", int(failures.Load())))
			al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", "error"))
		}
		return
	}
	defer sconn.Close()
	if err := c.SetDeadline(time.Time{}); err != nil {
		return
	}

	user, ok := auth.UserFrom(sconn.Permissions)
	if !ok {
		log.Error("authenticated connection without a user")
		return
	}
	al = al.With("user", user)
	log = log.With("user", user)
	al.Event("auth.success",
		slog.String("auth_method", "publickey"),
		slog.String("key_fp", sconn.Permissions.Extensions[auth.ExtFingerprint]),
		slog.Int("failed_attempts", int(failures.Load())))

	go ssh.DiscardRequests(reqs)
	s.serveChannels(chans, user, al, log)
	al.Event("conn.close", slog.Int64("duration_ms", time.Since(start).Milliseconds()), slog.String("result", "ok"))
}

func (s *Server) serveChannels(chans <-chan ssh.NewChannel, user string, al *audit.Logger, log *slog.Logger) {
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
			s.serveSession(ch, creqs, user, al, log)
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
