// SPDX-License-Identifier: Apache-2.0

package server

// Host key announcement and proofs: OpenSSH's hostkeys-00@openssh.com and
// hostkeys-prove-00@openssh.com (OpenSSH PROTOCOL, section 2.5), which
// x/crypto does not implement. They let OpenSSH clients learn a next host
// key before a rotation (ADR 0008).

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
)

const (
	hostkeysRequest = "hostkeys-00@openssh.com"
	proveRequest    = "hostkeys-prove-00@openssh.com"
	// proofWait bounds how long an SFTP session, before it ends, waits for
	// a proof in progress: the OpenSSH client exits when its session ends,
	// without waiting for the proof.
	proofWait = time.Second
)

// hostKeySet checks the host keys of cfg and returns the keys to announce:
// the host keys, then the announced-only keys.
func hostKeySet(cfg *Config) ([]ssh.Signer, error) {
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("no host keys")
	}
	types := map[string]bool{}
	for _, k := range cfg.HostKeys {
		t := k.PublicKey().Type()
		if types[t] {
			return nil, fmt.Errorf("two host keys of type %s: only one would be used", t)
		}
		types[t] = true
	}
	announced := append(append([]ssh.Signer(nil), cfg.HostKeys...), cfg.AnnouncedKeys...)
	seen := map[string]bool{}
	for _, k := range announced {
		blob := string(k.PublicKey().Marshal())
		if seen[blob] {
			// OpenSSH abandons an update that lists a key twice.
			return nil, fmt.Errorf("host key %s is given twice", ssh.FingerprintSHA256(k.PublicKey()))
		}
		seen[blob] = true
	}
	for _, c := range cfg.HostCertificates {
		cert, ok := c.PublicKey().(*ssh.Certificate)
		if !ok || cert.CertType != ssh.HostCert {
			return nil, errors.New("a host certificate signer without a host certificate")
		}
		if !slices.ContainsFunc(cfg.HostKeys, func(k ssh.Signer) bool { return bytes.Equal(k.PublicKey().Marshal(), cert.Key.Marshal()) }) {
			return nil, fmt.Errorf("host certificate of %s: not one of the host keys", ssh.FingerprintSHA256(cert.Key))
		}
	}
	return announced, nil
}

// certValid reports whether a host certificate signer is valid at now.
func certValid(s ssh.Signer, now time.Time) bool {
	cert, ok := s.PublicKey().(*ssh.Certificate)
	if !ok {
		return false
	}
	t := now.Unix()
	if t < 0 {
		return false
	}
	u := uint64(t)
	return cert.ValidAfter <= u && (cert.ValidBefore == ssh.CertTimeInfinity || u < cert.ValidBefore)
}

// hostKeyProofs announces a connection's host keys and answers its global
// requests.
type hostKeyProofs struct {
	sconn *ssh.ServerConn
	al    *audit.Logger
	log   *slog.Logger
	keys  []ssh.Signer // announced; nil when nothing was announced
	blobs [][]byte     // keys' public keys, marshaled

	started atomic.Bool   // a proof is being answered
	done    chan struct{} // closed once it is
}

// announce sends the host keys of sn, the snapshot the connection was
// accepted under, to an OpenSSH client, once.
func announce(sn *snapshot, sconn *ssh.ServerConn, al *audit.Logger, log *slog.Logger) *hostKeyProofs {
	p := &hostKeyProofs{sconn: sconn, al: al, log: log, done: make(chan struct{})}
	switch {
	case !sn.cfg.AnnounceHostKeys:
		return p
	case !strings.HasPrefix(string(sconn.ClientVersion()), "SSH-2.0-OpenSSH"):
		// Only OpenSSH uses it, and sshd skips clients that break on it.
		log.Debug("host keys not announced: the client is not OpenSSH")
		return p
	}
	var payload []byte
	blobs := make([][]byte, len(sn.announced))
	for i, k := range sn.announced {
		blobs[i] = k.PublicKey().Marshal()
		payload = appendString(payload, blobs[i])
	}
	if _, _, err := sconn.SendRequest(hostkeysRequest, false, payload); err != nil {
		return p
	}
	p.keys, p.blobs = sn.announced, blobs
	return p
}

// serve answers the global requests in order until the connection closes:
// the first proof request after the announcement; every other request is
// refused.
func (p *hostKeyProofs) serve(reqs <-chan *ssh.Request) {
	answered := false
	for req := range reqs {
		if req.Type == proveRequest && req.WantReply && !answered && p.keys != nil {
			answered = true
			p.started.Store(true)
			p.prove(req)
			close(p.done)
			continue
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// wait waits, at most d, for a proof in progress to be sent.
func (p *hostKeyProofs) wait(d time.Duration) {
	if p == nil || !p.started.Load() {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.done:
	case <-t.C:
	}
}

// prove answers a proof request: one signature per requested key, in order.
func (p *hostKeyProofs) prove(req *ssh.Request) {
	keys, err := p.requested(req.Payload)
	if err != nil {
		p.log.Debug("host key proof refused", "err", err)
		_ = req.Reply(false, nil)
		return
	}
	rsaAlgo := proofAlgorithm(p.sconn)
	sid := p.sconn.SessionID()
	var resp []byte
	fps := make([]string, len(keys))
	for i, k := range keys {
		data := ssh.Marshal(struct {
			Type      string
			SessionID []byte
			Key       []byte
		}{proveRequest, sid, k.PublicKey().Marshal()})
		sig, err := signProof(k, data, rsaAlgo)
		fps[i] = ssh.FingerprintSHA256(k.PublicKey())
		if err != nil {
			p.log.Error("cannot sign a host key proof", "key_fp", fps[i], "err", err)
			_ = req.Reply(false, nil)
			return
		}
		resp = appendString(resp, ssh.Marshal(sig))
	}
	if err := req.Reply(true, resp); err != nil {
		return
	}
	p.al.Event("conn.hostkeys_proved", slog.String("key_fps", strings.Join(fps, ",")))
}

// requested parses a proof request: strings, each the public key of an
// announced key, none twice.
func (p *hostKeyProofs) requested(payload []byte) ([]ssh.Signer, error) {
	var keys []ssh.Signer
	seen := make([]bool, len(p.keys))
	for len(payload) > 0 {
		blob, rest, ok := parseString(payload)
		if !ok {
			return nil, errors.New("malformed request")
		}
		payload = rest
		i := -1
		for j, b := range p.blobs {
			if bytes.Equal(b, blob) {
				i = j
				break
			}
		}
		switch {
		case i < 0:
			return nil, errors.New("a key that was not announced")
		case seen[i]:
			return nil, errors.New("a key requested twice")
		}
		seen[i] = true
		keys = append(keys, p.keys[i])
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys requested")
	}
	return keys, nil
}

// proofAlgorithm returns the algorithm of RSA proofs: the RSA algorithm of
// the connection's key exchange, which the client verifies the proof with,
// or rsa-sha2-512 after a key exchange with another key type (as sshd).
func proofAlgorithm(sconn *ssh.ServerConn) string {
	if m, ok := sconn.Conn.(ssh.AlgorithmsConnMetadata); ok {
		switch m.Algorithms().HostKey {
		case ssh.KeyAlgoRSASHA256, ssh.CertAlgoRSASHA256v01:
			return ssh.KeyAlgoRSASHA256
		}
	}
	return ssh.KeyAlgoRSASHA512
}

func signProof(k ssh.Signer, data []byte, rsaAlgo string) (*ssh.Signature, error) {
	if k.PublicKey().Type() != ssh.KeyAlgoRSA {
		return k.Sign(rand.Reader, data)
	}
	as, ok := k.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("the RSA key cannot sign with SHA-2")
	}
	return as.SignWithAlgorithm(rand.Reader, data, rsaAlgo)
}

// appendString appends an SSH string.
func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: keys and signatures are a few KiB
	return append(b, s...)
}

// parseString splits an SSH string off b.
func parseString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint64(n) > uint64(len(b)) {
		return nil, nil, false
	}
	return b[:n], b[n:], true
}
