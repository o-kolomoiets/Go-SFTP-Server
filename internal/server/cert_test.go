// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/rand"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// certSigner signs a certificate of key for principals, valid from an hour
// ago until before, and returns a signer that logs in with it.
func certSigner(t *testing.T, ca, key ssh.Signer, before time.Time, principals ...string) ssh.Signer {
	t.Helper()
	c := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "alice-laptop",
		Serial:          math.MaxUint64,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(before.Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(c, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func trustingAuth(users []auth.User, cas []ssh.PublicKey, revoked *auth.RevokedKeys) *auth.Authenticator {
	a := auth.NewUsers(users)
	a.Trust(cas, revoked)
	return a
}

// A certificate from a trusted CA logs in; the audit log names it. An
// expired one is refused with the reason, and the client learns nothing.
func TestCertificateLogin(t *testing.T) {
	t.Parallel()

	ca, key := signer(t), signer(t)
	users := []auth.User{{Name: "alice"}}
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Auth = trustingAuth(users, []ssh.PublicKey{ca.PublicKey()}, nil)
	}})

	c, err := e.dialAs(t, "alice", certSigner(t, ca, key, time.Now().Add(time.Hour), "alice"))
	if err != nil {
		t.Fatalf("certificate login: %v", err)
	}
	if got, err := readRemote(t, newSFTP(t, c), "a.txt"); err != nil || got != "original content" {
		t.Errorf("read %q, %v", got, err)
	}
	c.Close()
	if c, err := e.dialAs(t, "alice", certSigner(t, ca, key, time.Now().Add(-time.Minute), "alice")); err == nil {
		c.Close()
		t.Error("an expired certificate logged in")
	}
	if c, err := e.dialAs(t, "alice", certSigner(t, signer(t), key, time.Now().Add(time.Hour), "alice")); err == nil {
		c.Close()
		t.Error("a certificate from an untrusted CA logged in")
	}
	waitForMsg(t, func() bool { return strings.Count(e.auditLog.String(), `"event":"auth.failure"`) == 2 },
		func() string { return "want two auth.failure events:\n" + e.auditLog.String() })

	lines := auditLines(t, e.auditLog.String())
	checkSchema(t, lines)
	var success, refused, denied map[string]any
	for _, l := range lines {
		switch {
		case l["event"] == "auth.success":
			success = l
		case l["event"] == "auth.failure" && l["reason"] != nil:
			refused = l
		case l["event"] == "auth.failure":
			denied = l
		}
	}
	want := map[string]any{
		"key_fp":      ssh.FingerprintSHA256(key.PublicKey()),
		"cert_key_id": "alice-laptop",
		"cert_serial": "18446744073709551615",
		"cert_ca_fp":  ssh.FingerprintSHA256(ca.PublicKey()),
	}
	for k, v := range want {
		if success[k] != v {
			t.Errorf("auth.success %s = %v, want %v", k, success[k], v)
		}
		if refused[k] != v {
			t.Errorf("auth.failure %s = %v, want %v", k, refused[k], v)
		}
		if _, ok := denied[k]; ok {
			t.Errorf("auth.failure of an untrusted certificate names it (%s)", k)
		}
	}
	if refused["reason"] != auth.ReasonCertExpired {
		t.Errorf("reason = %v", refused["reason"])
	}
}

// A reload that revokes the certified key closes the connection with
// disconnect_removed_users, and refuses new logins.
func TestCertificateRevokedOnReload(t *testing.T) {
	t.Parallel()

	ca, key := signer(t), signer(t)
	users := []auth.User{{Name: "alice"}}
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Auth = trustingAuth(users, []ssh.PublicKey{ca.PublicKey()}, nil)
	}})
	cert := certSigner(t, ca, key, time.Now().Add(time.Hour), "alice")
	c, err := e.dialAs(t, "alice", cert)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	old := newSFTP(t, c) // the server pins the login once a session works
	if _, err := old.Getwd(); err != nil {
		t.Fatal(err)
	}
	revoked := &auth.RevokedKeys{}
	if err := revoked.Add(ssh.MarshalAuthorizedKey(cert.PublicKey()), "revoked"); err != nil {
		t.Fatal(err)
	}
	n := e.reload(t, func(c *Config) {
		c.Auth = trustingAuth(users, []ssh.PublicKey{ca.PublicKey()}, revoked)
		c.DisconnectRevoked = true
	})
	if n != 1 {
		t.Errorf("disconnected %d connections, want 1", n)
	}
	waitFor(t, func() bool { _, err := old.Getwd(); return err != nil })
	if c, err := e.dialAs(t, "alice", cert); err == nil {
		c.Close()
		t.Error("a revoked certificate logged in")
	}
	waitForMsg(t, func() bool { return strings.Contains(e.auditLog.String(), `"reason":"key_revoked"`) },
		func() string { return "no auth.failure with reason key_revoked:\n" + e.auditLog.String() })
	checkSchema(t, auditLines(t, e.auditLog.String()))
}
