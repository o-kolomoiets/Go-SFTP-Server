// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// waitMetrics waits until every series has its value.
func waitMetrics(t *testing.T, m *obs.Metrics, want map[string]float64) {
	t.Helper()
	waitForMsg(t, func() bool {
		for series, v := range want {
			if got, _ := m.Value(series); got != v {
				return false
			}
		}
		return true
	}, func() string {
		var b strings.Builder
		for series, v := range want {
			got, ok := m.Value(series)
			fmt.Fprintf(&b, "\n  %s = %v (%v), want %v", series, got, ok, v)
		}
		return b.String()
	})
}

// Every admitted connection ends with exactly one result, also those that
// never reach conn.close: probes send nothing, scanners no valid version.
func TestConnectionMetrics(t *testing.T) {
	t.Parallel()

	m := obs.NewMetrics("test")
	var bans *auth.BanTable
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) {
		c.Metrics = m
		bans = auth.NewBanTable(auth.BanOptions{AfterFailures: 2})
		c.Bans = bans
	}})
	var d net.Dialer

	// A health check: connect, read the banner, close without a byte.
	c, ok := silentDial(t, e.addr, &d)
	if !ok {
		t.Fatal("probe refused")
	}
	c.Close()
	// A scanner that sends no SSH version.
	c, err := d.DialContext(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_, _ = c.Read(make([]byte, 64))
	c.Close()
	waitMetrics(t, m, map[string]float64{
		`gosftpd_connections_total{result="no_version"}`:       1,
		`gosftpd_connections_total{result="handshake_failed"}`: 1,
		`gosftpd_connections_active`:                           0,
	})

	// A login with an SFTP session: operations and bytes.
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sc, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	writeRemote(t, sc, "/up.txt", "12345")
	if _, err := readRemote(t, sc, "/up.txt"); err != nil {
		t.Fatal(err)
	}
	writeRemote(t, sc, "/a.txt", "conflict") // on_conflict = "rename"
	if err := sc.PosixRename("/up.txt", "/a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := sc.Rename("/a.txt", "/up.txt"); err != nil {
		t.Fatal(err)
	}
	if err := sc.Rename("/up.txt", "/a (1).txt"); err == nil { // v3 RENAME onto an existing name
		t.Fatal("v3 rename replaced a file")
	}
	if _, err := sc.Stat("/missing"); err == nil {
		t.Fatal("stat of a missing file")
	}
	if err := sc.Symlink("/a.txt", "/link"); err == nil {
		t.Fatal("symlink created")
	}
	waitMetrics(t, m, map[string]float64{
		`gosftpd_logins_total{result="success"}`:                           1,
		`gosftpd_auth_attempts_total{method="publickey",result="success"}`: 1,
		`gosftpd_connections_active`:                                       1,
		`gosftpd_sftp_operations_total{op="upload",result="ok"}`:           2,
		`gosftpd_sftp_operations_total{op="download",result="ok"}`:         1,
		`gosftpd_sftp_operations_total{op="rename",result="ok"}`:           2,
		`gosftpd_sftp_operations_total{op="rename",result="error"}`:        1,
		`gosftpd_sftp_operations_total{op="stat",result="not_found"}`:      1,
		`gosftpd_sftp_operations_total{op="other",result="denied"}`:        1,
		`gosftpd_transfer_bytes_total{direction="upload"}`:                 13,
		`gosftpd_transfer_bytes_total{direction="download"}`:               5,
		`gosftpd_transfer_duration_seconds_count{direction="upload"}`:      2,
		`gosftpd_transfer_duration_seconds_count{direction="download"}`:    1,
		`gosftpd_conflicts_total{conflict="renamed",op="upload"}`:          1,
		`gosftpd_conflicts_total{conflict="renamed",op="rename"}`:          1,
	})

	// Wrong keys: failed attempts, failed logins, then a ban and refusals.
	wrong := []ssh.Signer{signer(t), signer(t)}
	for range 2 {
		if c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
			User: "alice", Auth: []ssh.AuthMethod{ssh.PublicKeys(wrong...)},
			HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
		}); err == nil {
			c.Close()
			t.Fatal("wrong keys accepted")
		}
	}
	waitMetrics(t, m, map[string]float64{
		`gosftpd_auth_attempts_total{method="publickey",result="failure"}`: 4,
		`gosftpd_logins_total{result="failure"}`:                           2,
		`gosftpd_connections_total{result="error"}`:                        2,
		`gosftpd_bans_total`:                                               1,
	})
	if n := e.srv.ActiveBans(); n != 1 {
		t.Errorf("ActiveBans() = %d", n)
	}
	if _, ok := silentDial(t, e.addr, &d); ok {
		t.Fatal("banned source admitted")
	}
	waitMetrics(t, m, map[string]float64{`gosftpd_connections_refused_total{reason="banned"}`: 1})

	// The SFTP connection ends: ok.
	sc.Close()
	conn.Close()
	waitMetrics(t, m, map[string]float64{
		`gosftpd_connections_total{result="ok"}`: 1,
		`gosftpd_connections_active`:             0,
	})
}

// Under on_conflict = "reject" an upload onto an existing name is denied
// and counted as a rejected conflict; v3 RENAME and O_EXCL are not.
func TestRejectedConflictMetrics(t *testing.T) {
	t.Parallel()

	m := obs.NewMetrics("test")
	e := startWith(t, startOpts{policy: vfs.ConflictReject, tweak: func(c *Config) { c.Metrics = m }})
	sc := e.sftp(t)
	if _, err := sc.Create("/a.txt"); err == nil {
		t.Fatal("upload replaced a file under reject")
	}
	if err := sc.PosixRename("/a.txt", "/a.txt.bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.share, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sc.PosixRename("/a.txt.bak", "/b.txt"); err == nil {
		t.Fatal("posix-rename replaced a file under reject")
	}
	if _, err := sc.OpenFile("/b.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		t.Fatal("O_EXCL opened an existing file")
	}
	waitMetrics(t, m, map[string]float64{
		`gosftpd_sftp_operations_total{op="upload",result="denied"}`: 1,
		`gosftpd_sftp_operations_total{op="upload",result="error"}`:  1,
		`gosftpd_sftp_operations_total{op="rename",result="denied"}`: 1,
		`gosftpd_conflicts_total{conflict="rejected",op="upload"}`:   1,
		`gosftpd_conflicts_total{conflict="rejected",op="rename"}`:   1,
	})
}

// A refusal for an unavailable audit log is counted, though not audited.
func TestRefusedAuditMetrics(t *testing.T) {
	t.Parallel()

	m := obs.NewMetrics("test")
	e := startWith(t, startOpts{policy: vfs.ConflictRename, tweak: func(c *Config) { c.Metrics = m }})
	e.auditLog.setFail(true)
	if c, err := e.dial(t, e.userKey); err == nil {
		c.Close() // the login's own events fail the log
	}
	waitForMsg(t, func() bool {
		if _, ok := silentDial(t, e.addr, &net.Dialer{}); ok {
			return false
		}
		v, _ := m.Value(`gosftpd_connections_refused_total{reason="audit_unavailable"}`)
		return v >= 1
	}, func() string { return "no refusal counted" })
}
