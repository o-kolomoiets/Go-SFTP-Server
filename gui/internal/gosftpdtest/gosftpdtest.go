// SPDX-License-Identifier: Apache-2.0

// Package gosftpdtest has helpers for the GUI's tests only: the gosftpd
// of this repository, keys, and OpenSSH sftp to connect with.
package gosftpdtest

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Build builds gosftpd from the repository at root, the parent module of
// the GUI's (the GUI runs the gosftpd of its own release), into a new
// temporary directory. clean removes it.
func Build(root string) (bin string, clean func(), err error) {
	dir, err := os.MkdirTemp("", "gosftpd-gui-test-")
	if err != nil {
		return "", nil, err
	}
	clean = func() { _ = os.RemoveAll(dir) }
	bin = filepath.Join(dir, "gosftpd")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "./cmd/gosftpd")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		clean()
		return "", nil, fmt.Errorf("building gosftpd: %w\n%s", err, out)
	}
	return bin, clean, nil
}

// SkipRoot skips a test as root: gosftpd refuses to run as root.
func SkipRoot(tb testing.TB) {
	tb.Helper()
	if os.Geteuid() == 0 {
		tb.Skip("gosftpd refuses to run as root")
	}
}

// FreePort returns a TCP port nobody listens on now.
func FreePort(tb testing.TB) int {
	tb.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

var keyMu sync.Mutex

// KeyPair makes an ed25519 key pair with ssh-keygen and returns the
// private key's file and the authorized_keys line.
func KeyPair(tb testing.TB) (file, pub string) {
	tb.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	file = filepath.Join(tb.TempDir(), "id_ed25519")
	if out, err := exec.CommandContext(context.Background(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", file).CombinedOutput(); err != nil {
		tb.Skipf("ssh-keygen: %v %s", err, out)
	}
	data, err := os.ReadFile(file + ".pub")
	if err != nil {
		tb.Fatal(err)
	}
	return file, strings.TrimSpace(string(data))
}

// Session opens an OpenSSH sftp session as user with key, which stays
// open until end is called: sftp reads its batch from a pipe that only
// end closes.
func Session(tb testing.TB, host string, port int, knownHosts, user, key string) (end func()) {
	tb.Helper()
	if _, err := exec.LookPath("sftp"); err != nil {
		tb.Skip("no OpenSSH sftp")
	}
	known := filepath.Join(tb.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(knownHosts+"\n"), 0o600); err != nil {
		tb.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), "sftp", "-b", "-", "-i", key, "-P", strconv.Itoa(port),
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known,
		"-o", "BatchMode=yes", "-o", "LogLevel=ERROR", user+"@"+host)
	in, err := cmd.StdinPipe()
	if err != nil {
		tb.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		tb.Fatal(err)
	}
	var once sync.Once
	end = func() {
		once.Do(func() {
			_ = in.Close()
			_ = cmd.Wait() // the server may have cut it
		})
	}
	tb.Cleanup(end)
	return end
}

// SFTP runs the batch commands with OpenSSH sftp as user with key, on
// host and port, checking the host key against the knownHosts line.
func SFTP(tb testing.TB, host string, port int, knownHosts, user, key, batch string) string {
	tb.Helper()
	if _, err := exec.LookPath("sftp"); err != nil {
		tb.Skip("no OpenSSH sftp")
	}
	known := filepath.Join(tb.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(knownHosts+"\n"), 0o600); err != nil {
		tb.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), "sftp", "-b", "-", "-i", key, "-P", strconv.Itoa(port),
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+known,
		"-o", "BatchMode=yes", "-o", "LogLevel=ERROR", user+"@"+host)
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("sftp: %v\n%s", err, out)
	}
	return string(out)
}
