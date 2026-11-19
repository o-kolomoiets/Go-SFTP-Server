// SPDX-License-Identifier: Apache-2.0

//go:build unix

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// ErrRunning means that another gosftpd-gui of this user runs.
var ErrRunning = errors.New("gosftpd-gui is already running")

// Lock is the lock of the one GUI a user runs (ADR 0013, "One GUI per
// user, one server per state directory"), with the pid of its gosftpd.
type Lock struct {
	f   *os.File
	pid string // the pid file
}

// AcquireLock takes the lock in dir, the runtime directory: ErrRunning
// when another GUI holds it. The lock goes with the process: a GUI that
// dies releases it.
func AcquireLock(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, "gosftpd-gui.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	return &Lock{f: f, pid: filepath.Join(dir, "gosftpd-gui.pid")}, nil
}

// Release releases the lock.
func (l *Lock) Release() error { return l.f.Close() }

// SetServer records pid, the gosftpd the GUI started, so that a GUI
// started after this one died finds a server still draining.
func (l *Lock) SetServer(pid int) error {
	return os.WriteFile(l.pid, []byte(strconv.Itoa(pid)+"\n"), 0o600)
}

// ClearServer forgets the gosftpd, which has exited.
func (l *Lock) ClearServer() error {
	if err := os.Remove(l.pid); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// PreviousServer returns the pid of a gosftpd that a GUI before this one
// started on layout and that still runs, 0 if there is none. A killed GUI
// leaves its gosftpd draining for up to shutdown_timeout; a new serve on
// the same state directory and port would mix its audit events with the
// old one's, so the GUI waits for it to exit.
func (l *Lock) PreviousServer(layout Layout) (int, error) {
	data, err := os.ReadFile(l.pid)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, l.ClearServer()
	}
	if !servesLayout(pid, layout) {
		return 0, l.ClearServer()
	}
	return pid, nil
}

// servesLayout reports whether pid is a gosftpd serve of layout's
// configuration: a pid that was reused for another process is not.
func servesLayout(pid int, layout Layout) bool {
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	var cmdline []string
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return false
		}
		cmdline = strings.Split(string(bytes.TrimRight(data, "\x00")), "\x00")
	} else {
		out, err := exec.CommandContext(context.Background(), "ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: a pid read back as a number
		if err != nil {
			return false
		}
		cmdline = strings.Fields(string(out))
	}
	return isServeOf(cmdline, layout.Config())
}

// isServeOf reports whether the command line is gosftpd serve with
// --config config.
func isServeOf(cmdline []string, config string) bool {
	if len(cmdline) < 2 || filepath.Base(cmdline[0]) != "gosftpd" || cmdline[1] != "serve" {
		return false
	}
	for i, a := range cmdline {
		if a == "--config="+config || (a == "--config" && i+1 < len(cmdline) && cmdline[i+1] == config) {
			return true
		}
	}
	return false
}
