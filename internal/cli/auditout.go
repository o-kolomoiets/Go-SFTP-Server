// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// auditOutput is where the audit log goes: stdout or a file. Every
// connection's audit logger writes through the one auditOutput, so a reload
// can reopen the file (after logrotate moved it) or switch to another one
// without replacing the loggers.
type auditOutput struct {
	stdout io.Writer

	mu     sync.Mutex
	dest   string
	f      *os.File // nil for stdout, and while dest cannot be opened
	closed bool
}

func isStdout(dest string) bool { return dest == "" || dest == "stdout" }

// openAuditFile opens dest for appending; it returns nil for stdout.
// O_APPEND, unlike uploads: logrotate's copytruncate must not leave a hole
// of zeros.
func openAuditFile(dest string) (*os.File, error) {
	if isStdout(dest) {
		return nil, nil
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit output: %w", err)
	}
	return f, nil
}

func openAuditOutput(dest string, stdout io.Writer) (*auditOutput, error) {
	f, err := openAuditFile(dest)
	if err != nil {
		return nil, err
	}
	return &auditOutput{stdout: stdout, dest: dest, f: f}, nil
}

// Write writes one audit line; lines from different loggers do not
// interleave. While the file cannot be opened, every write tries again and
// fails until it can: the audit logger then refuses changes (fail-closed)
// or logs the events to stderr (fail-open). After Close, lines are dropped.
func (a *auditOutput) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.closed:
		return len(p), nil
	case isStdout(a.dest):
		return a.stdout.Write(p)
	case a.f == nil:
		f, err := openAuditFile(a.dest)
		if err != nil {
			return 0, err
		}
		a.f = f
	}
	return a.f.Write(p)
}

// reopen opens the file again, for logrotate. If that fails, the old file
// is closed all the same: a rotated file may be compressed and deleted, and
// lines written to it would be lost without an error.
func (a *auditOutput) reopen() error {
	a.mu.Lock()
	dest := a.dest
	a.mu.Unlock()
	f, err := openAuditFile(dest)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.dest != dest {
		if f != nil {
			_ = f.Close()
		}
		return err
	}
	if a.f != nil {
		_ = a.f.Close()
	}
	a.f = f
	return err
}

// use switches to dest, opened with openAuditFile.
func (a *auditOutput) use(dest string, f *os.File) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		if f != nil {
			_ = f.Close()
		}
		return
	}
	if a.f != nil {
		_ = a.f.Close()
	}
	a.dest, a.f = dest, f
}

// Close closes the file, if any; later lines are dropped.
func (a *auditOutput) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}
