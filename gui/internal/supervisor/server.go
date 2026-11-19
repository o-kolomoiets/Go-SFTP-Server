// SPDX-License-Identifier: Apache-2.0

//go:build unix

package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Details are the connection details serve --print-details prints once
// it serves: the first listener and the first host key, then all of them.
type Details struct {
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	HostKeyFingerprint string    `json:"host_key_fingerprint"`
	KnownHosts         string    `json:"known_hosts"`
	PID                int       `json:"pid"`
	Version            string    `json:"version"`
	Listen             []string  `json:"listen"`
	HostKeys           []HostKey `json:"host_keys"`
	Addresses          []string  `json:"addresses"`
}

// HostKey is a host key of Details.
type HostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// SFTPCommand is the command a person types to connect as user.
func (d Details) SFTPCommand(user string) string {
	host := d.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if d.Port == 22 {
		return fmt.Sprintf("sftp %s@%s", user, host)
	}
	return fmt.Sprintf("sftp -P %d %s@%s", d.Port, user, host)
}

// StartError is a serve that did not start. Kind is that of its failure
// line: "listen" (such as a port that another program holds), "config",
// "sandbox" or "other"; empty when gosftpd ended without a line, as it
// does for an argument it cannot parse. Stderr holds the end of what
// gosftpd wrote.
type StartError struct {
	Kind    string
	Message string
	Address string // the address of kind "listen"
	Code    int    // the exit status
	Stderr  string
}

func (e *StartError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", e.Code)
	}
	return "gosftpd did not start: " + msg
}

// LogRecord is a line gosftpd wrote to stderr: a record of its JSON
// operational log, or Text for a line that is not JSON (an error of a
// start that failed, written as text too).
type LogRecord struct {
	Time  time.Time
	Level string
	Msg   string
	Attrs map[string]any
	Text  string
}

func parseLogLine(line []byte) LogRecord {
	var m map[string]any
	if json.Unmarshal(line, &m) != nil || m == nil {
		return LogRecord{Text: string(line)}
	}
	r := LogRecord{Attrs: m}
	if s, ok := m["time"].(string); ok {
		r.Time, _ = time.Parse(time.RFC3339Nano, s)
	}
	r.Level, _ = m["level"].(string)
	r.Msg, _ = m["msg"].(string)
	for _, k := range []string{"time", "level", "msg"} {
		delete(m, k)
	}
	return r
}

// Server is a running gosftpd serve.
type Server struct {
	cmd     *exec.Cmd
	stdin   *os.File // the write end of serve's stdin
	Details Details

	done    chan struct{}
	exitErr error

	mu       sync.Mutex
	stopping bool
	draining chan struct{} // closed once gosftpd logs that it shuts down
	reload   sync.Mutex    // one SIGHUP at a time
}

// stderrTail is how many lines of stderr a StartError keeps.
const stderrTail = 20

// Start runs gosftpd serve on the configuration and waits, until ctx
// ends, for its first line on stdout: the connection details, or why it
// did not start (*StartError). serve stops when its stdin, a pipe the
// Server holds, reaches end of file: when the GUI exits for any reason.
// log, if not nil, gets every line gosftpd writes to stderr, from another
// goroutine.
func (g Gosftpd) Start(ctx context.Context, log func(LogRecord)) (*Server, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// Not CommandContext: the Server, not a context, decides when it stops.
	cmd := exec.Command(g.Bin, "serve", "--config", g.Layout.Config(), "--print-details", "--stop-on-stdin-eof", "--log-format", "json") //nolint:gosec,noctx // G204: the gosftpd shipped with the GUI
	cmd.Env = childEnv(os.Environ())
	cmd.Dir = g.Layout.Dir
	cmd.Stdin = r
	// Its own process group: a Ctrl-C in the terminal that started the
	// GUI reaches the GUI, which stops gosftpd as Stop does.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, err
	}
	_ = r.Close() // gosftpd holds it now

	s := &Server{cmd: cmd, stdin: w, done: make(chan struct{}), draining: make(chan struct{})}
	first := make(chan []byte, 1)
	readsDone := make(chan struct{}, 2)
	go func() {
		br := bufio.NewReader(stdout)
		line, err := br.ReadBytes('\n')
		if err != nil && len(line) == 0 {
			line = nil
		}
		first <- line
		_, _ = io.Copy(io.Discard, br)
		readsDone <- struct{}{}
	}()
	var tailMu sync.Mutex
	var tail []string
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			rec := parseLogLine(sc.Bytes())
			tailMu.Lock()
			tail = append(tail, sc.Text())
			if len(tail) > stderrTail {
				tail = tail[len(tail)-stderrTail:]
			}
			tailMu.Unlock()
			if rec.Msg == "shutting down" {
				s.markDraining()
			}
			if log != nil {
				log(rec)
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
		readsDone <- struct{}{}
	}()
	go func() {
		// Wait only once both pipes are read to their end (os/exec).
		<-readsDone
		<-readsDone
		s.exitErr = cmd.Wait()
		s.markDraining()
		close(s.done)
	}()

	startErr := func(e *StartError) error {
		<-s.done
		e.Code = cmd.ProcessState.ExitCode()
		tailMu.Lock()
		e.Stderr = strings.Join(tail, "\n")
		tailMu.Unlock()
		_ = s.stdin.Close()
		return e
	}
	select {
	case line := <-first:
		if line == nil {
			return nil, startErr(&StartError{})
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			s.Kill()
			<-s.done
			return nil, fmt.Errorf("gosftpd serve: its first line is not JSON: %q", bytes.TrimSpace(line))
		}
		if _, failed := probe["error"]; failed {
			var f struct {
				Error   string `json:"error"`
				Kind    string `json:"kind"`
				Address string `json:"address"`
			}
			_ = json.Unmarshal(line, &f)
			return nil, startErr(&StartError{Kind: f.Kind, Message: f.Error, Address: f.Address})
		}
		if err := json.Unmarshal(line, &s.Details); err != nil {
			s.Kill()
			<-s.done
			return nil, fmt.Errorf("gosftpd serve: %w", err)
		}
		return s, nil
	case <-ctx.Done():
		s.Kill()
		<-s.done
		return nil, ctx.Err()
	}
}

func (s *Server) markDraining() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.draining:
	default:
		close(s.draining)
	}
}

// Done is closed when gosftpd has exited.
func (s *Server) Done() <-chan struct{} { return s.done }

// Err is how gosftpd exited, once Done is closed: nil for exit status 0.
func (s *Server) Err() error {
	<-s.done
	return s.exitErr
}

// Stop asks gosftpd to stop, as SIGTERM does: it stops accepting and
// waits up to shutdown_timeout (30 s by default) for the connections to
// end, then closes the rest. It returns at once; Done tells when gosftpd
// has exited.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.stopping = true
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
}

// StopNow ends gosftpd at once with the second SIGTERM, which cuts the
// connections that are still open ("Stop now"). That stop writes neither
// session.end nor server.stop to the audit log. If gosftpd has not begun
// to stop after a second, or still runs a few seconds later, it is
// killed.
func (s *Server) StopNow() {
	s.Stop()
	select {
	case <-s.draining:
	case <-s.done:
		return
	case <-time.After(time.Second):
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.Kill()
	}
}

// Kill kills gosftpd.
func (s *Server) Kill() { _ = s.cmd.Process.Kill() }

// Close closes the GUI's end of gosftpd's stdin, which stops it as Stop
// does: what happens on its own when the GUI exits.
func (s *Server) Close() error { return s.stdin.Close() }

// ErrNotRunning is a reload of a gosftpd that has exited.
var ErrNotRunning = errors.New("gosftpd is not running")

// Reload asks gosftpd to read its configuration again (SIGHUP, ADR 0005)
// and waits, until ctx ends, for its server.reload event in the audit log
// at auditLog. One reload runs at a time: two quick signals could give
// one reload. A failed reload keeps the running configuration; its text
// is in the operational log, since the audit log never names host paths.
func (s *Server) Reload(ctx context.Context, auditLog string) (ReloadResult, error) {
	s.reload.Lock()
	defer s.reload.Unlock()
	select {
	case <-s.done:
		return ReloadResult{}, ErrNotRunning
	default:
	}
	f := NewFollower(auditLog)
	if _, _, err := f.Poll(); err != nil { // to the end: only what follows counts
		return ReloadResult{}, err
	}
	if err := s.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return ReloadResult{}, err
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ReloadResult{}, ctx.Err()
		case <-s.done:
			return ReloadResult{}, ErrNotRunning
		case <-tick.C:
		}
		events, _, err := f.Poll()
		if err != nil {
			return ReloadResult{}, err
		}
		for _, e := range events {
			if e.Name == "server.reload" {
				return e.reloadResult(), nil
			}
		}
	}
}

// Restart stops s as Stop does, waits until ctx ends for it to exit, and
// starts gosftpd again: for a reload whose RestartRequired is not empty.
// A stop waits up to shutdown_timeout for the connections to end and cuts
// the rest, so the GUI restarts only when nobody is connected, or when the
// person says so (ADR 0013, "Restarts"). A new serve never starts while
// the old one runs: the two would share the port and the audit log.
func (g Gosftpd) Restart(ctx context.Context, s *Server, log func(LogRecord)) (*Server, error) {
	s.Stop()
	select {
	case <-s.Done():
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.Start(ctx, log)
}
