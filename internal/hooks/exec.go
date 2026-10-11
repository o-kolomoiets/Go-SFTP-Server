// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Exec limits (ADR 0010).
const (
	outputCap = 4 << 10         // kept of stdout and of stderr
	waitDelay = 2 * time.Second // after the process exits or is killed
)

// runExec runs the hook's program for one event, at most once.
func (r *runner) runExec(s *Spec, it *item) string {
	e := it.ev
	log := r.d.log.With("hook", r.name, "event", e.Name, "user", e.User)
	if !e.Gone && !sameFile(e) {
		log.Info("hook skipped: file changed before the hook ran", "path", e.file())
		return resultSkipped
	}
	if err := untrusted(s.Exec.Argv); err != nil {
		log.Warn("hook not run: its program cannot be trusted", "reason", err.Error())
		return resultFailed
	}
	ctx, cancel := context.WithTimeout(r.d.killCtx, s.Exec.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Exec.Argv[0], s.Exec.Argv[1:]...) //nolint:gosec // argv comes from the configuration, never from a client
	cmd.Dir = workDir()
	cmd.Env = environment(e)
	ownGroup(cmd)
	start := time.Now()
	stdout, stderr, leftover, err := run(cmd, e.Line)
	dur := time.Since(start)
	if leftover {
		log.Debug("hook output still open after the program exited: a process left its group", "duration_ms", dur.Milliseconds())
	}
	if err == nil {
		log.Debug("hook ran", "duration_ms", dur.Milliseconds())
		return resultOK
	}
	reason := err.Error()
	switch {
	case r.d.killed.Load():
		reason = "killed at shutdown"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		reason = "timed out after " + s.Exec.Timeout.String()
	}
	log.Warn("hook failed", "reason", reason, "duration_ms", dur.Milliseconds(),
		"stdout", stdout, "stderr", stderr)
	return resultFailed
}

// run starts cmd with stdin and returns the start of its output and the
// leader's result. The pipes are gosftpd's own, so the wait ends when the
// leader exits; then the rest of its process group is killed at once. A
// process that left the group (setsid) and holds a pipe is cut off after
// waitDelay: leftover is then true.
func run(cmd *exec.Cmd, stdin []byte) (stdout, stderr string, leftover bool, err error) {
	inR, inW, err := os.Pipe()
	if err != nil {
		return "", "", false, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW)
		return "", "", false, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		closeAll(inR, inW, outR, outW)
		return "", "", false, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	err = cmd.Start()
	closeAll(inR, outW, errW) // the child has its copies
	if err != nil {
		closeAll(inW, outR, errR)
		return "", "", false, err
	}
	var o, e capWriter
	done := make(chan struct{}, 3)
	go func() {
		_, _ = inW.Write(stdin) // EPIPE when the program does not read it
		_ = inW.Close()
		done <- struct{}{}
	}()
	drain := func(r *os.File, w *capWriter) {
		_, _ = io.Copy(w, r)
		done <- struct{}{}
	}
	go drain(outR, &o)
	go drain(errR, &e)
	err = cmd.Wait()
	killGroup(cmd.Process.Pid) // what the hook left behind
	t := time.NewTimer(waitDelay)
	for n := 0; n < 3; {
		select {
		case <-done:
			n++
			continue
		case <-t.C:
			leftover = true
			closeAll(inW, outR, errR) // unblocks the copies
			for ; n < 3; n++ {
				<-done
			}
		}
	}
	t.Stop()
	closeAll(outR, errR)
	return o.String(), e.String(), leftover, err
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}

// sameFile reports whether the host path still names the file of the
// event: the same file and the same type. A symlink swapped in, a mount
// repointed or a newer file under the name all fail.
func sameFile(e *Event) bool {
	if e.Info == nil || e.HostPath == "" {
		return false
	}
	if t := e.Info.Mode(); !t.IsRegular() && !t.IsDir() {
		return false // a symlink a local user made, renamed by a client
	}
	fi, err := os.Lstat(e.HostPath)
	return err == nil && fi.Mode().Type() == e.Info.Mode().Type() && os.SameFile(fi, e.Info)
}

// environment returns the hook's environment: PATH and the event.
func environment(e *Event) []string {
	env := []string{
		"PATH=" + cleanPath(os.Getenv("PATH")),
		"GOSFTPD_EVENT=" + e.Name,
		"GOSFTPD_USER=" + e.User,
		"GOSFTPD_MOUNT=" + e.Mount,
		"GOSFTPD_PATH=" + e.Path,
		"GOSFTPD_HOST_PATH=" + e.HostPath,
		"GOSFTPD_CONN_ID=" + e.ConnID,
	}
	if e.Name == "fs.upload" || e.Name == "fs.rename" {
		env = append(env, "GOSFTPD_FINAL_PATH="+e.FinalPath)
	}
	if e.Name == "fs.rename" {
		env = append(env, "GOSFTPD_TARGET_PATH="+e.TargetPath)
	}
	return env
}

// cleanPath drops empty and relative elements of PATH, so that a command
// a hook calls by name is never looked up in a directory a client can
// write.
func cleanPath(p string) string {
	var keep []string
	for _, dir := range filepath.SplitList(p) {
		if dir != "" && filepath.IsAbs(dir) {
			keep = append(keep, dir)
		}
	}
	if len(keep) == 0 {
		return defaultPath
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// capWriter keeps the first outputCap bytes and discards the rest without
// an error: refusing more would kill a talkative program with SIGPIPE.
type capWriter struct{ b []byte }

func (w *capWriter) Write(p []byte) (int, error) {
	if room := outputCap - len(w.b); room > 0 {
		w.b = append(w.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (w *capWriter) String() string { return string(w.b) }
