// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestEphemeralReadyAfterDetails: serve --ephemeral prints its line just
// before it reports ready.
func TestEphemeralReadyAfterDetails(t *testing.T) {
	isolate(t)
	ephemeralTemp(t)
	next := notifySocket(t)
	ts := startServe(t, "--ephemeral")
	next("READY=1")
	if out := ts.stdout.String(); !strings.HasSuffix(out, "}\n") {
		t.Errorf("READY=1 before the details; stdout %q", out)
	}
	decodeDetails(t, ts.stdout.String())
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}

// brokenPipeEnv makes this test binary the child of
// TestEphemeralBrokenPipe, which runs serve --ephemeral on the stdout and
// stderr its parent gave it.
const brokenPipeEnv = "GOSFTPD_TEST_BROKEN_PIPE"

// TestEphemeralBrokenPipe: a stdout or a stderr whose reader has gone
// makes the writes fail; it does not kill serve --ephemeral with SIGPIPE,
// Go's default for fd 1 and 2, which would leave the client key and the
// data behind. With stdout gone the line cannot be written, and it exits
// 1; with stderr gone it serves, and SIGTERM stops it with exit 0. Either
// way it removes what it made. The child is this test binary without
// -test.v: the testing package then writes nothing to its stdout.
func TestEphemeralBrokenPipe(t *testing.T) {
	t.Parallel()
	if os.Getenv(brokenPipeEnv) == "1" {
		os.Exit(run(context.Background(), []string{"serve", "--ephemeral", "--allow-root"}, os.Stdout, os.Stderr))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"stdout", "stderr"} {
		t.Run(gone, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestEphemeralBrokenPipe$", "-test.count=1", "-test.timeout=5m")
			cmd.Env = append(os.Environ(), brokenPipeEnv+"=1", "TMPDIR="+tmp,
				"GOSFTPD_CONFIG=", "GOSFTPD_LISTEN=", "GOSFTPD_LOG_LEVEL=", "GOSFTPD_LOG_FORMAT=")
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			r.Close() // the reader has gone before the child starts
			defer w.Close()
			var stderr lockedBuffer
			var stdout io.ReadCloser
			if gone == "stdout" {
				cmd.Stdout, cmd.Stderr = w, &stderr
			} else {
				cmd.Stderr = w
				if stdout, err = cmd.StdoutPipe(); err != nil {
					t.Fatal(err)
				}
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			w.Close()
			want := exitFailure
			if stdout != nil {
				want = exitOK
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err == nil {
					if d := decodeDetails(t, line); filepath.Dir(filepath.Dir(d.PrivateKeyPath)) != tmp {
						t.Errorf("details %+v", d)
					}
					if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
						t.Fatal(err)
					}
				}
				if rest, _ := io.ReadAll(stdout); len(rest) != 0 {
					t.Errorf("more on stdout: %q", rest)
				}
			}
			err = cmd.Wait()
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				t.Fatalf("killed by %v; %s holds %v:\n%s", ws.Signal(), tmp, entries(t, tmp), stderr.String())
			}
			if code := cmd.ProcessState.ExitCode(); code != want {
				t.Errorf("exit %d (%v), want %d:\n%s", code, err, want, stderr.String())
			}
			if gone == "stdout" && !strings.Contains(stderr.String(), "Error: writing the connection details: write /dev/stdout: broken pipe") {
				t.Errorf("stderr:\n%s", stderr.String())
			}
			if got := entries(t, tmp); len(got) != 0 {
				t.Errorf("%s holds %v", tmp, got)
			}
		})
	}
}
