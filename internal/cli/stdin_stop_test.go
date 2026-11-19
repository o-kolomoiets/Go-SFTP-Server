// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// runWith runs the command line args with stdin as its stdin, until it
// exits.
func runWith(t *testing.T, stdin *os.File, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	ctx := context.WithValue(t.Context(), stdinKey{}, stdin)
	var out, errOut lockedBuffer
	code = run(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// refused reports whether a new connection to addr is refused.
func refused(addr string) func() bool {
	return func() bool {
		d := net.Dialer{Timeout: time.Second}
		conn, err := d.DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
		}
		return err != nil
	}
}

// auditNames returns the names of the events of the audit log, in order.
func auditNames(t *testing.T, log string) []string {
	t.Helper()
	var names []string
	for l := range strings.SplitSeq(log, "\n") {
		if l == "" {
			continue
		}
		var ev struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		names = append(names, ev.Event)
	}
	return names
}

// checkDrained checks that the audit log shows a drain: both uploads, the
// end of the session and server.stop last.
func checkDrained(t *testing.T, log string) {
	t.Helper()
	names := auditNames(t, log)
	if len(names) == 0 || names[len(names)-1] != "server.stop" || !slices.Contains(names, "session.end") {
		t.Errorf("events %v:\n%s", names, log)
	}
	var uploads []string
	for _, ev := range events(t, log, "fs.upload") {
		p, _ := ev["path"].(string)
		uploads = append(uploads, p)
	}
	if !slices.Equal(uploads, []string{"/before.txt", "/during.txt"}) {
		t.Errorf("uploads %v:\n%s", uploads, log)
	}
}

// TestServeStopOnStdinEOF: end of file on stdin stops serve as SIGTERM
// does: it accepts no new connection, lets the open session go on until it
// ends, writes server.stop and exits 0. What is written to stdin before is
// discarded.
func TestServeStopOnStdinEOF(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	alice := newSigner(t)
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", alice)
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	ts := startWith(t, r, "serve", "--allow-root", "--print-details", "--stop-on-stdin-eof", "--log-format", "json", "--config", path)
	line := ts.stdout.String()
	if _, err := w.WriteString("anything\n"); err != nil {
		t.Fatal(err)
	}
	c, err := detailsLogin(t, ts.addr, alice, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := putFile(c, "/before.txt", "before"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "serve refuses new connections", refused(ts.addr))
	if err := putFile(c, "/during.txt", "during"); err != nil {
		t.Errorf("an upload during the drain: %v", err)
	}
	select {
	case code := <-ts.done:
		t.Fatalf("serve exited with %d before the session ended:\n%s", code, ts.stderr.String())
	case <-time.After(100 * time.Millisecond):
	}
	c.Close()
	if code := ts.exited(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, ts.stderr.String())
	}
	if !strings.Contains(ts.stderr.String(), `"msg":"stdin reached end of file; stopping as on SIGTERM"`) {
		t.Errorf("stderr:\n%s", ts.stderr.String())
	}
	checkDrained(t, audit())
	if ts.stdout.String() != line {
		t.Errorf("stdout %q, was %q", ts.stdout.String(), line)
	}
	for _, f := range []string{"before.txt", "during.txt"} {
		if _, err := os.Stat(filepath.Join(dir, "data", f)); err != nil {
			t.Error(err)
		}
	}
}

// TestServeStopOnStdinEOFWithoutDetails: the flag works without
// --print-details, and a SIGTERM before end of file stops serve as usual,
// without the log line of stdin.
func TestServeStopOnStdinEOFWithoutDetails(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	audit := auditFile(t, filepath.Join(dir, "audit", "audit.jsonl"))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	ts := startWith(t, r, "serve", "--allow-root", "--stop-on-stdin-eof", "--config", path)
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, ts.stderr.String())
	}
	w.Close()
	if ts.stdout.String() != "" || strings.Contains(ts.stderr.String(), "stdin") || len(events(t, audit(), "server.stop")) != 1 {
		t.Errorf("stdout %q, stderr:\n%s\naudit:\n%s", ts.stdout.String(), ts.stderr.String(), audit())
	}

	// Stdin at end of file already: serve starts and stops at once.
	code, out, errOut := runWith(t, r, "serve", "--allow-root", "--stop-on-stdin-eof", "--config", path)
	if code != exitOK || out != "" || !strings.Contains(errOut, `msg="stdin reached end of file; stopping as on SIGTERM"`) {
		t.Errorf("exit %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
	if len(events(t, audit(), "server.stop")) != 2 {
		t.Errorf("audit:\n%s", audit())
	}
}

// TestServeStopOnStdinEOFNeedsPipe: stdin must be a pipe or a socket; a
// file or a directory never reaches end of file when the program that
// started gosftpd exits. The start fails with exit status 2, before
// anything is made.
func TestServeStopOnStdinEOFNeedsPipe(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["127.0.0.1:0"]`, "", newSigner(t))
	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	folder, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	const need = "--stop-on-stdin-eof needs stdin to be a pipe or a socket"
	type stdinCase struct {
		stdin *os.File
		want  string // the error, or its start
	}
	cases := []stdinCase{
		{file, need + " whose other end the program that starts gosftpd holds; stdin is a file"},
		{folder, need + " whose other end the program that starts gosftpd holds; stdin is a directory"},
	}
	if runtime.GOOS != "windows" { // where Stat of a closed file may reach a reused handle
		cases = append(cases, stdinCase{closed, need + ": stat " + closed.Name() + ": file already closed"})
	}
	for _, tt := range cases {
		code, out, errOut := runWith(t, tt.stdin, "serve", "--allow-root", "--stop-on-stdin-eof", "--config", path)
		if code != exitUsage || out != "" || !strings.Contains(errOut, "Error: "+tt.want) {
			t.Errorf("exit %d, stdout %q, stderr:\n%s", code, out, errOut)
		}
		code, out, errOut = runWith(t, tt.stdin, "serve", "--allow-root", "--print-details", "--stop-on-stdin-eof", "--config", path)
		if f := decodeFailure(t, out); code != exitUsage || f.Kind != failConfig || !strings.HasPrefix(f.Error, tt.want) || !strings.Contains(errOut, "Error: "+f.Error+"\n") {
			t.Errorf("--print-details: exit %d, line %+v, stderr:\n%s", code, f, errOut)
		}
	}
	// With --ephemeral too, before its directory is made.
	code, _, errOut := runWith(t, file, "serve", "--allow-root", "--ephemeral", "--stop-on-stdin-eof")
	if code != exitUsage || !strings.Contains(errOut, need) {
		t.Errorf("--ephemeral: exit %d:\n%s", code, errOut)
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v", tmp, got)
	}
	if got := entries(t, filepath.Join(dir, "state")); len(got) != 0 {
		t.Errorf("a host key was made: %v", got)
	}
}

// TestServeStopOnStdinEOFEphemeral: serve --ephemeral stops on end of file
// too, and removes what it made.
func TestServeStopOnStdinEOFEphemeral(t *testing.T) {
	isolate(t)
	tmp := ephemeralTemp(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	ts := startWith(t, r, "serve", "--allow-root", "--ephemeral", "--stop-on-stdin-eof")
	waitDetails(t, ts)
	w.Close()
	if code := ts.exited(t); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, ts.stderr.String())
	}
	if got := entries(t, tmp); len(got) != 0 {
		t.Errorf("%s holds %v after the stop", tmp, got)
	}
	if logs := ts.stderr.String(); !strings.Contains(logs, `msg="stdin reached end of file; stopping as on SIGTERM"`) || !strings.Contains(logs, `"event":"server.stop"`) {
		t.Errorf("stderr:\n%s", logs)
	}
}

// TestServeStopOnStdinEOFHostName: a stop asked for while starting does not
// fail the lookup of a listen address that is a host name, which
// --print-details would report as a listen error.
func TestServeStopOnStdinEOFHostName(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := detailsConfig(t, dir, `listen = ["localhost:0"]`, "", newSigner(t))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close() // at end of file before serve starts
	t.Cleanup(func() { r.Close() })
	for range 5 {
		code, out, errOut := runWith(t, r, "serve", "--allow-root", "--stop-on-stdin-eof", "--print-details", "--config", path)
		if code != exitOK || strings.Contains(out, `"error"`) {
			t.Fatalf("exit %d, stdout %q, stderr:\n%s", code, out, errOut)
		}
	}
}
