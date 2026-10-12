// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
)

// TestServeSandboxStep: serve calls the sandbox once, with one held
// directory per mount, before it serves; its status goes into
// server.start, and a failure fails the start with exit status 1. Not
// parallel: it replaces startSandbox.
func TestServeSandboxStep(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.a]
path = "`+filepath.ToSlash(filepath.Join(dir, "a"))+`"
[mounts.b]
path = "`+filepath.ToSlash(filepath.Join(dir, "b"))+`"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { a = "full", b = "full" }
`)
	defer func() { startSandbox = noSandbox }()

	var calls []sandbox.Options
	startSandbox = func(_ context.Context, o sandbox.Options) (sandbox.Result, error) {
		calls = append(calls, o)
		return sandbox.Result{Status: sandbox.StatusOff}, nil
	}
	ts := startServe(t, "--config", path)
	if code := ts.stop(t); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(calls) != 1 || calls[0].Config == nil || calls[0].Log == nil {
		t.Fatalf("calls = %+v", calls)
	}
	var names []string
	for _, m := range calls[0].Mounts {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, []string{"a", "b"}) {
		t.Errorf("mounts %v", names)
	}
	if evs := events(t, ts.stdout.String(), "server.start"); len(evs) != 1 || evs[0]["landlock"] != sandbox.StatusOff {
		t.Errorf("server.start = %v", evs)
	}

	startSandbox = func(context.Context, sandbox.Options) (sandbox.Result, error) {
		return sandbox.Result{}, errors.New("landlock: failed: self-check: / can still be opened")
	}
	code, out, errOut := execute(t, "serve", "--allow-root", "--config", path)
	if code != exitFailure || !strings.Contains(errOut, "Error: landlock: failed: self-check: / can still be opened") || strings.Contains(out, "server.start") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
}
