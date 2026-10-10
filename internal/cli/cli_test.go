// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

func execute(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(t.Context(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	t.Parallel()

	code, out, _ := execute(t, "version")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.HasPrefix(out, "gosftpd ") {
		t.Errorf("output = %q, want prefix %q", out, "gosftpd ")
	}
}

func TestVersionJSON(t *testing.T) {
	t.Parallel()

	code, out, _ := execute(t, "version", "--json")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	var got struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if got.Version == "" || got.GoVersion == "" {
		t.Errorf("incomplete JSON: %s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"no-such-command"},
		{"version", "--no-such-flag"},
		{"version", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			code, _, errOut := execute(t, args...)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(errOut, "--help") {
				t.Errorf("stderr = %q, want a hint to --help", errOut)
			}
		})
	}
}

func TestNoArgsPrintsHelp(t *testing.T) {
	t.Parallel()

	code, out, _ := execute(t)
	if code != exitOK || !strings.Contains(out, "Usage:") {
		t.Errorf("exit code = %d, output = %q; want help and exit 0", code, out)
	}
}

func TestServeUsageErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte("# no keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"serve", "--dir", dir, "--on-conflict", "merge"},
		{"serve", "--dir", dir, "--log-level", "loud"},
		{"serve", "--dir", dir, "--log-format", "xml"},
		{"serve", "--dir", filepath.Join(dir, "missing")},
		{"serve", "--dir", keys},
		{"serve", "--dir", dir, "--authorized-keys", keys},
		{"serve", "--dir", dir, "--authorized-keys", filepath.Join(dir, "missing")},
		{"hostkey", "show", "--host-key", filepath.Join(dir, "missing")},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			if code, _, errOut := execute(t, args...); code != exitUsage {
				t.Errorf("exit code = %d, want %d; stderr %q", code, exitUsage, errOut)
			}
		})
	}
}

func TestParseDirs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	specs, err := parseDirs([]string{dir, "docs=" + dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].Name != filepath.Base(dir) || specs[1].Name != "docs" {
		t.Errorf("specs = %+v", specs)
	}
}

func TestHostkeyShow(t *testing.T) {
	t.Parallel()

	state := t.TempDir()
	if _, err := hostkey.Generate(filepath.Join(state, hostkey.DefaultFile)); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := execute(t, "hostkey", "show", "--state-dir", state, "--known-hosts", "example.org:2022")
	if code != exitOK {
		t.Fatalf("exit code = %d: %s", code, errOut)
	}
	if !strings.HasPrefix(out, "SHA256:") || !strings.Contains(out, "[example.org]:2022 ssh-ed25519 ") {
		t.Errorf("output = %q", out)
	}
}
