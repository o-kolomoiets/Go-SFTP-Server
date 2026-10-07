// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
