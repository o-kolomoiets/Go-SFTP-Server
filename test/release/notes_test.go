// SPDX-License-Identifier: Apache-2.0

// Package release tests the scripts that the release workflows run, in
// .github/scripts (ADR 0012).
package release

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// root is the repository's top directory.
var root = filepath.Join("..", "..")

// releaseNotes runs .github/scripts/release-notes.sh with args in the
// repository's top directory, as the release workflow does, and returns its
// standard output, its standard error and its exit code.
func releaseNotes(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the release workflows run the script on Linux")
	}
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{".github/scripts/release-notes.sh"}, args...)...)
	cmd.Dir = root
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

// writeChangelog writes text to a CHANGELOG.md in a new directory and
// returns its path.
func writeChangelog(t *testing.T, text string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

const changelog = `# Changelog

All notable changes.

## [Unreleased]
%s
## [0.5.0] - 2026-11-02

### Added

- One.

  Continued after a blank line.

### Fixed

- Two.


## [0.5.0-rc.1] - 2026-11-01

### Added

- The candidate.

## [0.4.0] - 2026-10-17

- Old.

[Unreleased]: https://example.com/compare/v0.5.0...HEAD
[0.5.0]: https://example.com/compare/v0.4.0...v0.5.0
`

func TestReleaseNotes(t *testing.T) {
	t.Parallel()
	released := strings.Replace(changelog, "%s", "", 1)
	pending := strings.Replace(changelog, "%s", "\n### Changed\n\n- Next.\n", 1)
	tests := []struct {
		name      string
		changelog string
		args      []string
		want      string // standard output
		code      int
		stderr    string // a part of the standard error
	}{
		{
			name:      "a version's section without its heading",
			changelog: released,
			args:      []string{"0.5.0"},
			want:      "### Added\n\n- One.\n\n  Continued after a blank line.\n\n### Fixed\n\n- Two.\n",
		},
		{
			name:      "a tag",
			changelog: released,
			args:      []string{"v0.5.0"},
			want:      "### Added\n\n- One.\n\n  Continued after a blank line.\n\n### Fixed\n\n- Two.\n",
		},
		{
			name:      "the last section stops at the link definitions",
			changelog: pending,
			args:      []string{"0.4.0"},
			want:      "- Old.\n",
		},
		{
			name:      "a pre-release with a section of its own",
			changelog: pending,
			args:      []string{"v0.5.0-rc.1"},
			want:      "### Added\n\n- The candidate.\n",
		},
		{
			name:      "a pre-release without a section gets Unreleased",
			changelog: pending,
			args:      []string{"v0.6.0-beta"},
			want:      "### Changed\n\n- Next.\n",
		},
		{
			name:      "a pre-release without a section and an empty Unreleased",
			changelog: released,
			args:      []string{"0.6.0-rc.2"},
			code:      1,
			stderr:    "has no section [0.6.0-rc.2], and its section [Unreleased] is empty",
		},
		{
			name:      "a pre-release without a section and without Unreleased",
			changelog: "# Changelog\n\n## [0.4.0] - 2026-10-17\n\n- Old.\n",
			args:      []string{"0.5.0-alpha.1"},
			code:      1,
			stderr:    "has neither a section [0.5.0-alpha.1] nor [Unreleased]",
		},
		{
			name:      "a version without a section never gets Unreleased",
			changelog: pending,
			args:      []string{"0.6.0"},
			code:      1,
			stderr:    `has no section [0.6.0]: move the Unreleased entries under "## [0.6.0] - YYYY-MM-DD"`,
		},
		{
			name:      "an empty section",
			changelog: "## [Unreleased]\n\n## [0.6.0] - 2026-12-01\n\n\n## [0.5.0] - 2026-11-02\n\n- One.\n",
			args:      []string{"0.6.0"},
			code:      1,
			stderr:    "the section [0.6.0] of",
		},
		{
			name:      "a heading is matched whole",
			changelog: "## [Unreleased]\n\n- Next.\n\n## [10.5.0]\n\n- Ten.\n\n## [0.5.0]x\n\n- X.\n\n## [0.5.0-rc.1]\n\n- Candidate.\n",
			args:      []string{"0.5.0"},
			code:      1,
			stderr:    "has no section [0.5.0]",
		},
		{
			name:      "a heading without a date",
			changelog: "## [0.5.0]\n- One.\n## [0.4.0]\n- Old.\n",
			args:      []string{"0.5.0"},
			want:      "- One.\n",
		},
		{
			name:      "not a release version",
			changelog: released,
			args:      []string{"0.5.0-dev"},
			code:      2,
			stderr:    "0.5.0-dev is not a release version",
		},
		{
			name:      "a version with four numbers",
			changelog: released,
			args:      []string{"0.5.0.1"},
			code:      2,
			stderr:    "is not a release version",
		},
		{
			name:      "an empty version",
			changelog: released,
			args:      []string{""},
			code:      2,
			stderr:    "is not a release version",
		},
		{
			name: "no version",
			code: 2, stderr: "usage: release-notes.sh VERSION [CHANGELOG]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			args := tt.args
			if args != nil {
				args = append(slices.Clone(args), writeChangelog(t, tt.changelog))
			}
			got, stderr, code := releaseNotes(t, args...)
			if code != tt.code || got != tt.want || !strings.Contains(stderr, tt.stderr) {
				t.Errorf("release-notes.sh %q = exit %d\n%s\nstderr: %s\nwant exit %d\n%s\nstderr with %q",
					tt.args, code, got, stderr, tt.code, tt.want, tt.stderr)
			}
			if code != 0 && got != "" {
				t.Errorf("standard output on a failure: %q", got)
			}
		})
	}

	t.Run("a missing file", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "CHANGELOG.md")
		got, stderr, code := releaseNotes(t, "0.5.0", missing)
		if code != 1 || got != "" || !strings.Contains(stderr, "cannot read "+missing) {
			t.Errorf("exit %d, %q, stderr %q; want exit 1 and cannot read %s", code, got, stderr, missing)
		}
	})
}

// TestReleaseNotesOfChangelog runs the script for every version in the
// repository's CHANGELOG.md, as the release workflow does, and compares
// its output with the text between the version's heading and the next one.
func TestReleaseNotesOfChangelog(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if i := strings.Index(text, "\n[Unreleased]: "); i >= 0 {
		text = text[:i+1] // the link definitions
	}
	heading := regexp.MustCompile(`(?m)^## \[([^\]]+)\]( - \d{4}-\d{2}-\d{2})?$`)
	sections := heading.FindAllStringSubmatchIndex(text, -1)
	if len(sections) < 5 {
		t.Fatalf("CHANGELOG.md: %d sections, want Unreleased and at least four versions", len(sections))
	}
	var unreleased string
	for i, s := range sections {
		version := text[s[2]:s[3]]
		end := len(text)
		if i+1 < len(sections) {
			end = sections[i+1][0]
		}
		want := strings.Trim(text[s[1]:end], "\n")
		if strings.Contains("\n"+want, "\n## ") {
			t.Fatalf("CHANGELOG.md: a heading in the section [%s] that is not a version's", version)
		}
		if version == "Unreleased" {
			unreleased = want
			continue
		}
		if s[4] < 0 {
			t.Errorf("CHANGELOG.md: the heading of [%s] has no date", version)
		}
		got, stderr, code := releaseNotes(t, "v"+version)
		if code != 0 || got != want+"\n" {
			t.Errorf("release-notes.sh v%s = exit %d (%s), %d bytes; want the %d bytes of its section", version, code, stderr, len(got), len(want)+1)
		}
	}

	// A version that has no section yet: a pre-release gets Unreleased,
	// when it holds entries; a release fails.
	got, stderr, code := releaseNotes(t, "999.0.0-rc.1")
	switch {
	case unreleased == "" && code != 1:
		t.Errorf("release-notes.sh 999.0.0-rc.1 with an empty Unreleased section = exit %d (%s), want 1", code, stderr)
	case unreleased != "" && (code != 0 || got != unreleased+"\n"):
		t.Errorf("release-notes.sh 999.0.0-rc.1 = exit %d (%s), %d bytes; want the %d bytes of Unreleased", code, stderr, len(got), len(unreleased)+1)
	}
	if _, stderr, code := releaseNotes(t, "999.0.0"); code != 1 {
		t.Errorf("release-notes.sh 999.0.0 = exit %d (%s), want 1", code, stderr)
	}
}
