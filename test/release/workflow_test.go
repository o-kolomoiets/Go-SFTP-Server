// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The parts of release.yml that the tests of its scripts do not reach
// (ADR 0012). The workflow is read as text, in the layout it is written
// in: jobs at two spaces, a step's "- " at six and its keys at eight.

// workflowSteps returns the steps of a job of .github/workflows/FILE, each
// from its "- " line to the next step, without the comment lines between
// the keys.
func workflowSteps(t *testing.T, file, job string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	inJob, inSteps := false, false
	for line := range strings.Lines(string(data)) {
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#") && indent < 10:
		case !inJob:
			inJob = line == "  "+job+":\n"
		case !inSteps:
			inSteps = line == "    steps:\n"
		case strings.HasPrefix(line, "      - "):
			steps = append(steps, line)
		case len(steps) > 0 && (trimmed == "" || indent >= 8):
			steps[len(steps)-1] += line
		default:
			return steps
		}
	}
	return steps
}

// stepNamed returns the step with this name.
func stepNamed(t *testing.T, steps []string, name string) string {
	t.Helper()
	var found []string
	for _, s := range steps {
		if strings.HasPrefix(s, "      - name: "+name+"\n") || strings.Contains(s, "\n        name: "+name+"\n") {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d steps named %q", len(found), name)
	}
	return found[0]
}

// stepMap returns the entries of a mapping key of a step, such as env or
// with, written one per line.
func stepMap(step, key string) map[string]string {
	m := map[string]string{}
	_, rest, ok := strings.Cut(step, "\n        "+key+":\n")
	if !ok {
		return m
	}
	for line := range strings.Lines(rest) {
		entry, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "          ")
		if !ok || strings.HasPrefix(entry, " ") {
			break
		}
		k, v, _ := strings.Cut(entry, ": ")
		m[k] = v
	}
	return m
}

// runScript returns the script of a step's "run: |", unindented.
func runScript(t *testing.T, step string) string {
	t.Helper()
	_, rest, ok := strings.Cut(step, "\n        run: |\n")
	if !ok {
		t.Fatalf("the step has no run: |\n%s", step)
	}
	var script strings.Builder
	for line := range strings.Lines(rest) {
		if body, ok := strings.CutPrefix(line, "          "); ok {
			script.WriteString(body)
		} else if strings.TrimSpace(line) == "" {
			script.WriteString("\n")
		} else {
			break
		}
	}
	return script.String()
}

// TestReleaseGoReleaserTag checks that release.yml's GoReleaser step names
// the tag the guard checked. On its own GoReleaser builds the highest tag
// on HEAD in git's version sort, which can be a tag the guard does not
// count, such as v0.9.0-dev.
func TestReleaseGoReleaserTag(t *testing.T) {
	t.Parallel()
	var found []string
	for _, s := range workflowSteps(t, "release.yml", "release") {
		if strings.Contains(s, "uses: goreleaser/goreleaser-action@") {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the release job has %d GoReleaser steps, want 1", len(found))
	}
	step := found[0]
	if args := stepMap(step, "with")["args"]; !strings.HasPrefix(args, "release ") {
		t.Errorf("the GoReleaser step runs %q, want release", args)
	}
	if got := stepMap(step, "env")["GORELEASER_CURRENT_TAG"]; got != "${{ github.ref_name }}" {
		t.Errorf("the GoReleaser step sets GORELEASER_CURRENT_TAG to %q, want ${{ github.ref_name }}:\n%s", got, step)
	}
}

// TestReleaseConcurrency checks that release.yml runs one run at a time,
// whatever the tag, and cancels none in progress: a run dispatched during
// another waits, and its guard then sees the other run's tag, so that
// latest does not move backwards when two runs would overlap.
func TestReleaseConcurrency(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "\nconcurrency:\n")
	if !ok {
		t.Fatal("release.yml has no workflow-level concurrency")
	}
	var got []string
	for line := range strings.Lines(rest) {
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break
		}
		if entry := strings.TrimSpace(line); entry != "" && !strings.HasPrefix(entry, "#") {
			got = append(got, entry)
		}
	}
	if want := []string{"group: release"}; !slices.Equal(got, want) {
		t.Errorf("release.yml's concurrency is %q, want %q", got, want)
	}
}

// fakeDocker stands for docker in the step that moves latest: it logs its
// arguments to docker.log in the state directory, and imagetools inspect
// names the digest that imagetools create gave the tag last.
const fakeDocker = `#!/bin/sh
printf '%s\n' "$*" >>"$GOSFTPD_FAKE_GH/docker.log"
for last; do :; done
case "$1 $2 $3" in
"buildx imagetools create") printf '%s\n' "${last#*@}" >"$GOSFTPD_FAKE_GH/latest" ;;
"buildx imagetools inspect") printf '{"digest":"%s"}\n' "$(cat "$GOSFTPD_FAKE_GH/latest")" ;;
*) exit 2 ;;
esac
`

// TestReleaseLatest runs the script of release.yml's step that points
// latest at the verified image, for v0.5.0, with the fake gh and a fake
// docker. It runs the guard again first: a tag made while the run was in
// progress, which the concurrency group does not stop, makes v0.5.0 no
// longer the highest, and latest is left to that tag's run.
func TestReleaseLatest(t *testing.T) {
	t.Parallel()
	step := stepNamed(t, workflowSteps(t, "release.yml", "release"), "latest names the verified image")
	if got := stepMap(step, "env")["GH_TOKEN"]; got != "${{ github.token }}" {
		t.Errorf("the step sets GH_TOKEN to %q, want ${{ github.token }} for the guard", got)
	}
	script := runScript(t, step)
	const (
		repo   = "ghcr.io/o-kolomoiets/gosftpd"
		digest = "4b825dc642cb6eb9a060e54bf8d69288fbee4904a8fd2f4a1cfb7c1d7e1d0a5c"
	)
	for _, tt := range []struct {
		name   string
		tags   []string    // besides v0.4.0 and v0.5.0
		fail   [][2]string // failOn arguments
		code   int
		stderr string // a part of standard error
	}{
		{name: "the highest tag"},
		{
			name: "a higher tag made during the run",
			tags: []string{"v0.5.1"},
			code: 1, stderr: "v0.5.0 is not the highest release tag of o-kolomoiets/Go-SFTP-Server: v0.5.1 is",
		},
		{
			name: "a higher pre-release made during the run",
			tags: []string{"v0.6.0-rc.1"},
			code: 1, stderr: "v0.6.0-rc.1 is",
		},
		{
			name: "the tags cannot be listed",
			fail: [][2]string{{"matching-refs", "500"}},
			code: 1, stderr: "cannot list the tags of o-kolomoiets/Go-SFTP-Server",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeGitHub(t)
			for _, tag := range append([]string{"v0.4.0", "v0.5.0"}, tt.tags...) {
				f.tag(tag, f.commits[1])
			}
			f.release("v0.4.0", 200)
			for _, fail := range tt.fail {
				f.failOn(fail[0], fail[1])
			}
			if err := os.WriteFile(filepath.Join(f.bin, "docker"), []byte(fakeDocker), 0o700); err != nil {
				t.Fatal(err)
			}
			// The checkout, as far as the step uses it: the scripts and
			// dist/digests.txt.
			dir := t.TempDir()
			for _, d := range []string{".github", "dist"} {
				if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(scripts(t), filepath.Join(dir, ".github", "scripts")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "dist", "digests.txt"), []byte(digest+"  "+repo+":v0.5.0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// As GitHub Actions runs a bash step.
			got := f.bash(dir, []string{"GITHUB_REF=refs/tags/v0.5.0", "GITHUB_REF_NAME=v0.5.0"},
				"--noprofile", "--norc", "-eo", "pipefail", "-c", script)
			if got.code != tt.code || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("the step = exit %d\n%s\nstderr: %s\nwant exit %d, stderr with %q", got.code, got.stdout, got.stderr, tt.code, tt.stderr)
			}
			var calls []string
			if data, err := os.ReadFile(filepath.Join(f.dir, "docker.log")); err == nil {
				calls = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			} else if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			var want []string
			if tt.code == 0 {
				want = []string{
					"buildx imagetools create --tag " + repo + ":latest " + repo + "@sha256:" + digest,
					"buildx imagetools inspect " + repo + ":latest --format {{json .Manifest}}",
				}
			}
			if !slices.Equal(calls, want) {
				t.Errorf("docker ran as\n%s\nwant\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}
