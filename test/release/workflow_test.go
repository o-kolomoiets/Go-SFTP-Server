// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"path/filepath"
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
