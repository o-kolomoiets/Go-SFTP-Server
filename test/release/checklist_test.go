// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestChecklistPins checks that step 5 of docs/release-checklist.md, the
// table of the versions that Dependabot does not update, names each one
// that .goreleaser.yaml and the workflows pin (ADR 0012): the inputs
// version: (GoReleaser), cosign-release: and syft-version:, and every image
// named by tag and digest outside a uses: line, such as BuildKit in
// driver-opts and the SBOM scanner in the flags of dockers_v2. Dependabot
// updates the uses: lines and the FROM lines of Dockerfiles, not these, so
// a pin missing from the table is never updated.
func TestChecklistPins(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(root, "docs", "release-checklist.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, step, ok := strings.Cut(string(data), "\n5. The versions that Dependabot does not update")
	if !ok {
		t.Fatal("docs/release-checklist.md has no step 5 \"The versions that Dependabot does not update\"")
	}
	var table strings.Builder
	for line := range strings.Lines(step) {
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			table.WriteString(line)
		} else if table.Len() > 0 {
			break
		}
	}
	if table.Len() == 0 {
		t.Fatal("step 5 of docs/release-checklist.md has no table")
	}

	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, ".goreleaser.yaml"))
	input := regexp.MustCompile(`^\s+(version|cosign-release|syft-version): v[0-9]`)
	image := regexp.MustCompile(`([a-z0-9][a-z0-9._/-]*):[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}`)
	found := map[string][]string{} // what the table must name: the files that pin it
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(data)) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "uses:") || strings.HasPrefix(trimmed, "- uses:") {
				continue
			}
			if m := input.FindStringSubmatch(line); m != nil {
				found["`"+m[1]+":`"] = append(found["`"+m[1]+":`"], filepath.Base(f))
			}
			for _, m := range image.FindAllStringSubmatch(line, -1) {
				repo := strings.TrimPrefix(m[1], "docker.io/")
				found[repo] = append(found[repo], filepath.Base(f))
			}
		}
	}
	for _, want := range []string{"`version:`", "`cosign-release:`", "`syft-version:`", "moby/buildkit"} {
		if found[want] == nil {
			t.Errorf("no workflow pins %s any more: update this test and the table", want)
		}
	}
	for name, by := range found {
		if !strings.Contains(table.String(), name) {
			t.Errorf("%s pins %s, which the table of step 5 of docs/release-checklist.md does not name", strings.Join(by, ", "), name)
		}
	}
}
