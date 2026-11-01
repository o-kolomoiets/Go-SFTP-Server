// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestImageSBOMGenerator checks where the SBOM attestation of the release
// image comes from (ADR 0012). Each dockers_v2 entry of .goreleaser.yaml
// sets sbom: false and passes its own --attest=type=sbom with the scanner
// pinned by tag and digest, only outside a snapshot. With sbom: true
// GoReleaser passes --attest=type=sbom without a generator, which buildx
// takes first, and BuildKit then runs docker/buildkit-syft-scanner:stable-1,
// a floating tag, in the build whose index is signed and attested.
func TestImageSBOMGenerator(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "\ndockers_v2:\n")
	if !ok {
		t.Fatal(".goreleaser.yaml has no dockers_v2")
	}
	// The section, up to the next top-level key, without comment lines.
	var section strings.Builder
	for line := range strings.Lines(rest) {
		if line != "\n" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
			break
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			section.WriteString(line)
		}
	}
	entries := regexp.MustCompile(`(?m)^  - `).Split(section.String(), -1)[1:]
	if len(entries) == 0 {
		t.Fatal("dockers_v2 has no entries")
	}
	attest := regexp.MustCompile(`--attest=type=sbom[^"\s{]*`)
	pinned := regexp.MustCompile(`^--attest=type=sbom,generator=[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	for _, entry := range entries {
		id, _, _ := strings.Cut(entry, "\n")
		if !regexp.MustCompile(`(?m)^    sbom: false$`).MatchString(entry) {
			t.Errorf("dockers_v2 %s: sbom is not false, so GoReleaser passes --attest=type=sbom without a generator", id)
		}
		flags := attest.FindAllString(entry, -1)
		if len(flags) != 1 {
			t.Errorf("dockers_v2 %s: %d --attest=type=sbom flags %q, want 1", id, len(flags), flags)
			continue
		}
		if !pinned.MatchString(flags[0]) {
			t.Errorf("dockers_v2 %s: %s does not name its generator by tag and digest", id, flags[0])
		}
		if want := `      - "{{ if not .IsSnapshot }}` + flags[0] + `{{ end }}"` + "\n"; !strings.Contains(entry, want) {
			t.Errorf("dockers_v2 %s: the flag is not %s, outside a snapshot only", id, strings.TrimSpace(want))
		}
	}
}
