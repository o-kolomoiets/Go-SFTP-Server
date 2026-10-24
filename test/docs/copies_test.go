// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestQuickstartCopies checks that README.md and docs/quickstart.md show
// the Docker Quickstart as the quickstart block of docs/install.md has it,
// the block the docker CI job runs: a change to the block must reach its
// copies.
func TestQuickstartCopies(t *testing.T) {
	t.Parallel()
	install, err := os.ReadFile(filepath.Join(root, "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	block := markedBlock(t, string(install), "quickstart")
	for _, name := range []string{"README.md", filepath.Join("docs", "quickstart.md")} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), block) {
			t.Errorf("%s has no copy of the quickstart block of docs/install.md:\n%s", filepath.ToSlash(name), block)
		}
	}
}

// markedBlock returns the fenced block between <!-- ci:NAME --> and
// <!-- /ci --> in text, with its fences.
func markedBlock(t *testing.T, text, name string) string {
	t.Helper()
	_, after, ok := strings.Cut(text, "<!-- ci:"+name+" -->")
	if !ok {
		t.Fatalf("docs/install.md has no marker ci:%s", name)
	}
	inner, _, ok := strings.Cut(after, "<!-- /ci -->")
	if !ok {
		t.Fatalf("docs/install.md: the block %s has no end marker", name)
	}
	start, end := strings.Index(inner, "```"), strings.LastIndex(inner, "```")
	if start < 0 || end <= start {
		t.Fatalf("docs/install.md: the block %s has no fenced code", name)
	}
	return inner[start : end+len("```")]
}
