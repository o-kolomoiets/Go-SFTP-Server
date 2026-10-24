// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
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

// sedInPlace matches sed -i, the in-place option, without a suffix
// attached to it.
var sedInPlace = regexp.MustCompile(`\bsed\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*i(?:''|"")?(?:\s|$)`)

// TestQuickstartSed checks that the quickstart block, which README.md and
// docs/quickstart.md copy for macOS readers too, runs sed -i only with a
// backup suffix attached (-i.orig): GNU sed takes that, and the BSD sed of
// macOS requires a suffix, taking the next argument as one otherwise, so
// that the script becomes the file name and the placeholder stays.
func TestQuickstartSed(t *testing.T) {
	t.Parallel()
	install, err := os.ReadFile(filepath.Join(root, "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	block := markedBlock(t, string(install), "quickstart")
	if !strings.Contains(block, "sed ") {
		t.Fatal("the quickstart block has no sed: update this test")
	}
	for line := range strings.Lines(block) {
		if sedInPlace.MatchString(line) {
			t.Errorf("the quickstart block runs sed -i without a suffix, which the BSD sed of macOS refuses: %s", strings.TrimSpace(line))
		}
	}
}

// TestSedInPlace checks the pattern of TestQuickstartSed.
func TestSedInPlace(t *testing.T) {
	t.Parallel()
	for line, want := range map[string]bool{
		`sed -i "s|a|b|" f`:                    true,
		`sudo sed -i 's/x/y/' f`:               true,
		`sed -n -i 's/x/y/' f`:                 true,
		`sed -Ei 's/x/y/' f`:                   true,
		`sed -i.orig "s|a|b|" f && rm f.orig`:  false,
		`sed -i'' 's/x/y/' f`:                  true,
		`sed "s|a|b|" f > f.new && mv f.new f`: false,
		`sed -n '1p' f`:                        false,
	} {
		if got := sedInPlace.MatchString(line); got != want {
			t.Errorf("sedInPlace.MatchString(%q) = %v, want %v", line, got, want)
		}
	}
}
