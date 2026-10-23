// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/o-kolomoiets/go-sftp-server/internal/cli"
)

// readTree returns the files under dir by slash-separated relative path.
func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			t.Errorf("%s is not a regular file", p)
		}
		data, err := os.ReadFile(p)
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// pages returns the man page each available command should get, cobra's
// completion command included.
func pages() []string {
	root := cli.NewRootCommand()
	root.InitDefaultCompletionCmd()
	var names []string
	for _, c := range commands(root) {
		if c.IsAvailableCommand() || c == root {
			names = append(names, "man/"+strings.ReplaceAll(c.CommandPath(), " ", "-")+".1.gz")
		}
	}
	return names
}

// The files the release job accepts from the generate job, and nothing
// else (ADR 0012).
var releaseFile = regexp.MustCompile(`^(THIRD_PARTY_LICENSES|completions/(_gosftpd|gosftpd\.bash|gosftpd\.fish)|man/gosftpd(-[a-z0-9-]+)?\.1\.gz)$`)

// TestGenerate checks that two runs give the same files, one page for
// every command and the three completions, and nothing else; that a page
// left from an earlier run goes; and what a page holds.
func TestGenerate(t *testing.T) {
	t.Parallel()

	// 23:30 UTC on the last day of a month: in a time zone east of UTC
	// the page would show the next month.
	date := time.Date(2026, time.October, 31, 23, 30, 0, 0, time.UTC)
	a, b := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(a, "man"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, "man", "gosftpd-removed.1.gz"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := generate(a, date); err != nil {
		t.Fatal(err)
	}
	if err := generate(b, date); err != nil {
		t.Fatal(err)
	}
	files := readTree(t, a)
	if !maps.EqualFunc(files, readTree(t, b), bytes.Equal) {
		t.Error("two runs with the same date gave different files")
	}

	want := append(pages(), "completions/_gosftpd", "completions/gosftpd.bash", "completions/gosftpd.fish")
	got := slices.Sorted(maps.Keys(files))
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("files:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, name := range []string{
		"man/gosftpd.1.gz", "man/gosftpd-serve.1.gz", "man/gosftpd-config-validate.1.gz",
		"man/gosftpd-user-add.1.gz", "man/gosftpd-hostkey-rotate.1.gz", "man/gosftpd-healthcheck.1.gz", "man/gosftpd-completion-bash.1.gz",
	} {
		if files[name] == nil {
			t.Errorf("%s is missing", name)
		}
	}
	for _, name := range got {
		if !releaseFile.MatchString(name) {
			t.Errorf("%s: the release job would refuse this file", name)
		}
	}

	for name, data := range files {
		if !strings.HasPrefix(name, "man/") {
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if zr.Name != "" || !zr.ModTime.IsZero() {
			t.Errorf("%s: gzip header has name %q, time %v", name, zr.Name, zr.ModTime)
		}
		page, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		title := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(name, "man/"), ".1.gz"))
		if th := `.TH "` + title + `" "1" "Oct 2026" "gosftpd" "gosftpd manual"`; !bytes.Contains(page, []byte(th)) {
			t.Errorf("%s lacks %s:\n%.300s", name, th, page)
		}
		if bytes.Contains(page, []byte("Auto generated")) || bytes.Contains(page, []byte(`\<`)) {
			t.Errorf("%s has an auto-generated tag or an escape:\n%s", name, page)
		}
	}
	// manText ran on the long help: the indented table of hostkey rotate
	// is a code block, not a paragraph that man reflows.
	if table := ".EX\n  rotate            create the next key"; !bytes.Contains(gunzip(t, filepath.Join(a, "man", "gosftpd-hostkey-rotate.1.gz")), []byte(table)) {
		t.Errorf("gosftpd-hostkey-rotate.1 lacks %q", table)
	}
	for name, sig := range map[string]string{
		"completions/gosftpd.bash": "__start_gosftpd",
		"completions/_gosftpd":     "#compdef gosftpd",
		"completions/gosftpd.fish": "complete -c gosftpd",
	} {
		if !bytes.Contains(files[name], []byte(sig)) {
			t.Errorf("%s lacks %q", name, sig)
		}
	}
}

// Every <placeholder> of a help text stays in the page: md2man would take
// it for an HTML tag and drop it.
func TestGeneratePlaceholders(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := generate(dir, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	placeholder := regexp.MustCompile(`<[a-z][^<>]*>`)
	root := cli.NewRootCommand()
	n := 0
	for _, c := range commands(root) {
		if !c.IsAvailableCommand() && c != root {
			continue
		}
		texts := []string{c.Short, c.Long}
		c.NonInheritedFlags().VisitAll(func(f *pflag.Flag) { texts = append(texts, f.Usage) })
		name := strings.ReplaceAll(c.CommandPath(), " ", "-") + ".1.gz"
		var page []byte
		for _, p := range placeholder.FindAllString(strings.Join(texts, "\n"), -1) {
			if page == nil {
				page = gunzip(t, filepath.Join(dir, "man", name))
			}
			if !bytes.Contains(page, []byte(p)) {
				t.Errorf("%s lacks %s", name, p)
			}
			n++
		}
	}
	if n == 0 {
		t.Error("no placeholder found: the test checks nothing")
	}
}

func gunzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManText(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"default <user config dir>/x", `default \<user config dir\>/x`},
		{"a > b", `a \> b`},
		{"text:\n\n  a   one\n      two\n\nmore", "text:\n\n      a   one\n          two\n\nmore"},
		{"text:\n  a   one", "text:\n\n      a   one"},
		{"run:\n\n\tsource <(gosftpd completion bash)\n", "run:\n\n\tsource <(gosftpd completion bash)\n"},
	} {
		if got := manText(tt.in); got != tt.want {
			t.Errorf("manText(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSourceDate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 23, 20, 0, 0, 0, time.FixedZone("UTC+2", 2*3600))
	for _, tt := range []struct {
		epoch string
		want  time.Time
		ok    bool
	}{
		{"", now.UTC(), true},
		{"0", time.Unix(0, 0).UTC(), true},
		{"1793489400", time.Date(2026, time.October, 31, 23, 30, 0, 0, time.UTC), true},
		{"-1", time.Time{}, false},
		{"1.5", time.Time{}, false},
		{"yesterday", time.Time{}, false},
		{" 1", time.Time{}, false},
	} {
		got, err := sourceDate(tt.epoch, now)
		if (err == nil) != tt.ok || !got.Equal(tt.want) || tt.ok && got.Location() != time.UTC {
			t.Errorf("sourceDate(%q) = %v, %v; want %v (UTC)", tt.epoch, got, err, tt.want)
		}
	}
}

// commands is also what the generator walks; check that it reaches the
// leaves.
func TestCommands(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{Use: "a"}
	b := &cobra.Command{Use: "b"}
	b.AddCommand(&cobra.Command{Use: "c"})
	root.AddCommand(b)
	var names []string
	for _, c := range commands(root) {
		names = append(names, c.CommandPath())
	}
	if want := []string{"a", "a b", "a b c"}; !slices.Equal(names, want) {
		t.Errorf("commands = %q, want %q", names, want)
	}
}
