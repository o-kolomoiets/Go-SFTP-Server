// SPDX-License-Identifier: Apache-2.0

// Package docs tests test/docs/run-block.sh, which runs the command blocks
// of docs/install.md in CI, and the blocks and anchors the workflows and
// the code rely on (ADR 0012); and, in guides_test.go, documented commands
// that no CI job runs as written.
package docs

import (
	"bytes"
	"errors"
	"io/fs"
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

// result is what a run of run-block.sh gave.
type result struct {
	stdout, stderr string
	code           int
}

// runBlock runs test/docs/run-block.sh with args in dir, with the
// environment env added to this process's (V removed first) and stdin as
// its standard input.
func runBlock(t *testing.T, dir string, env []string, stdin string, args ...string) result {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("CI runs the blocks on Linux")
	}
	script, err := filepath.Abs(filepath.Join(root, "test", "docs", "run-block.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "V=") }), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var r result
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	r.stdout, r.stderr = out.String(), errOut.String()
	return r
}

// write writes text to name in dir.
func write(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeCommand writes commands named names into a new directory, each of
// which appends its arguments to NAME.log in dir, and returns PATH with
// that directory first.
func fakeCommand(t *testing.T, dir string, names ...string) string {
	t.Helper()
	bin := t.TempDir()
	for _, name := range names {
		log := filepath.Join(dir, name+".log")
		script := "#!/bin/sh\necho \"$*\" >> '" + log + "'\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")
}

// commandLog returns the calls of the fake command name in dir.
func commandLog(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name+".log"))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const doc = "# Install\n\n" +
	"<!-- ci:one -->\n```sh\nV=0.5.0\necho \"one $V\"\n```\n<!-- /ci -->\n\n" +
	"Prose.\n\n```sh\necho unmarked\n```\n\n" +
	"<!-- ci:two -->\n\n```bash\necho two\nprintf '%s\\n' \"$PWD\"\n```\n\n<!-- /ci -->\n"

func TestRunBlock(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		doc    string // the Markdown file; doc above when empty
		block  string // a block "b" in a file of its own, instead of doc
		args   []string
		env    []string
		stdin  string
		want   string // standard output; "$PWD" stands for the directory it runs in
		code   int
		stderr string // a part of standard error
	}{
		{
			name: "only the marked block, with the caller's V",
			args: []string{"one"}, env: []string{"V=9.9.9"},
			want: "one 9.9.9\n", stderr: "the one block of",
		},
		{
			name: "blank lines around the fence, in the working directory",
			args: []string{"two"},
			want: "two\n$PWD\n",
		},
		{
			name: "the V= line needs V from the caller",
			args: []string{"one"},
			code: 2, stderr: "the one block uses V: set V to the version under test",
		},
		{
			name: "--print writes the block without the V= line",
			args: []string{"--print", "one"}, env: []string{"V=1"},
			want: "echo \"one $V\"\n",
		},
		{
			name:  "-e: a failing command stops the block",
			block: "true\nfalse\necho after",
			code:  1, stderr: "the b block failed at line 2 with exit status 1",
		},
		{
			name:  "-u: an unset variable stops the block",
			block: "echo \"$GOSFTPD_RUN_BLOCK_UNSET\"\necho after",
			code:  1, stderr: "GOSFTPD_RUN_BLOCK_UNSET: unbound variable",
		},
		{
			name:  "pipefail: a failure in a pipeline stops the block",
			block: "false | true\necho after",
			code:  1, stderr: "failed at line 1",
		},
		{
			name:  "-E: a failure in a function names its line",
			block: "f() {\n\tfalse\n}\nf\necho after",
			code:  1, stderr: "failed at line 2",
		},
		{
			name:  "standard input is empty",
			block: "printf '[%s]\\n' \"$(cat)\"", stdin: "data\n",
			want: "[]\n",
		},
		{
			name: "no such block",
			args: []string{"three"},
			code: 2, stderr: "no block <!-- ci:three -->",
		},
		{
			name: "a name that is not a marker's",
			args: []string{"One"},
			code: 2, stderr: "usage: run-block.sh [--print] NAME [MARKDOWN]",
		},
		{
			name: "no name",
			code: 2, stderr: "usage:",
		},
		{
			name: "two markers of one name",
			doc:  "<!-- ci:a -->\n```sh\necho 1\n```\n<!-- /ci -->\n<!-- ci:a -->\n```sh\necho 2\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: ":6: a second <!-- ci:a -->",
		},
		{
			name: "a marker that is not closed",
			doc:  "<!-- ci:a -->\n```sh\necho 1\n```\n",
			args: []string{"a"},
			code: 2, stderr: "<!-- ci:a --> is not closed by <!-- /ci -->",
		},
		{
			name: "a fence that is not closed",
			doc:  "<!-- ci:a -->\n```sh\necho 1\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "is not closed",
		},
		{
			name: "no fenced block",
			doc:  "<!-- ci:a -->\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "<!-- ci:a --> holds no fenced block",
		},
		{
			name: "two fenced blocks",
			doc:  "<!-- ci:a -->\n```sh\necho 1\n```\n```sh\necho 2\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "holds more than one fenced block",
		},
		{
			name: "text between the markers",
			doc:  "<!-- ci:a -->\nRun this:\n```sh\necho 1\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "text outside the fenced block of <!-- ci:a -->: Run this:",
		},
		{
			name: "a block that is not shell",
			doc:  "<!-- ci:a -->\n```yaml\nkey: value\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "holds a block that is not sh or bash: ```yaml",
		},
		{
			name: "an empty block",
			doc:  "<!-- ci:a -->\n```sh\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			code: 2, stderr: "the block of <!-- ci:a --> is empty",
		},
		{
			name: "a marker inside another block is the other block's text",
			doc:  "<!-- ci:a -->\n```sh\necho '<!-- ci:b -->'\n```\n<!-- /ci -->\n",
			args: []string{"a"},
			want: "<!-- ci:b -->\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			text, args := tt.doc, tt.args
			switch {
			case tt.block != "":
				text, args = "<!-- ci:b -->\n```sh\n"+tt.block+"\n```\n<!-- /ci -->\n", []string{"b"}
			case text == "":
				text = doc
			}
			if len(args) > 0 {
				args = append(slices.Clone(args), write(t, t.TempDir(), "install.md", text))
			}
			got := runBlock(t, dir, tt.env, tt.stdin, args...)
			want := strings.ReplaceAll(tt.want, "$PWD", dir)
			if got.code != tt.code || got.stdout != want || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("run-block.sh %q = exit %d, %q\nstderr: %s\nwant exit %d, %q, stderr with %q",
					tt.args, got.code, got.stdout, got.stderr, tt.code, want, tt.stderr)
			}
		})
	}
}

// TestRunBlockReleaseDownload checks that gh release download is skipped
// when every file it names is present, and that gh runs otherwise.
func TestRunBlockReleaseDownload(t *testing.T) {
	t.Parallel()
	const block = "<!-- ci:verify -->\n```sh\nV=0.5.0\n" +
		"gh release download \"v$V\" -R o/r -p checksums.txt \\\n  -p \"gosftpd_${V}_linux_*.tar.gz\" %s\n" +
		"gh attestation verify x --repo o/r\necho done\n```\n<!-- /ci -->\n"
	for _, tt := range []struct {
		name    string
		files   []string // created in the working directory, or in sub with -D
		flags   string   // more flags of gh release download
		sub     string   // the directory -D names
		skipped bool
	}{
		{name: "all present", files: []string{"checksums.txt", "gosftpd_1.2.3_linux_amd64.tar.gz"}, skipped: true},
		{name: "one missing", files: []string{"checksums.txt"}},
		{name: "none present"},
		{name: "a pattern that matches another version", files: []string{"checksums.txt", "gosftpd_0.5.0_linux_amd64.tar.gz"}},
		{name: "in the directory of -D", files: []string{"checksums.txt", "gosftpd_1.2.3_linux_arm64.tar.gz"}, sub: "assets", flags: "-D assets", skipped: true},
		{name: "--dir= and --pattern=", files: []string{"checksums.txt", "gosftpd_1.2.3_linux_arm64.tar.gz", "x.json"}, sub: "a", flags: "--dir=a --pattern=x.json", skipped: true},
		{name: "-D names an empty directory", files: []string{"checksums.txt", "gosftpd_1.2.3_linux_arm64.tar.gz"}, flags: "-D elsewhere"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for _, f := range tt.files {
				d := filepath.Join(dir, tt.sub)
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
				write(t, d, f, "")
			}
			md := write(t, t.TempDir(), "install.md", strings.Replace(block, "%s", tt.flags, 1))
			got := runBlock(t, dir, []string{"V=1.2.3", fakeCommand(t, dir, "gh")}, "", "verify", md)
			if got.code != 0 || got.stdout != "done\n" {
				t.Fatalf("exit %d, %q, stderr: %s; want exit 0, \"done\"", got.code, got.stdout, got.stderr)
			}
			log := commandLog(t, dir, "gh")
			download := "release download v1.2.3 -R o/r -p checksums.txt -p gosftpd_1.2.3_linux_*.tar.gz"
			if tt.flags != "" {
				download += " " + tt.flags
			}
			want := download + "\nattestation verify x --repo o/r\n"
			if tt.skipped {
				want = "attestation verify x --repo o/r\n"
				if !strings.Contains(got.stderr, "skipped gh release download") {
					t.Errorf("stderr does not say that gh release download was skipped: %s", got.stderr)
				}
			}
			if log != want {
				t.Errorf("gh ran with\n%s\nwant\n%s", log, want)
			}
		})
	}
}

// runBlockCall matches a call of run-block.sh with a block's name.
var runBlockCall = regexp.MustCompile(`run-block\.sh"?\s+(?:--print\s+)?([a-z0-9][a-z0-9-]*)\b`)

// TestWorkflowBlocks checks that every block a workflow or a test script
// runs with run-block.sh is in docs/install.md and well formed: a marker
// that was renamed or removed fails here, not in a release.
func TestWorkflowBlocks(t *testing.T) {
	t.Parallel()
	var files []string
	for _, pattern := range []string{".github/workflows/*.yml", "test/*/*.sh"} {
		m, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	names := map[string][]string{} // name: the files that run it
	for _, f := range files {
		if filepath.Base(f) == "run-block.sh" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range runBlockCall.FindAllStringSubmatch(string(data), -1) {
			names[m[1]] = append(names[m[1]], f)
		}
	}
	// The docker job runs the first two, the packages job deb, release.yml
	// and verify-release.yml verify (ADR 0012).
	for _, want := range []string{"quickstart", "compose", "deb", "verify"} {
		if names[want] == nil {
			t.Errorf("no workflow or test script runs the %s block", want)
		}
	}
	for name, by := range names {
		got := runBlock(t, t.TempDir(), []string{"V=0.0.0"}, "", "--print", name)
		if got.code != 0 || got.stdout == "" {
			t.Errorf("%s run the block %s, which docs/install.md does not hold as run-block.sh needs it (exit %d): %s",
				strings.Join(by, ", "), name, got.code, got.stderr)
		}
	}
}

// TestInstallAnchors checks that every link the code gives to a section of
// docs/install.md, such as the hint of a missing configuration file, names
// a heading there.
func TestInstallAnchors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join(root, "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]bool{}
	heading := regexp.MustCompile(`^#{1,6} (.+)$`)
	fenced := false
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
		}
		if m := heading.FindStringSubmatch(line); m != nil && !fenced {
			anchors[anchor(m[1])] = true
		}
	}
	link := regexp.MustCompile(`docs/install\.md#([a-z0-9-]+)`)
	found := 0
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range link.FindAllStringSubmatch(string(src), -1) {
			found++
			if !anchors[m[1]] {
				t.Errorf("%s links docs/install.md#%s, which has no such heading", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Error("no link to docs/install.md#... in internal/: the hint of internal/cli/hint.go has one")
	}
}

// anchor returns the anchor GitHub gives a heading: lower case, without
// punctuation other than - and _, spaces as -.
func anchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}
