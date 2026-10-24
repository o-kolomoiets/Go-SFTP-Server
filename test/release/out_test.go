// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// generatedFiles are files of the generate job's artifact as make generate
// writes them: the release takes exactly these, the man pages of other
// commands aside.
var generatedFiles = []string{
	"THIRD_PARTY_LICENSES",
	"completions/_gosftpd", "completions/gosftpd.bash", "completions/gosftpd.fish",
	"man/gosftpd.1.gz", "man/gosftpd-serve.1.gz", "man/gosftpd-user-add.1.gz",
}

// releaseOut runs .github/scripts/release-out.sh with args, as the release
// job does.
func releaseOut(t *testing.T, args ...string) result {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the release workflow runs the script on Linux")
	}
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{".github/scripts/release-out.sh"}, args...)...)
	cmd.Dir = root
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var r result
	err := cmd.Run()
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

// writeGenerated writes the files of generatedFiles into a new directory,
// each holding its own name, and returns the directory.
func writeGenerated(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range generatedFiles {
		writeFile(t, dir, name)
	}
	return dir
}

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tree lists the files and directories under dir, directories with a
// trailing slash.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if d.IsDir() {
			rel += "/"
		}
		entries = append(entries, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestReleaseOut(t *testing.T) {
	t.Parallel()
	generated := writeGenerated(t)
	out := filepath.Join(t.TempDir(), "out")
	got := releaseOut(t, generated, out)
	if got.code != 0 || got.stderr != "" {
		t.Fatalf("release-out.sh = exit %d: %s", got.code, got.stderr)
	}
	want := append([]string{
		"completions/", "docker/", "docker/empty/", "docker/home-root/", "docker/home-root/home/", "man/",
	}, generatedFiles...)
	slices.Sort(want)
	if entries := tree(t, out); !slices.Equal(entries, want) {
		t.Errorf("out holds\n%s\nwant\n%s", strings.Join(entries, "\n"), strings.Join(want, "\n"))
	}
	for _, name := range generatedFiles {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || string(data) != name {
			t.Errorf("out/%s = %q, %v; want the generated file", name, data, err)
		}
	}
	if !strings.Contains(got.stdout, "holds 7 files from") {
		t.Errorf("standard output: %q", got.stdout)
	}
}

// change changes the files of writeGenerated.
type change func(t *testing.T, dir string)

// add adds a file.
func add(name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		writeFile(t, dir, name)
	}
}

// remove removes a file or a directory.
func remove(name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// replaceWithLink replaces name, a file or directory, with a symbolic link
// to a copy of it elsewhere.
func replaceWithLink(name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.Rename(filepath.Join(dir, name), target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// link adds a symbolic link.
func link(target, name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// fifo adds a named pipe.
func fifo(name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "mkfifo", filepath.Join(dir, name))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("mkfifo: %v: %s", err, out)
		}
	}
}

// emptyDir adds an empty directory.
func emptyDir(name string) change {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReleaseOutRefuses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		change change
		stderr string
	}{
		{name: "a binary for the image", change: add("docker/home-root/usr/bin/gosftpd"), stderr: "docker/home-root/usr/bin/gosftpd: an unexpected file"},
		{name: "a host key for the image", change: add("docker/empty/ssh_host_ed25519_key"), stderr: "docker: an unexpected directory"},
		{name: "a file beside the license file", change: add("NOTES"), stderr: "NOTES: an unexpected file"},
		{name: "a hidden file", change: add("man/.gosftpd.1.gz"), stderr: "man/.gosftpd.1.gz: an unexpected file"},
		{name: "a man page of another name", change: add("man/sshd.1.gz"), stderr: "man/sshd.1.gz: an unexpected file"},
		{name: "a man page in another section", change: add("man/gosftpd.8.gz"), stderr: "man/gosftpd.8.gz: an unexpected file"},
		{name: "a man page not compressed", change: add("man/gosftpd-serve.1"), stderr: "man/gosftpd-serve.1: an unexpected file"},
		{name: "a man page in a subdirectory", change: add("man/man1/gosftpd.1.gz"), stderr: "man/man1: an unexpected directory"},
		{name: "another completion", change: add("completions/gosftpd.ps1"), stderr: "completions/gosftpd.ps1: an unexpected file"},
		// A name of the list with something after it, or in another
		// directory: the list's anchors.
		{name: "a completion with a suffix", change: add("completions/gosftpd.bash.orig"), stderr: "completions/gosftpd.bash.orig: an unexpected file"},
		{name: "a man page with a suffix", change: add("man/gosftpd.1.gz.1.gz"), stderr: "man/gosftpd.1.gz.1.gz: an unexpected file"},
		{name: "the license file with a suffix", change: add("THIRD_PARTY_LICENSES.txt"), stderr: "THIRD_PARTY_LICENSES.txt: an unexpected file"},
		{name: "the license file among the completions", change: add("completions/THIRD_PARTY_LICENSES"), stderr: "completions/THIRD_PARTY_LICENSES: an unexpected file"},
		{name: "the license file among the man pages", change: add("man/THIRD_PARTY_LICENSES"), stderr: "man/THIRD_PARTY_LICENSES: an unexpected file"},
		{name: "an empty directory", change: emptyDir("docker"), stderr: "docker: an unexpected directory"},
		{name: "a man page that is a symbolic link", change: link("../THIRD_PARTY_LICENSES", "man/gosftpd-init.1.gz"), stderr: "man/gosftpd-init.1.gz: a symbolic link"},
		{name: "the license file as a symbolic link", change: replaceWithLink("THIRD_PARTY_LICENSES"), stderr: "THIRD_PARTY_LICENSES: a symbolic link"},
		{name: "the completions as a symbolic link", change: replaceWithLink("completions"), stderr: "completions: a symbolic link"},
		{name: "a named pipe", change: fifo("man/gosftpd-fifo.1.gz"), stderr: "man/gosftpd-fifo.1.gz: neither a regular file nor a directory"},
		{name: "no main man page", change: remove("man/gosftpd.1.gz"), stderr: "man/gosftpd.1.gz is missing"},
		{name: "no license file", change: remove("THIRD_PARTY_LICENSES"), stderr: "THIRD_PARTY_LICENSES is missing"},
		{name: "no fish completion", change: remove("completions/gosftpd.fish"), stderr: "completions/gosftpd.fish is missing"},
		{name: "no completions", change: remove("completions"), stderr: "completions/_gosftpd is missing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generated := writeGenerated(t)
			tt.change(t, generated)
			out := filepath.Join(t.TempDir(), "out")
			got := releaseOut(t, generated, out)
			if got.code != 1 || !strings.Contains(got.stderr, "release-out.sh: "+tt.stderr) ||
				!strings.Contains(got.stderr, "does not hold exactly the files of make generate that a release takes") {
				t.Errorf("release-out.sh = exit %d, stderr:\n%s\nwant exit 1 and %q", got.code, got.stderr, tt.stderr)
			}
			if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("out was created: %v", err)
			}
		})
	}
}

func TestReleaseOutUsage(t *testing.T) {
	t.Parallel()
	generated := writeGenerated(t)
	existing := t.TempDir()
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(generated, link); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{name: "no arguments", code: 2, stderr: "usage: release-out.sh GENERATED OUT"},
		{name: "one argument", args: []string{generated}, code: 2, stderr: "usage:"},
		{name: "an existing directory", args: []string{generated, existing}, code: 1, stderr: existing + " exists: the files go into a new directory"},
		{name: "an existing file", args: []string{generated, file}, code: 1, stderr: file + " exists"},
		{name: "not a directory", args: []string{file, filepath.Join(existing, "out")}, code: 1, stderr: file + " is not a directory"},
		{name: "a symbolic link to the artifact", args: []string{link, filepath.Join(existing, "out")}, code: 1, stderr: link + " is not a directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := releaseOut(t, tt.args...)
			if got.code != tt.code || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("release-out.sh %q = exit %d, stderr: %s; want exit %d, %q", tt.args, got.code, got.stderr, tt.code, tt.stderr)
			}
		})
	}
	if entries := tree(t, existing); len(entries) != 0 {
		t.Errorf("the existing directory got %q", entries)
	}
}
