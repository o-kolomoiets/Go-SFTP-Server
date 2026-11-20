// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// releaseGUI runs .github/scripts/release-gui.sh with args, as the release
// job does.
func releaseGUI(t *testing.T, args ...string) result {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the release workflow runs the script on Ubuntu, with its tools")
	}
	cmd := exec.CommandContext(t.Context(), "bash", append([]string{".github/scripts/release-gui.sh"}, args...)...)
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

// fedoraRelease is packaging/gui/build.sh's FEDORA_RELEASE, the release in
// the name of the Fedora rpm.
func fedoraRelease(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "packaging", "gui", "build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^FEDORA_RELEASE=([0-9]+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("packaging/gui/build.sh has no FEDORA_RELEASE")
	}
	return string(m[1])
}

// guiFiles are the files of the gui-linux job's artifact for a version
// whose deb, rpm and Arch versions are deb, rpm and arch: the packages as
// nfpm names them, and an SBOM of each.
func guiFiles(t *testing.T, deb, rpm, arch string) []string {
	t.Helper()
	fc := fedoraRelease(t)
	var files []string
	for _, p := range []string{
		"gosftpd-gui_" + deb + "-1_amd64.deb",
		"gosftpd-gui-" + rpm + "-1.fc" + fc + ".x86_64.rpm",
		"gosftpd-gui-" + rpm + "-1.el9.x86_64.rpm",
		"gosftpd-gui-" + arch + "-1-x86_64.pkg.tar.zst",
	} {
		files = append(files, p, p+".sbom.json")
	}
	slices.Sort(files)
	return files
}

// writeGUI writes files into a new directory, each holding its own name,
// and returns the directory.
func writeGUI(t *testing.T, files []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range files {
		writeFile(t, dir, name)
	}
	return dir
}

func TestReleaseGUICheck(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		tag, deb, rpm, arch string
	}{
		{tag: "v0.6.0", deb: "0.6.0", rpm: "0.6.0", arch: "0.6.0"},
		// A pre-release sorts below its final: after "~" in deb and rpm,
		// and in Arch with the epoch nfpm writes.
		{tag: "v0.6.0-rc.1", deb: "0.6.0~rc.1", rpm: "0.6.0~rc.1", arch: "0.6.0rc.1"},
		// rpm and Arch versions have no "-".
		{tag: "v1.2.3-beta.2-x", deb: "1.2.3~beta.2-x", rpm: "1.2.3~beta.2_x", arch: "1.2.3beta.2_x"},
	} {
		t.Run(tt.tag, func(t *testing.T) {
			t.Parallel()
			files := guiFiles(t, tt.deb, tt.rpm, tt.arch)
			downloaded := writeGUI(t, files)
			out := filepath.Join(t.TempDir(), "gui")
			got := releaseGUI(t, "check", downloaded, out, tt.tag)
			if got.code != 0 || got.stderr != "" {
				t.Fatalf("release-gui.sh check = exit %d: %s", got.code, got.stderr)
			}
			if entries := tree(t, out); !slices.Equal(entries, files) {
				t.Errorf("out holds\n%s\nwant\n%s", strings.Join(entries, "\n"), strings.Join(files, "\n"))
			}
			for _, name := range files {
				data, err := os.ReadFile(filepath.Join(out, name))
				if err != nil || string(data) != name {
					t.Errorf("out/%s = %q, %v; want the downloaded file", name, data, err)
				}
			}
			if !strings.Contains(got.stdout, "holds the 8 GUI files of "+tt.tag) {
				t.Errorf("standard output: %q", got.stdout)
			}
		})
	}
}

func TestReleaseGUICheckRefuses(t *testing.T) {
	t.Parallel()
	files := func(t *testing.T) []string {
		t.Helper()
		return guiFiles(t, "0.6.0", "0.6.0", "0.6.0")
	}
	deb := "gosftpd-gui_0.6.0-1_amd64.deb"
	arch := "gosftpd-gui-0.6.0-1-x86_64.pkg.tar.zst"
	for _, tt := range []struct {
		name   string
		change change
		stderr string
	}{
		{name: "a loose gosftpd", change: add("gosftpd"), stderr: "gosftpd: an unexpected file"},
		{name: "the build's checksums", change: add("SHA256SUMS"), stderr: "SHA256SUMS: an unexpected file"},
		{name: "a package of another version", change: add("gosftpd-gui_0.5.9-1_amd64.deb"), stderr: "gosftpd-gui_0.5.9-1_amd64.deb: an unexpected file"},
		{name: "a package for arm64", change: add("gosftpd-gui_0.6.0-1_arm64.deb"), stderr: "gosftpd-gui_0.6.0-1_arm64.deb: an unexpected file"},
		{name: "a hidden file", change: add(".gosftpd-gui_0.6.0-1_amd64.deb"), stderr: ".gosftpd-gui_0.6.0-1_amd64.deb: an unexpected file"},
		{name: "a file in a directory", change: add("gui/" + deb), stderr: "gui: an unexpected directory"},
		{name: "an empty directory", change: emptyDir("gui"), stderr: "gui: an unexpected directory"},
		{name: "a package as a symbolic link", change: replaceWithLink(deb), stderr: deb + ": a symbolic link"},
		{name: "a named pipe", change: fifo("gosftpd-gui.fifo"), stderr: "gosftpd-gui.fifo: neither a regular file nor a directory"},
		{name: "no Arch package", change: remove(arch), stderr: arch + " is missing"},
		{name: "no SBOM of the deb", change: remove(deb + ".sbom.json"), stderr: deb + ".sbom.json is missing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			downloaded := writeGUI(t, files(t))
			tt.change(t, downloaded)
			out := filepath.Join(t.TempDir(), "gui")
			got := releaseGUI(t, "check", downloaded, out, "v0.6.0")
			if got.code != 1 || !strings.Contains(got.stderr, "release-gui.sh: "+tt.stderr) ||
				!strings.Contains(got.stderr, "does not hold exactly the GUI packages of v0.6.0 and their SBOMs") {
				t.Errorf("release-gui.sh check = exit %d, stderr:\n%s\nwant exit 1 and %q", got.code, got.stderr, tt.stderr)
			}
			if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("out was created: %v", err)
			}
		})
	}
	t.Run("the files of another tag", func(t *testing.T) {
		t.Parallel()
		downloaded := writeGUI(t, guiFiles(t, "0.6.0~rc.1", "0.6.0~rc.1", "0.6.0rc.1"))
		got := releaseGUI(t, "check", downloaded, filepath.Join(t.TempDir(), "gui"), "v0.6.0")
		if got.code != 1 || !strings.Contains(got.stderr, "release-gui.sh: "+deb+" is missing") {
			t.Errorf("release-gui.sh check = exit %d, stderr:\n%s", got.code, got.stderr)
		}
	})
}

func TestReleaseGUIUsage(t *testing.T) {
	t.Parallel()
	downloaded := writeGUI(t, guiFiles(t, "0.6.0", "0.6.0", "0.6.0"))
	existing := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(downloaded, link); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "gui")
	for _, tt := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{name: "no arguments", code: 2, stderr: "usage: release-gui.sh check DOWNLOADED OUT TAG"},
		{name: "check without the tag", args: []string{"check", downloaded, out}, code: 2, stderr: "usage:"},
		{name: "another command", args: []string{"sign", downloaded, out}, code: 2, stderr: "usage:"},
		{name: "not a version tag", args: []string{"check", downloaded, out, "0.6.0"}, code: 1, stderr: "0.6.0 is not a version tag"},
		{name: "a tag with a space", args: []string{"check", downloaded, out, "v0.6.0 x"}, code: 1, stderr: "is not a version tag"},
		{name: "an existing directory", args: []string{"check", downloaded, existing, "v0.6.0"}, code: 1, stderr: existing + " exists: the files go into a new directory"},
		{name: "a symbolic link to the artifact", args: []string{"check", link, out, "v0.6.0"}, code: 1, stderr: link + " is not a directory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := releaseGUI(t, tt.args...)
			if got.code != tt.code || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("release-gui.sh %q = exit %d, stderr: %s; want exit %d, %q", tt.args, got.code, got.stderr, tt.code, tt.stderr)
			}
		})
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("out was created: %v", err)
	}
	if entries := tree(t, existing); len(entries) != 0 {
		t.Errorf("the existing directory got %q", entries)
	}
}

// checksumLine is the line of name in checksums.txt, as GoReleaser writes
// it, for a file holding its own name.
func checksumLine(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestReleaseGUIChecksums(t *testing.T) {
	t.Parallel()
	files := guiFiles(t, "0.6.0", "0.6.0", "0.6.0")
	var all strings.Builder
	all.WriteString(checksumLine("gosftpd_0.6.0_linux_amd64.tar.gz"))
	for _, name := range files {
		all.WriteString(checksumLine(name))
	}
	deb := "gosftpd-gui_0.6.0-1_amd64.deb"
	for _, tt := range []struct {
		name   string
		sums   string
		stderr string // empty: the check passes
	}{
		{name: "every file", sums: all.String()},
		{name: "a file left out", sums: strings.Replace(all.String(), checksumLine(deb), "", 1), stderr: "does not list " + deb + " with its SHA-256"},
		{name: "another digest", sums: strings.Replace(all.String(), checksumLine(deb), strings.Repeat("0", 64)+"  "+deb+"\n", 1), stderr: "does not list " + deb},
		{name: "another name", sums: strings.Replace(all.String(), "  "+deb+"\n", "  x"+deb+"\n", 1), stderr: "does not list " + deb},
		{name: "a line with more after the name", sums: strings.Replace(all.String(), "  "+deb+"\n", "  "+deb+".orig\n", 1), stderr: "does not list " + deb},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := writeGUI(t, files)
			sums := filepath.Join(t.TempDir(), "checksums.txt")
			if err := os.WriteFile(sums, []byte(tt.sums), 0o600); err != nil {
				t.Fatal(err)
			}
			got := releaseGUI(t, "checksums", dir, sums)
			if tt.stderr == "" {
				if got.code != 0 || got.stderr != "" || !strings.Contains(got.stdout, "lists the 8 files of") {
					t.Errorf("release-gui.sh checksums = exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
				}
				return
			}
			if got.code != 1 || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("release-gui.sh checksums = exit %d, stderr:\n%s\nwant exit 1 and %q", got.code, got.stderr, tt.stderr)
			}
		})
	}
	t.Run("no files", func(t *testing.T) {
		t.Parallel()
		sums := filepath.Join(t.TempDir(), "checksums.txt")
		if err := os.WriteFile(sums, []byte(all.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		got := releaseGUI(t, "checksums", t.TempDir(), sums)
		if got.code != 1 || !strings.Contains(got.stderr, "holds no file") {
			t.Errorf("release-gui.sh checksums = exit %d, stderr: %s", got.code, got.stderr)
		}
	})
}
