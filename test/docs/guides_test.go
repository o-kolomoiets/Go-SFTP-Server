// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// readFile returns the repository file at the path elem names.
func readFile(t *testing.T, elem ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{root}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAtmozUsersFileMode checks that docs/migrate-from-atmoz.md keeps the
// users file, which holds plain passwords, from the other users of the
// host, and that test/docker/atmoz.sh runs the guide's form: the image's
// group 65532 and mode 0640, not the 0644 of a key file.
func TestAtmozUsersFileMode(t *testing.T) {
	t.Parallel()
	guide := readFile(t, "docs", "migrate-from-atmoz.md")
	script := readFile(t, "test", "docker", "atmoz.sh")

	chmods := regexp.MustCompile(`chmod (\S+) (?:<host-dir>/)?users\.conf\b`).FindAllStringSubmatch(guide, -1)
	if len(chmods) == 0 {
		t.Fatal("docs/migrate-from-atmoz.md has no chmod of users.conf")
	}
	for _, m := range chmods {
		if mode, err := strconv.ParseUint(m[1], 8, 32); err != nil || mode&0o007 != 0 {
			t.Errorf("docs/migrate-from-atmoz.md: %q leaves the users file readable by others", m[0])
		}
	}

	// The command of "Store users in config", which atmoz.sh follows.
	cmd := regexp.MustCompile(`sudo chown (\S+) <host-dir>/users\.conf && sudo chmod (\S+) <host-dir>/users\.conf`).FindAllStringSubmatch(guide, -1)
	if len(cmd) != 1 {
		t.Fatalf("docs/migrate-from-atmoz.md has %d \"sudo chown OWNER <host-dir>/users.conf && sudo chmod MODE ...\" commands, want 1", len(cmd))
	}
	owner, mode := cmd[0][1], cmd[0][2]
	if owner != "root:65532" || mode != "0640" {
		t.Errorf("docs/migrate-from-atmoz.md: the users file gets %s %s, want root:65532 0640", owner, mode)
	}
	// atmoz.sh names the owner by numbers, and UID alone for UID:UID.
	numeric := func(owner string) string {
		user, group, ok := strings.Cut(owner, ":")
		if !ok {
			group = user
		}
		id := func(name string) string {
			if name == "root" {
				return "0"
			}
			return name
		}
		return id(user) + ":" + id(group)
	}
	ran := map[string]string{} // chmod and own: the argument atmoz.sh gives them
	for _, m := range regexp.MustCompile(`(?m)^(chmod|own) (\S+) "\$WORK/users\.conf"$`).FindAllStringSubmatch(script, -1) {
		ran[m[1]] = m[2]
	}
	if ran["chmod"] != mode || numeric(ran["own"]) != numeric(owner) {
		t.Errorf("test/docker/atmoz.sh gives users.conf the mode %q and the owner %q, want the guide's %s and %s",
			ran["chmod"], ran["own"], mode, owner)
	}
}

// htpasswdB matches an htpasswd command with -b among its options, which
// takes the password from the command line.
var htpasswdB = regexp.MustCompile(`htpasswd\s+(?:(?:-[A-Za-z]+|\d+)\s+)*-[A-Za-z]*b`)

// TestHtpasswdAsks checks that no command in the Markdown files of docs/
// and the top directory runs htpasswd with -b: the password would stay in
// the shell history and show in the process list. Without -b, htpasswd
// asks for it.
func TestHtpasswdAsks(t *testing.T) {
	t.Parallel()
	top, err := filepath.Glob(filepath.Join(root, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files := top
	err = filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if m := htpasswdB.FindString(line); m != "" {
				t.Errorf("%s:%d: %q puts the password on the command line; let htpasswd ask for it", f, i+1, m)
			}
		}
	}
}

// TestHtpasswdB checks the pattern of TestHtpasswdAsks.
func TestHtpasswdB(t *testing.T) {
	t.Parallel()
	for line, want := range map[string]bool{
		`htpasswd -bnBC 10 "" 'the password' | tr -d ':\n'`: true,
		`htpasswd -nbBC 10 "" PASS`:                         true,
		`htpasswd -nBC 10 -b "" PASS`:                       true,
		"`htpasswd -c -b file user pass`":                   true,
		`htpasswd -nBC 10 "" | tr -d ':\n'`:                 false,
		`htpasswd -niBC 10 ""`:                              false,
		"`htpasswd`'s default bcrypt cost":                  false,
		"do not give it to `htpasswd` with `-b`":            false,
	} {
		if got := htpasswdB.MatchString(line); got != want {
			t.Errorf("htpasswdB.MatchString(%q) = %v, want %v", line, got, want)
		}
	}
}

// TestComposeExample checks the compose block of docs/install.md with a fake
// docker and gh (test/docker/run.sh runs it against the image after each
// variant of the Quickstart). It gets digests.txt with gh (run-block.sh
// skips that when the file is present), and with the release's digest it
// writes docs/examples/compose.yaml, with <digest> for the digest; only
// then, and once docker compose config accepts the file, it removes the
// Quickstart's container, which holds port 2022, and starts the service.
// Without the digest it removes nothing. After the Quickstart's variants,
// DATA and STATE name its named volumes, and RUN_AS its user.
func TestComposeExample(t *testing.T) {
	t.Parallel()
	m := regexp.MustCompile("(?m)^<!-- ci:compose -->\n```sh\nV=(\\S+)$").FindStringSubmatch(readFile(t, "docs", "install.md"))
	if m == nil {
		t.Fatal("docs/install.md: no compose block that starts with a V= line")
	}
	v := m[1]
	digest := strings.Repeat("0123456789abcdef", 4)
	example := strings.ReplaceAll(readFile(t, "docs", "examples", "compose.yaml"), "<digest>", digest)
	const started = "compose config --quiet\nrm -f gosftpd\ncompose up -d --wait\n"
	for _, tt := range []struct {
		name    string
		digests string   // digests.txt; none when empty
		env     []string // the variant's variables
		started bool     // the block removed the container and started the service
		gh      string   // the calls of gh
		file    func(string) string
	}{
		{
			name:    "the release's digests.txt",
			digests: digest + "  ghcr.io/o-kolomoiets/gosftpd:v" + v + "\n",
			started: true,
			file:    func(string) string { return example },
		},
		{
			name: "no digests.txt, and gh downloads nothing",
			gh:   "release download v" + v + " -R o-kolomoiets/Go-SFTP-Server -p digests.txt --clobber\n",
		},
		{
			name:    "digests.txt without the version",
			digests: digest + "  ghcr.io/o-kolomoiets/gosftpd:v0.0.1\n",
		},
		{
			name:    "after the variant with named volumes",
			digests: digest + "  ghcr.io/o-kolomoiets/gosftpd:v" + v + "\n",
			env:     []string{"DATA=gosftpd-data", "STATE=gosftpd-state"},
			started: true,
			file: func(string) string {
				return strings.NewReplacer(
					"./data and ./state keep", "gosftpd-data and gosftpd-state keep",
					"      - ./data:/srv/sftp\n", "      - gosftpd-data:/srv/sftp\n",
					"      - ./state:/var/lib/gosftpd\n", "      - gosftpd-state:/var/lib/gosftpd\n",
				).Replace(example)
			},
		},
		{
			name:    "after the variant with your own uid",
			digests: digest + "  ghcr.io/o-kolomoiets/gosftpd:v" + v + "\n",
			env:     []string{"RUN_AS=1000:1000"},
			started: true,
			file: func(string) string {
				return strings.Replace(example, `    user: "65532:65532"`+"\n", `    user: "1000:1000"`+"\n", 1)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if tt.digests != "" {
				write(t, dir, "digests.txt", tt.digests)
			}
			env := append([]string{"V=" + v, fakeCommand(t, dir, "docker", "gh"), "DATA=", "STATE=", "RUN_AS="}, tt.env...)
			got := runBlock(t, dir, env, "", "compose")
			if tt.started != (got.code == 0) {
				t.Errorf("exit %d, stderr: %s", got.code, got.stderr)
			}
			want := ""
			if tt.started {
				want = started
			}
			if log := commandLog(t, dir, "docker"); log != want {
				t.Errorf("the compose block ran docker with\n%s\nwant\n%s", log, want)
			}
			if log := commandLog(t, dir, "gh"); log != tt.gh {
				t.Errorf("the compose block ran gh with\n%s\nwant\n%s", log, tt.gh)
			}
			if tt.file == nil {
				return
			}
			data, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if want := tt.file(example); string(data) != want {
				t.Errorf("the compose block writes\n%s\nwant\n%s", data, want)
			}
		})
	}
}

// macOSCheck matches the sentence that gives the macOS checksum command,
// in text whose white space is collapsed: the command, then what follows
// up to the sentence's end.
var macOSCheck = regexp.MustCompile("On macOS, check (?:the archive )?with `([^`]+)`([^.]*)\\.")

// TestMacOSChecksum checks the macOS checksum command of docs/install.md,
// docs/quickstart.md and README.md, which no CI job runs: the three give
// the same sentence, and the command checks the one archive downloaded
// against a checksums.txt laid out like a release's, which also lists each
// archive's SBOM (<archive>.sbom.json) and the packages. It runs with the
// shasum that macOS has, Perl's Digest::SHA, which the Ubuntu runners have
// too, for darwin_arm64 and for darwin_amd64, which the sentence names
// for an Intel Mac.
func TestMacOSChecksum(t *testing.T) {
	t.Parallel()
	var sentence, cmd string
	for _, name := range []string{"docs/install.md", "docs/quickstart.md", "README.md"} {
		text := strings.Join(strings.Fields(readFile(t, filepath.FromSlash(name))), " ")
		m := macOSCheck.FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("%s has no sentence \"On macOS, check the archive with `COMMAND`\"", name)
		}
		switch {
		case sentence == "":
			sentence, cmd = m[0], m[1]
		case m[0] != sentence:
			t.Errorf("%s says %q, docs/install.md %q", name, m[0], sentence)
		}
	}
	if !strings.Contains(sentence, "`darwin_amd64`") {
		t.Errorf("the macOS sentence does not name darwin_amd64 for an Intel Mac: %q", sentence)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the command runs in a POSIX shell")
	}
	if _, err := exec.LookPath("shasum"); err != nil {
		t.Skip("no shasum here: it comes with Perl")
	}
	const v = "0.5.0"
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			archive := "gosftpd_" + v + "_darwin_" + arch + ".tar.gz"
			data := []byte("the archive for darwin_" + arch)
			write(t, dir, archive, string(data))
			sum := sha256.Sum256(data)
			var names []string
			for _, p := range []string{"darwin_amd64", "darwin_arm64", "freebsd_amd64", "freebsd_arm64", "linux_amd64", "linux_arm64"} {
				a := "gosftpd_" + v + "_" + p + ".tar.gz"
				names = append(names, a, a+".sbom.json")
				if strings.HasPrefix(p, "linux_") {
					for _, ext := range []string{".deb", ".rpm", ".pkg.tar.zst"} {
						names = append(names, "gosftpd_"+v+"_"+p+ext)
					}
				}
			}
			slices.Sort(names)
			var sums strings.Builder
			for i, n := range names {
				h := fmt.Sprintf("%064x", i+1)
				if n == archive {
					h = hex.EncodeToString(sum[:])
				}
				fmt.Fprintf(&sums, "%s  %s\n", h, n)
			}
			write(t, dir, "checksums.txt", sums.String())
			c := strings.ReplaceAll(cmd, "darwin_arm64", "darwin_"+arch)
			run := exec.CommandContext(t.Context(), "bash", "-c", c)
			run.Dir = dir
			out, err := run.CombinedOutput()
			if want := archive + ": OK\n"; err != nil || string(out) != want {
				t.Errorf("%s: %v, output:\n%s\nwant %q", c, err, out, want)
			}
		})
	}
}

// docVersion matches a version that a documented example names: V=X.Y.Z
// and the image's tag gosftpd:vX.Y.Z, with a pre-release suffix.
var docVersion = regexp.MustCompile(`\bV=([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*)|\bgosftpd:v([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*)`)

// TestDocVersions checks that the examples of README.md, SECURITY.md and
// docs/ (but the ADRs, which record what was decided when) name the
// version that the Quickstart block of docs/install.md names, so that step
// 13 of the release checklist, which moves them to the new release, leaves
// none behind: the GitHub Actions step and the container example of
// configuration.md, migrate-from-atmoz.md, examples/compose.yaml and the
// copies of the Quickstart.
func TestDocVersions(t *testing.T) {
	t.Parallel()
	m := regexp.MustCompile("(?m)^<!-- ci:quickstart -->\n```sh\nV=(\\S+)$").FindStringSubmatch(readFile(t, "docs", "install.md"))
	if m == nil {
		t.Fatal("docs/install.md: no quickstart block that starts with a V= line")
	}
	want := m[1]
	files := []string{filepath.Join(root, "README.md"), filepath.Join(root, "SECURITY.md")}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "adr":
			return filepath.SkipDir
		case !d.IsDir() && (strings.HasSuffix(path, ".md") || strings.HasPrefix(filepath.ToSlash(path), filepath.ToSlash(filepath.Join(root, "docs", "examples"))+"/")):
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range docVersion.FindAllStringSubmatch(line, -1) {
				found++
				if got := m[1] + m[2]; got != want {
					t.Errorf("%s:%d: %q names %s; the Quickstart of docs/install.md names %s", f, i+1, m[0], got, want)
				}
			}
		}
	}
	if found < 10 {
		t.Errorf("only %d versions found in the examples: the pattern no longer matches them", found)
	}
}

// imageKey matches the image: line of a Compose service.
var imageKey = regexp.MustCompile(`(?m)^\s*image:`)

// composeKeys are the top-level keys of the Compose file format; x-
// extensions are allowed too.
var composeKeys = map[string]bool{
	"version": true, "name": true, "include": true, "services": true, "networks": true,
	"volumes": true, "configs": true, "secrets": true, "models": true,
}

// TestComposeFiles checks that every yaml block of docs/ (but the ADRs)
// that names an image, and every file in docs/examples, is a Compose file
// that docker compose accepts as it stands, as far as its top level goes:
// only Compose's own keys, the services under services:. atmoz's README
// still has the old form with the service at the top level, which Compose
// refuses ("additional properties 'sftp' not allowed").
func TestComposeFiles(t *testing.T) {
	t.Parallel()
	type file struct{ name, text string }
	var files []file
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "adr":
			return filepath.SkipDir
		case d.IsDir():
			return nil
		case filepath.Base(filepath.Dir(path)) == "examples" && strings.HasSuffix(path, ".yaml"):
			data, err := os.ReadFile(path)
			files = append(files, file{path, string(data)})
			return err
		case !strings.HasSuffix(path, ".md"):
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		block, line, in := "", 0, false
		for i, l := range strings.Split(string(data), "\n") {
			switch {
			case !in && strings.TrimSpace(l) == "```yaml":
				in, block, line = true, "", i+1
			case in && strings.TrimSpace(l) == "```":
				in = false
				if imageKey.MatchString(block) {
					files = append(files, file{fmt.Sprintf("%s:%d", path, line), block})
				}
			case in:
				block += l + "\n"
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("found %d compose files in docs/, want the migration guide's and docs/examples/compose.yaml", len(files))
	}
	for _, f := range files {
		var keys []string
		for l := range strings.SplitSeq(f.text, "\n") {
			if l == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "#") {
				continue
			}
			key, _, _ := strings.Cut(l, ":")
			keys = append(keys, key)
			if !composeKeys[key] && !strings.HasPrefix(key, "x-") {
				t.Errorf("%s: the top-level key %q is not one of Compose's: put the service under services:", f.name, key)
			}
		}
		if !slices.Contains(keys, "services") {
			t.Errorf("%s: no services: at the top level", f.name)
		}
	}
}
