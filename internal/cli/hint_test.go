// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// wantHint is the hint after the first line for a build without a release
// version, such as a test binary (ADR 0012).
const wantHint = `Create one with 'gosftpd config example > config.toml' and replace the key placeholder.
With Docker, keep it in a directory and mount the directory:
  mkdir -p gosftpd && sudo chown "$(id -u):$(id -g)" gosftpd
  docker run --rm ghcr.io/o-kolomoiets/gosftpd:latest config example > gosftpd/config.toml
  # replace the key placeholder in gosftpd/config.toml with your public key, then:
  sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml
  docker run ... -v ./gosftpd:/etc/gosftpd:ro ...
See https://github.com/o-kolomoiets/Go-SFTP-Server/blob/main/docs/install.md#docker
`

// TestConfigHint checks the whole message, and exit code 2, for each case
// that gets the hint: --config or $GOSFTPD_CONFIG naming a missing file or
// a directory, a directory found by the search, no file found, and in the
// image an empty mounted /etc/gosftpd.
func TestConfigHint(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.toml")
	cfgDir := filepath.Join(dir, "config.toml")
	if err := os.Mkdir(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(dir, "etc-gosftpd") // stands for /etc/gosftpd
	if err := os.Mkdir(mounted, 0o755); err != nil {
		t.Fatal(err)
	}
	isDirCause := ": Docker creates one when the host file of a bind mount does not exist. " +
		"Remove it on the host ('sudo rmdir ./config.toml') and mount a directory instead"
	notFound := func() string { return "no configuration file found (" + searchList() + ")" }

	for _, tt := range []struct {
		name     string
		args     []string
		env      map[string]string
		imageDir string        // imageConfigDir; empty for one that does not exist
		search   bool          // the search must find nothing on this machine
		first    func() string // the first line, after "Error: "
	}{
		{
			name: "--config missing", args: []string{"config", "validate", "--config", missing},
			first: func() string { return "--config: " + missing + " does not exist" },
		},
		{
			name: "hostkey --config missing", args: []string{"hostkey", "show", "--config", missing},
			first: func() string { return "--config: " + missing + " does not exist" },
		},
		{
			name: "--config missing in the image", args: []string{"serve", "--allow-root", "--config", missing},
			env: map[string]string{envImage: "1"}, imageDir: mounted,
			first: func() string { return "--config: " + missing + " does not exist" },
		},
		{
			name: "$GOSFTPD_CONFIG missing", args: []string{"config", "show"}, env: map[string]string{config.EnvConfig: missing},
			first: func() string { return "$" + config.EnvConfig + ": " + missing + " does not exist" },
		},
		{
			name: "--config a directory", args: []string{"serve", "--allow-root", "--config", cfgDir},
			first: func() string { return "--config: " + cfgDir + " is a directory" + isDirCause },
		},
		{
			name: "$GOSFTPD_CONFIG a directory", args: []string{"user", "list"}, env: map[string]string{config.EnvConfig: cfgDir},
			first: func() string { return "$" + config.EnvConfig + ": " + cfgDir + " is a directory" + isDirCause },
		},
		{name: "nothing found", args: []string{"serve", "--allow-root"}, search: true, first: notFound},
		{
			name: "nothing found, outside the image", args: []string{"serve", "--allow-root"}, search: true,
			imageDir: mounted, first: notFound,
		},
		{
			name: "nothing found, in the image without /etc/gosftpd", args: []string{"serve", "--allow-root"}, search: true,
			env: map[string]string{envImage: "1"}, first: notFound,
		},
		{
			name: "nothing found, in the image with an empty /etc/gosftpd", args: []string{"config", "validate"}, search: true,
			env: map[string]string{envImage: "1"}, imageDir: mounted,
			first: func() string {
				return mounted + " is mounted but holds no config.toml; check the host path of -v (Docker creates a missing one as an empty directory owned by root)"
			},
		},
		{
			name: "image marker other than 1", args: []string{"serve", "--allow-root"}, search: true,
			env: map[string]string{envImage: "true"}, imageDir: mounted, first: notFound,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			if tt.search {
				noSystemConfig(t)
			}
			t.Chdir(t.TempDir())
			t.Setenv(envImage, "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			saved := imageConfigDir
			imageConfigDir = tt.imageDir
			if imageConfigDir == "" {
				imageConfigDir = filepath.Join(dir, "no-such-dir")
			}
			t.Cleanup(func() { imageConfigDir = saved })

			code, stdout, stderr := execute(t, tt.args...)
			if code != exitUsage || stdout != "" {
				t.Errorf("exit %d, stdout %q; want 2 and nothing", code, stdout)
			}
			if want := "Error: " + tt.first() + "\n" + wantHint; stderr != want {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr, want)
			}
		})
	}
}

// A configuration file that ./gosftpd.toml names but which is a directory
// gets the hint too, with that name in the rmdir command.
func TestConfigHintSearchFindsDirectory(t *testing.T) {
	isolate(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir(config.LocalFile, 0o700); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := execute(t, "config", "validate")
	want := "Error: " + config.LocalFile + " is a directory: Docker creates one when the host file of a bind mount does not exist. " +
		"Remove it on the host ('sudo rmdir ./" + config.LocalFile + "') and mount a directory instead\n" + wantHint
	if code != exitUsage || stderr != want {
		t.Errorf("exit %d, stderr:\n%s\nwant:\n%s", code, stderr, want)
	}
}

// Other errors of config.Find get no hint: they are not about a missing
// file, and the hint would not help.
func TestConfigHintOtherErrors(t *testing.T) {
	t.Parallel()

	noEnv := func(string) string { return "" }
	for _, err := range []error{
		&config.FileError{
			From: "--config", Path: "/etc/gosftpd/config.toml",
			Err: &fs.PathError{Op: "stat", Path: "/etc/gosftpd/config.toml", Err: syscall.EACCES},
		},
		&config.FileError{
			Path: "/etc/gosftpd/config.toml",
			Err:  &fs.PathError{Op: "stat", Path: "/etc/gosftpd/config.toml", Err: syscall.ENOTDIR},
		},
		// A search path that does not exist is skipped, never an error;
		// this one would be a bug, not a missing file.
		&config.FileError{Path: "/etc/gosftpd/config.toml", Err: fs.ErrNotExist},
		errors.New("something else"),
	} {
		if h := configHint(err, noEnv); h != nil {
			t.Errorf("%v: hint %q", err, h)
		}
	}
	h := configHint(config.ErrNotFound, noEnv)
	if !errors.Is(h, config.ErrNotFound) || !strings.HasPrefix(h.Error(), "no configuration file found (") {
		t.Errorf("not found: %v", h)
	}
}

func TestImageVersion(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ version, tag, ref string }{
		{"v0.5.0", "v0.5.0", "v0.5.0"},
		{"v0.5.0-rc.1", "v0.5.0-rc.1", "v0.5.0-rc.1"},
		{"v1.2.3-beta", "v1.2.3-beta", "v1.2.3-beta"},
		{"v0.1.0-alpha.2", "v0.1.0-alpha.2", "v0.1.0-alpha.2"},
		{"dev", "latest", "main"},
		{"", "latest", "main"},
		{"v0.5.1-0.20261023120000-0123456789ab", "latest", "main"}, // go install of a commit
		{"v0.5.0+dirty", "latest", "main"},
		{"v0.5.0-SNAPSHOT-0123456", "latest", "main"},
		{"0.5.0", "latest", "main"},
	} {
		if tag, ref := imageVersion(tt.version); tag != tt.tag || ref != tt.ref {
			t.Errorf("imageVersion(%q) = %q, %q; want %q, %q", tt.version, tag, ref, tt.tag, tt.ref)
		}
	}
}
