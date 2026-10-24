// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
)

// envImage is set by the container image (ENV GOSFTPD_ATMOZ_IMAGE=1, ADR
// 0012).
const envImage = "GOSFTPD_ATMOZ_IMAGE"

// imageConfigDir is where the image looks for its configuration. Its base
// image has no such directory, so in the image one is a mount, and one
// without config.toml was mounted from a wrong or missing host path. A
// variable for tests.
var imageConfigDir = "/etc/gosftpd"

// safeName matches a file name that a shell command can hold unquoted.
var safeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// releaseVersion matches the version of a release build: the release
// workflows accept only tags of this form.
var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`)

// hintText follows the first line of a hint: the commands lead to a
// configuration that serve accepts. Outside Docker that is gosftpd init,
// whose ./gosftpd.toml the search finds, or serve --dir; with Docker the
// host directory may have been created by Docker as root and the file
// must belong to root or to the image's user, 65532 (ADR 0012).
const hintText = `Create one with 'gosftpd init' (it writes ./gosftpd.toml, which serve finds; --out names another path), or serve a directory without one: 'gosftpd serve --dir PATH'.
With Docker, keep it in a directory and mount the directory:
  mkdir -p gosftpd && sudo chown "$(id -u):$(id -g)" gosftpd
  docker run --rm ghcr.io/o-kolomoiets/gosftpd:%[1]s config example > gosftpd/config.toml
  # replace the key placeholder in gosftpd/config.toml with your public key, then:
  sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml
  docker run ... -v ./gosftpd:/etc/gosftpd:ro ...
See https://github.com/o-kolomoiets/Go-SFTP-Server/blob/%[2]s/docs/install.md#docker`

// hintError is a configuration file that is missing or a directory: what
// is wrong on the first line, then what to do.
type hintError struct {
	first, hint string
	err         error // from config.Find
}

func (e hintError) Error() string { return e.first + "\n" + e.hint }
func (e hintError) Unwrap() error { return e.err }

// configHint returns err, an error of config.Find, with a hint when no
// file was found or the file that --config or $GOSFTPD_CONFIG names does
// not exist or is a directory, and nil for any other error.
func configHint(err error, getenv func(string) string) error {
	var first string
	fe, _ := errors.AsType[*config.FileError](err)
	inImage := getenv(envImage) == "1"
	switch {
	case errors.Is(err, config.ErrNotFound):
		first = fmt.Sprintf("%s (%s)", config.ErrNotFound, searchList())
		if errors.Is(err, fs.ErrPermission) {
			// config.Find skipped ./gosftpd.toml, which may exist.
			first += "; " + localPath() + " was not checked, since the working directory cannot be searched: name the file with --config"
		}
		if inImage && isDir(imageConfigDir) {
			first = imageConfigDir + " is mounted but holds no config.toml; check the host path of -v (Docker creates a missing one as an empty directory owned by root)"
		}
	case fe != nil && errors.Is(err, config.ErrIsDir) && fe.From != "" && !inImage:
		// Named on the host: most likely the configuration directory.
		first = fmt.Sprintf("%s: name the file in it, such as %s", err, filepath.Join(fe.Path, "config.toml"))
	case fe != nil && errors.Is(err, config.ErrIsDir):
		first = fmt.Sprintf("%s: Docker creates one when the host file of a bind mount does not exist. Remove it on the host ('sudo rmdir %s') and mount a directory instead",
			err, hostPath(fe.Path))
	case fe != nil && fe.From != "" && errors.Is(err, fs.ErrNotExist):
		first = err.Error()
	default:
		return nil
	}
	tag, ref := imageVersion(version.Get().Version)
	return hintError{first: first, hint: fmt.Sprintf(hintText, tag, ref), err: err}
}

// imageVersion returns the image tag and the git ref that the hint names:
// the binary's own version for a release build (a snapshot reports the
// last tag), else latest and main.
func imageVersion(v string) (tag, ref string) {
	if releaseVersion.MatchString(v) {
		return v, v
	}
	return "latest", "main"
}

// hostPath returns the path to give rmdir for the host directory that
// Docker created in place of the file path: ./ and its name, which the
// mount most likely shares, or a placeholder for a name that would need
// quoting.
func hostPath(path string) string {
	if name := filepath.Base(path); safeName.MatchString(name) && name != "." && name != ".." {
		return "./" + name
	}
	return "<host path of -v>"
}

// searchList lists the paths config.Find searches, ./gosftpd.toml first.
func searchList() string {
	paths := config.SearchPaths()
	for i, p := range paths {
		if !filepath.IsAbs(p) {
			paths[i] = "." + string(filepath.Separator) + p
		}
	}
	return strings.Join(paths, ", ")
}

// localPath is ./gosftpd.toml as searchList names it.
func localPath() string { return "." + string(filepath.Separator) + config.LocalFile }

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
