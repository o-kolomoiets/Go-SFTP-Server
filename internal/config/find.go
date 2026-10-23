// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

// Environment variables. Command-line flags override them; they override the
// configuration file.
const (
	EnvConfig    = "GOSFTPD_CONFIG"
	EnvListen    = "GOSFTPD_LISTEN"
	EnvLogLevel  = "GOSFTPD_LOG_LEVEL"
	EnvLogFormat = "GOSFTPD_LOG_FORMAT"
)

// LocalFile is the configuration file looked for in the current directory;
// gosftpd init writes it.
const LocalFile = "gosftpd.toml"

// ErrNotFound means no configuration file was found.
var ErrNotFound = errors.New("no configuration file found")

// ErrIsDir means the configuration file is a directory. Docker creates one
// when the host file of a bind mount does not exist.
var ErrIsDir = errors.New("is a directory")

// FileError is a configuration file that Find was given or found but
// cannot use. Err is the error of stat, fs.ErrNotExist among them, or
// ErrIsDir.
type FileError struct {
	From string // "--config" or "$GOSFTPD_CONFIG"; empty for a search path
	Path string
	Err  error
}

func (e *FileError) Error() string {
	var msg string
	switch {
	case errors.Is(e.Err, fs.ErrNotExist):
		msg = e.Path + " does not exist"
	case errors.Is(e.Err, ErrIsDir):
		msg = e.Path + " " + ErrIsDir.Error()
	default:
		msg = e.Err.Error()
	}
	if e.From == "" {
		return msg
	}
	return e.From + ": " + msg
}

func (e *FileError) Unwrap() error { return e.Err }

// SearchPaths returns the default locations, in order: ./gosftpd.toml,
// /etc/gosftpd/config.toml (not on Windows) and the user configuration
// directory.
func SearchPaths() []string {
	paths := []string{LocalFile}
	if runtime.GOOS != "windows" {
		paths = append(paths, "/etc/gosftpd/config.toml")
	}
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "gosftpd", "config.toml"))
	}
	return paths
}

// Find returns the configuration file to use: explicit (from --config) if
// set, else $GOSFTPD_CONFIG, else the first of SearchPaths that exists. An
// explicit or environment path must exist, and no file it returns is a
// directory. A permission error on ./gosftpd.toml counts as not found when
// lstat fails with one too, so that a working directory the user cannot
// search (/root under sudo -u, the image's under docker run --user) does
// not stop the search; a ./gosftpd.toml that lstat sees but stat cannot
// reach, such as a symlink into a directory the user cannot search, and a
// permission error on every other path are errors (ADR 0012). ErrNotFound
// then wraps the skipped error too. Its errors other than ErrNotFound are
// *FileError.
func Find(explicit string, getenv func(string) string) (string, error) {
	return find(explicit, getenv, SearchPaths(), os.Stat, os.Lstat)
}

func find(explicit string, getenv func(string) string, search []string, stat, lstat func(string) (fs.FileInfo, error)) (string, error) {
	for _, p := range []struct{ path, from string }{{explicit, "--config"}, {getenv(EnvConfig), "$" + EnvConfig}} {
		if p.path == "" {
			continue
		}
		fi, err := stat(p.path)
		if err == nil && fi.IsDir() {
			err = ErrIsDir
		}
		if err != nil {
			return "", &FileError{From: p.from, Path: p.path, Err: err}
		}
		return p.path, nil
	}
	var skipped error // the permission error of ./gosftpd.toml
	for _, p := range search {
		fi, err := stat(p)
		switch {
		case err == nil && fi.IsDir():
			return "", &FileError{Path: p, Err: ErrIsDir}
		case err == nil:
			return p, nil
		case errors.Is(err, fs.ErrNotExist):
		case errors.Is(err, fs.ErrPermission) && !filepath.IsAbs(p):
			// Only a working directory that cannot be searched hides the
			// entry from lstat as well.
			if _, lerr := lstat(p); !errors.Is(lerr, fs.ErrPermission) {
				return "", &FileError{Path: p, Err: err}
			}
			skipped = err
		default:
			return "", &FileError{Path: p, Err: err}
		}
	}
	if skipped != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, skipped)
	}
	return "", ErrNotFound
}

// ReadListen returns server.listen of the file at path, read leniently for
// gosftpd healthcheck: only that key, without includes or validation and
// ignoring every other key, so that an edit a reload refused does not fail
// the check. It returns nil when the file does not set the key.
func ReadListen(path string) ([]string, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Server struct {
			Listen []string `toml:"listen"`
		} `toml:"server"`
	}
	if _, err := toml.Decode(string(data), &f); err != nil {
		return nil, decodeError(path, err)
	}
	return f.Server.Listen, nil
}

// ReadTrustedProxies returns server.trusted_proxies of the file at path,
// read leniently for gosftpd healthcheck and apart from server.listen (ADR
// 0011): a value of the wrong type or an entry that does not parse must
// not fail the check. It returns the entries that parse, and an error that
// names the others, or says why the key cannot be read at all: the file
// cannot be read or is not TOML, or the key is not a list.
func ReadTrustedProxies(path string) ([]netip.Prefix, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var f map[string]any
	if _, err := toml.Decode(string(data), &f); err != nil {
		return nil, decodeError(path, err)
	}
	srv, _ := f["server"].(map[string]any)
	v, ok := srv["trusted_proxies"]
	if !ok {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("not a list of addresses but %s", tomlKind(v))
	}
	var (
		prefixes []netip.Prefix
		errs     []error
	)
	for i, e := range list {
		s, ok := e.(string)
		if !ok {
			errs = append(errs, fmt.Errorf("entry %d is %s, not an address", i+1, tomlKind(e)))
			continue
		}
		p, err := ParseTrustedProxy(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d: %w", i+1, err))
			continue
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, errors.Join(errs...)
}

// tomlKind names the TOML type of a decoded value.
func tomlKind(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case int64, float64:
		return "a number"
	case bool:
		return "a boolean"
	case map[string]any:
		return "a table"
	case []any, []map[string]any:
		return "a list"
	}
	return "a date or time"
}
