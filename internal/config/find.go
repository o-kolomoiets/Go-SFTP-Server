// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
// explicit or environment path must exist.
func Find(explicit string, getenv func(string) string) (string, error) {
	for _, p := range []struct{ path, from string }{{explicit, "--config"}, {getenv(EnvConfig), "$" + EnvConfig}} {
		if p.path == "" {
			continue
		}
		if _, err := os.Stat(p.path); err != nil {
			return "", fmt.Errorf("%s: %w", p.from, err)
		}
		return p.path, nil
	}
	for _, p := range SearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return "", ErrNotFound
}
