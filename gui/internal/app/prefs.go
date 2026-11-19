// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Prefs are the GUI's own settings, kept in <user config dir>/gosftpd-gui.conf,
// outside the state directory, which holds only what gosftpd names (ADR
// 0013, "The state directory").
type Prefs struct {
	// ActivityFrom is where the activity view begins in the audit log:
	// Clear activity hides what came before. ActivityLog names the file it
	// is an offset of (device and inode): a log rotated since is shown
	// from its start.
	ActivityFrom int64  `json:"activity_from,omitempty"`
	ActivityLog  string `json:"activity_log,omitempty"`
}

// DefaultPrefsPath is <user config dir>/gosftpd-gui.conf.
func DefaultPrefsPath() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "gosftpd-gui.conf"), nil
}

// LoadPrefs reads the preferences at path; none yet is no error.
func LoadPrefs(path string) (Prefs, error) {
	var p Prefs
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return Prefs{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// SavePrefs writes the preferences to path, mode 0600, through a
// temporary file and a rename.
func SavePrefs(path string, p Prefs) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gosftpd-gui.conf-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// fileID names the file at path by its device and inode, "" when it
// does not exist.
func fileID(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}
