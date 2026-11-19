// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Layout is the state directory: the files of the gosftpd the GUI runs
// (ADR 0013, "The state directory"). It holds only what gosftpd names, so
// that gosftpd treats it as a directory of its own and gives no Landlock
// warning: the configuration, users.d/, the host key and its .pub, and the
// audit log in a directory of its own. The GUI's own files go elsewhere.
type Layout struct {
	Dir string
}

// DefaultLayout is <user config dir>/gosftpd-gui: ~/.config/gosftpd-gui on
// Linux, ~/Library/Application Support/gosftpd-gui on macOS.
func DefaultLayout() (Layout, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return Layout{}, err
	}
	return Layout{Dir: filepath.Join(d, "gosftpd-gui")}, nil
}

// Config is the configuration file.
func (l Layout) Config() string { return filepath.Join(l.Dir, "config.toml") }

// UsersDir is the directory of the people's files, users.d/.
func (l Layout) UsersDir() string { return filepath.Join(l.Dir, "users.d") }

// AuditLog is the audit log, in a directory of its own.
func (l Layout) AuditLog() string { return filepath.Join(l.Dir, "audit", "audit.jsonl") }

// Ensure creates the state directory with mode 0700, or gives an existing
// one that mode: init does not create the directory of its --out.
func (l Layout) Ensure() error {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(l.Dir, 0o700) //nolint:gosec // G302: a directory needs the x bit
}

// Exists reports whether the configuration was written: whether the GUI
// has shared a folder before.
func (l Layout) Exists() bool {
	_, err := os.Stat(l.Config())
	return err == nil
}

// gosftpdCandidates are the places of the gosftpd shipped with the GUI,
// in order: never PATH (ADR 0013, "Which gosftpd"). exe is the GUI's own
// executable, its links resolved.
func gosftpdCandidates(goos, exe string) []string {
	switch goos {
	case "darwin":
		// gosftpd-gui.app/Contents/MacOS/, next to the GUI.
		return []string{filepath.Join(filepath.Dir(exe), "gosftpd")}
	default:
		// The Linux packages: /usr/libexec on Debian, Fedora and EL, and
		// /usr/lib on Arch. Not next to /usr/bin/gosftpd-gui: that would
		// be the server package's gosftpd, which may be another version.
		return []string{"/usr/libexec/gosftpd-gui/gosftpd", "/usr/lib/gosftpd-gui/gosftpd"}
	}
}

// ErrNoGosftpd means that the gosftpd shipped with the GUI is missing.
var ErrNoGosftpd = errors.New("gosftpd is not where gosftpd-gui expects it")

// FindGosftpd returns the gosftpd shipped with the GUI. A development
// build passes its own (--gosftpd PATH) instead of calling this.
func FindGosftpd() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return findGosftpd(gosftpdCandidates(runtime.GOOS, exe))
}

func findGosftpd(candidates []string) (string, error) {
	for _, p := range candidates {
		if executable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: looked for %q", ErrNoGosftpd, candidates)
}

// executable reports whether p is a regular file that someone may run.
func executable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// RuntimeDir is a directory of the user's for files that live while the
// GUI runs: its lock and the pid of its gosftpd. It is $XDG_RUNTIME_DIR
// where set, else a directory of the user's own in the temporary
// directory, which RuntimeDir creates with mode 0700 and checks: a
// directory that someone else made there in advance is refused.
func RuntimeDir() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
		return d, nil
	}
	d := filepath.Join(os.TempDir(), fmt.Sprintf("gosftpd-gui-%d", os.Getuid()))
	if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(d)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || !ownedByUs(fi) {
		return "", fmt.Errorf("%s is not a directory of this user's with mode 0700", d)
	}
	return d, nil
}
