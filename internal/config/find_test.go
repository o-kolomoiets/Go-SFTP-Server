// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// fakeInfo is the result of a fake stat: a file or a directory.
type fakeInfo struct{ dir bool }

func (fakeInfo) Name() string       { return "" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() fs.FileMode  { return 0 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool      { return i.dir }
func (fakeInfo) Sys() any           { return nil }

// TestFindTable covers the order of the sources and what each kind of
// stat result does: --config and $GOSFTPD_CONFIG are strict, a missing
// search path is skipped, a permission error is skipped only on the
// relative ./gosftpd.toml and only when lstat fails with one too (the
// working directory cannot be searched), and a directory is never used.
func TestFindTable(t *testing.T) {
	t.Parallel()

	base := t.TempDir() // absolute on every system
	etc := filepath.Join(base, "etc", "config.toml")
	user := filepath.Join(base, "user", "config.toml")
	search := []string{LocalFile, etc, user}
	explicit := filepath.Join(base, "explicit.toml")
	env := filepath.Join(base, "env.toml")

	file, dir := fakeInfo{}, fakeInfo{dir: true}
	denied := func(p string) error { return &fs.PathError{Op: "stat", Path: p, Err: syscall.EACCES} }
	notPermitted := func(p string) error { return &fs.PathError{Op: "stat", Path: p, Err: syscall.EPERM} }
	// A stat through a file fails with ENOTDIR, which stops the search. On
	// Windows ENOTDIR is ERROR_PATH_NOT_FOUND, a missing file, so the case
	// uses another error that is neither a missing file nor a permission
	// error.
	var notDir error = syscall.ENOTDIR
	if runtime.GOOS == "windows" {
		notDir = syscall.EIO
	}

	for _, tt := range []struct {
		name     string
		explicit string
		env      string
		files    map[string]any // fakeInfo or error; any other path does not exist
		lstat    map[string]any // lstat's result where it differs from stat's
		want     string
		wantErr  error  // matched with errors.Is
		wantAlso error  // matched with errors.Is too
		wantMsg  string // the whole message
	}{
		{name: "explicit", explicit: explicit, env: env, files: map[string]any{explicit: file, env: file, LocalFile: file}, want: explicit},
		{
			name: "explicit missing", explicit: explicit, files: map[string]any{LocalFile: file},
			wantErr: fs.ErrNotExist, wantMsg: "--config: " + explicit + " does not exist",
		},
		{
			name: "explicit directory", explicit: explicit, files: map[string]any{explicit: dir},
			wantErr: ErrIsDir, wantMsg: "--config: " + explicit + " is a directory",
		},
		{
			name: "explicit denied stays an error", explicit: explicit, files: map[string]any{explicit: denied(explicit), LocalFile: file},
			wantErr: fs.ErrPermission, wantMsg: "--config: stat " + explicit + ": permission denied",
		},
		{
			name: "explicit relative and denied stays an error", explicit: LocalFile, files: map[string]any{LocalFile: denied(LocalFile), etc: file},
			wantErr: fs.ErrPermission,
		},
		{name: "env", env: env, files: map[string]any{env: file, LocalFile: file}, want: env},
		{
			name: "env missing", env: env, files: map[string]any{LocalFile: file},
			wantErr: fs.ErrNotExist, wantMsg: "$" + EnvConfig + ": " + env + " does not exist",
		},
		{
			name: "env directory", env: env, files: map[string]any{env: dir},
			wantErr: ErrIsDir, wantMsg: "$" + EnvConfig + ": " + env + " is a directory",
		},
		{
			name: "env denied stays an error", env: env, files: map[string]any{env: notPermitted(env)},
			wantErr: fs.ErrPermission,
		},
		{name: "local first", files: map[string]any{LocalFile: file, etc: file}, want: LocalFile},
		{name: "local missing", files: map[string]any{etc: file, user: file}, want: etc},
		{name: "local EACCES skipped", files: map[string]any{LocalFile: denied(LocalFile), etc: file}, want: etc},
		{name: "local EPERM skipped", files: map[string]any{LocalFile: notPermitted(LocalFile), user: file}, want: user},
		{
			name: "local denied and nothing else", files: map[string]any{LocalFile: denied(LocalFile)},
			wantErr: ErrNotFound, wantAlso: fs.ErrPermission, wantMsg: ErrNotFound.Error() + ": stat " + LocalFile + ": permission denied",
		},
		// A symlink in a readable working directory whose target the user
		// cannot reach: lstat sees it, so it is not skipped.
		{
			name: "local EACCES with a visible entry stays an error", files: map[string]any{LocalFile: denied(LocalFile), etc: file},
			lstat: map[string]any{LocalFile: file}, wantErr: fs.ErrPermission, wantMsg: "stat " + LocalFile + ": permission denied",
		},
		{
			name: "local EPERM with a visible entry stays an error", files: map[string]any{LocalFile: notPermitted(LocalFile), user: file},
			lstat: map[string]any{LocalFile: file}, wantErr: fs.ErrPermission,
		},
		{
			name: "local EACCES, lstat finds nothing, stays an error", files: map[string]any{LocalFile: denied(LocalFile), etc: file},
			lstat: map[string]any{LocalFile: &fs.PathError{Op: "lstat", Path: LocalFile, Err: fs.ErrNotExist}}, wantErr: fs.ErrPermission,
		},
		{
			name: "local directory", files: map[string]any{LocalFile: dir, etc: file},
			wantErr: ErrIsDir, wantMsg: LocalFile + " is a directory",
		},
		{
			name: "etc denied stays an error", files: map[string]any{etc: denied(etc), user: file},
			wantErr: fs.ErrPermission, wantMsg: "stat " + etc + ": permission denied",
		},
		{
			name: "user dir EPERM stays an error", files: map[string]any{user: notPermitted(user)},
			wantErr: fs.ErrPermission,
		},
		{
			name: "etc directory", files: map[string]any{etc: dir, user: file},
			wantErr: ErrIsDir, wantMsg: etc + " is a directory",
		},
		{
			name: "etc not a directory stays an error", files: map[string]any{etc: &fs.PathError{Op: "stat", Path: etc, Err: notDir}, user: file},
			wantErr: notDir,
		},
		{name: "nothing", wantErr: ErrNotFound, wantMsg: ErrNotFound.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getenv := func(k string) string {
				if k == EnvConfig {
					return tt.env
				}
				return ""
			}
			result := func(files map[string]any, p string) (fs.FileInfo, error) {
				switch v := files[p].(type) {
				case fakeInfo:
					return v, nil
				case error:
					return nil, v
				}
				return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
			}
			stat := func(p string) (fs.FileInfo, error) { return result(tt.files, p) }
			lstat := func(p string) (fs.FileInfo, error) {
				if _, ok := tt.lstat[p]; ok {
					return result(tt.lstat, p)
				}
				return result(tt.files, p)
			}
			got, err := find(tt.explicit, getenv, search, stat, lstat)
			if tt.wantErr == nil {
				if err != nil || got != tt.want {
					t.Fatalf("find = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) || got != "" {
				t.Fatalf("find = %q, %v; want %v", got, err, tt.wantErr)
			}
			if tt.wantAlso != nil && !errors.Is(err, tt.wantAlso) {
				t.Errorf("%v is not %v", err, tt.wantAlso)
			}
			if tt.wantMsg != "" && err.Error() != tt.wantMsg {
				t.Errorf("message %q, want %q", err, tt.wantMsg)
			}
			if _, ok := errors.AsType[*FileError](err); ok == errors.Is(err, ErrNotFound) {
				t.Errorf("%v: *FileError is %v", err, ok)
			}
		})
	}
}

// From a working directory the user cannot read (sudo -u gosftpd from
// /root), the search goes on past ./gosftpd.toml; --config with a relative
// path there stays an error. The table test fakes the errors; this one
// gets them from the system.
func TestFindUnreadableWorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory this user cannot search")
	}
	dir := t.TempDir()
	cwd := filepath.Join(dir, "cwd")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(next, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if err := os.Chmod(cwd, 0o200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cwd, 0o700) })
	if _, err := os.Stat(LocalFile); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("stat in an unsearchable directory: %v", err)
	}

	noEnv := func(string) string { return "" }
	if p, err := find("", noEnv, []string{LocalFile, next}, os.Stat, os.Lstat); err != nil || p != next {
		t.Errorf("search = %q, %v; want %s", p, err, next)
	}
	if _, err := find("", noEnv, []string{LocalFile}, os.Stat, os.Lstat); !errors.Is(err, ErrNotFound) || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("search of ./%s alone: %v; want ErrNotFound with the permission error", LocalFile, err)
	}
	if _, err := find(LocalFile, noEnv, []string{next}, os.Stat, os.Lstat); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("--config %s: %v; want a permission error", LocalFile, err)
	}
}

// A ./gosftpd.toml in a readable working directory that is a symlink to a
// target the user cannot reach is an error: the search must not go on to
// another file without a word.
func TestFindUnreachableSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a symlink and a directory this user cannot search")
	}
	dir := t.TempDir()
	cwd, locked := filepath.Join(dir, "cwd"), filepath.Join(dir, "locked")
	for _, d := range []string{cwd, locked} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(locked, "config.toml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(next, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(locked, "config.toml"), filepath.Join(cwd, LocalFile)); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.Stat(LocalFile); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("stat through a symlink into an unsearchable directory: %v", err)
	}

	p, err := find("", func(string) string { return "" }, []string{LocalFile, next}, os.Stat, os.Lstat)
	if fe, ok := errors.AsType[*FileError](err); !ok || fe.Path != LocalFile || !errors.Is(err, fs.ErrPermission) {
		t.Errorf("search = %q, %v; want the permission error of %s", p, err, LocalFile)
	}
}
