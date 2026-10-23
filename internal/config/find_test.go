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
// relative ./gosftpd.toml, and a directory is never used.
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

	for _, tt := range []struct {
		name     string
		explicit string
		env      string
		files    map[string]any // fakeInfo or error; any other path does not exist
		want     string
		wantErr  error  // matched with errors.Is
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
		{name: "local denied and nothing else", files: map[string]any{LocalFile: denied(LocalFile)}, wantErr: ErrNotFound},
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
			name: "etc not a directory stays an error", files: map[string]any{etc: &fs.PathError{Op: "stat", Path: etc, Err: syscall.ENOTDIR}, user: file},
			wantErr: syscall.ENOTDIR,
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
			stat := func(p string) (fs.FileInfo, error) {
				switch v := tt.files[p].(type) {
				case fakeInfo:
					return v, nil
				case error:
					return nil, v
				}
				return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
			}
			got, err := find(tt.explicit, getenv, search, stat)
			if tt.wantErr == nil {
				if err != nil || got != tt.want {
					t.Fatalf("find = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) || got != "" {
				t.Fatalf("find = %q, %v; want %v", got, err, tt.wantErr)
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
	if p, err := find("", noEnv, []string{LocalFile, next}, os.Stat); err != nil || p != next {
		t.Errorf("search = %q, %v; want %s", p, err, next)
	}
	if _, err := find("", noEnv, []string{LocalFile}, os.Stat); !errors.Is(err, ErrNotFound) {
		t.Errorf("search of ./%s alone: %v; want ErrNotFound", LocalFile, err)
	}
	if _, err := find(LocalFile, noEnv, []string{next}, os.Stat); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("--config %s: %v; want a permission error", LocalFile, err)
	}
}
