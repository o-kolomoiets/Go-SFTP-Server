// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
)

// Errors returned by the VFS. Callers match them with errors.Is; the wrapped
// OS error (with paths relative to a mount) is only for server-side logs.
var (
	ErrDenied         = errors.New("permission denied")
	ErrExists         = errors.New("file already exists")
	ErrConflict       = errors.New("file exists and on_conflict=reject")
	ErrResumeDisabled = errors.New("resume is disabled")
	ErrImmutable      = errors.New("existing data is immutable")
	ErrBusy           = errors.New("file is being written by another upload")
	ErrTooLarge       = errors.New("file too large (max_file_size)")
	ErrNoSpace        = errors.New("not enough free space (min_free_space)")
	ErrUnsupported    = errors.New("operation not supported")
	ErrNotRegular     = errors.New("not a regular file")
	ErrIsDir          = errors.New("is a directory")
	ErrNotDir         = errors.New("not a directory")
	ErrNotEmpty       = errors.New("directory not empty")
	ErrInvalidPath    = errors.New("invalid path")

	// ErrHomeNotDir: a user's home is not a real directory (for example a
	// symlink planted in its place); the home mount is unavailable.
	ErrHomeNotDir = errors.New("home is not a directory")
	// ErrHomeMissing: a user's home does not exist and create is off.
	ErrHomeMissing = errors.New("home does not exist")
)

// osError classifies an error from os.Root into one of the VFS errors.
func osError(err error) error {
	if err == nil {
		return nil
	}
	var kind error
	// "Not empty" first: the syscall package also reports it as fs.ErrExist.
	switch {
	case isNotEmpty(err):
		kind = ErrNotEmpty
	case errors.Is(err, fs.ErrNotExist):
		kind = fs.ErrNotExist
	case errors.Is(err, fs.ErrExist):
		kind = ErrExists
	case errors.Is(err, fs.ErrPermission), isEscape(err), errors.Is(err, syscall.ELOOP):
		kind = ErrDenied
	case errors.Is(err, syscall.ENOTDIR):
		kind = ErrNotDir
	case errors.Is(err, syscall.EISDIR):
		kind = ErrIsDir
	default:
		return err
	}
	return fmt.Errorf("%w: %w", kind, err)
}

// isEscape reports whether os.Root refused a path that leaves the root. The
// standard library does not export this error, so match its text; a test
// pins the behaviour.
func isEscape(err error) bool {
	return strings.Contains(err.Error(), "path escapes from parent")
}
