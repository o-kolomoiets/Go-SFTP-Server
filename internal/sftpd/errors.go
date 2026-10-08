// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"errors"
	"io/fs"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// status is an SFTP status sent to the client. pkg/sftp finds the code via
// errors.As and sends Error() as the message, so clients get a fixed text
// and never a host path.
type status struct {
	code error // one of sftp.ErrSSHFx*
	msg  string
}

func (s status) Error() string { return s.msg }
func (s status) Unwrap() error { return s.code }

var (
	errTooManyHandles    = errors.New("too many open handles")
	errAuditUnavailable  = errors.New("audit log unavailable")
	errBadAttributes     = errors.New("malformed attributes")
	errUnsupportedMethod = errors.New("unsupported request")
)

// toStatus maps an internal error to its audit result class and a
// client-safe SFTP status.
func toStatus(err error) (string, error) {
	if err == nil {
		return "ok", nil
	}
	for _, m := range statusMap {
		if errors.Is(err, m.err) {
			return m.result, status{m.code, m.msg}
		}
	}
	return "error", status{sftp.ErrSSHFxFailure, "operation failed"}
}

var statusMap = []struct {
	err    error
	code   error
	msg    string
	result string
}{
	{fs.ErrNotExist, sftp.ErrSSHFxNoSuchFile, "no such file", "not_found"},
	{vfs.ErrDenied, sftp.ErrSSHFxPermissionDenied, "permission denied", "denied"},
	{fs.ErrPermission, sftp.ErrSSHFxPermissionDenied, "permission denied", "denied"},
	{vfs.ErrUnsupported, sftp.ErrSSHFxOpUnsupported, "operation unsupported", "denied"},
	{errUnsupportedMethod, sftp.ErrSSHFxOpUnsupported, "operation unsupported", "denied"},
	{vfs.ErrConflict, sftp.ErrSSHFxFailure, "file exists (on_conflict=reject)", "denied"},
	{vfs.ErrExists, sftp.ErrSSHFxFailure, "file already exists", "error"},
	{vfs.ErrImmutable, sftp.ErrSSHFxPermissionDenied, "existing data is immutable", "denied"},
	{vfs.ErrResumeDisabled, sftp.ErrSSHFxFailure, "resume is disabled", "denied"},
	{vfs.ErrIsDir, sftp.ErrSSHFxFailure, "is a directory", "error"},
	{vfs.ErrNotDir, sftp.ErrSSHFxFailure, "not a directory", "error"},
	{vfs.ErrNotEmpty, sftp.ErrSSHFxFailure, "directory not empty", "error"},
	{vfs.ErrNotRegular, sftp.ErrSSHFxFailure, "not a regular file", "denied"},
	{vfs.ErrInvalidPath, sftp.ErrSSHFxBadMessage, "invalid path", "error"},
	{errBadAttributes, sftp.ErrSSHFxBadMessage, "malformed attributes", "error"},
	{errTooManyHandles, sftp.ErrSSHFxFailure, "too many open handles", "error"},
	{errAuditUnavailable, sftp.ErrSSHFxFailure, "audit log unavailable", "error"},
}
