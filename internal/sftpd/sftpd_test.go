// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

func TestToStatus(t *testing.T) {
	t.Parallel()

	hostErr := &fs.PathError{Op: "openat", Path: "/srv/secret/path", Err: fs.ErrPermission}
	tests := []struct {
		err    error
		code   error
		result string
	}{
		{fmt.Errorf("%w: %w", vfs.ErrDenied, hostErr), sftp.ErrSSHFxPermissionDenied, "denied"},
		{fmt.Errorf("x: %w", fs.ErrNotExist), sftp.ErrSSHFxNoSuchFile, "not_found"},
		{vfs.ErrUnsupported, sftp.ErrSSHFxOpUnsupported, "denied"},
		{vfs.ErrConflict, sftp.ErrSSHFxFailure, "denied"},
		{vfs.ErrInvalidPath, sftp.ErrSSHFxBadMessage, "error"},
		{errors.New("disk on fire at /srv/data"), sftp.ErrSSHFxFailure, "error"},
	}
	for _, tt := range tests {
		result, st := toStatus(tt.err)
		if result != tt.result || !errors.Is(st, tt.code) {
			t.Errorf("toStatus(%v) = %s, %v; want %s, %v", tt.err, result, st, tt.result, tt.code)
		}
		if msg := st.Error(); containsAny(msg, "/srv", "openat", "fire") {
			t.Errorf("client message %q exposes the internal error", msg)
		}
	}
	if result, st := toStatus(nil); result != "ok" || st != nil {
		t.Errorf("toStatus(nil) = %s, %v", result, st)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

func TestFlagString(t *testing.T) {
	t.Parallel()

	if got := flagString(vfs.OpenFlags{Write: true, Creat: true, Trunc: true}); got != "WRITE+CREAT+TRUNC" {
		t.Errorf("flagString = %q", got)
	}
}
