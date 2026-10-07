// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package vfs

import (
	"errors"
	"syscall"
)

// isNotEmpty reports a "directory not empty" error. ENOTEMPTY also matches
// fs.ErrExist in the syscall package.
func isNotEmpty(err error) bool { return errors.Is(err, syscall.ENOTEMPTY) }
