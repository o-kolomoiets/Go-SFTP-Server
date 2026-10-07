// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isNotEmpty reports a "directory not empty" error. Windows reports
// ERROR_DIR_NOT_EMPTY, which the syscall package also maps to fs.ErrExist.
func isNotEmpty(err error) bool { return errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) }
