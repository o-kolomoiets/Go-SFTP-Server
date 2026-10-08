// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !freebsd

package vfs

import "os"

// StatFSSupported reports whether StatFS works on this platform.
const StatFSSupported = false

func statfs(*os.File) (*StatFS, error) { return nil, ErrUnsupported }
