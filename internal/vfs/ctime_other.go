// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !freebsd && !netbsd

package vfs

import "io/fs"

// ctime is unknown here. On Windows os.SameFile compares NTFS file IDs,
// which carry a sequence number, so a reused record does not match.
func ctime(fs.FileInfo) int64 { return 0 }
