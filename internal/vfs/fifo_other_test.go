// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package vfs

import "testing"

// mkfifo is a no-op where FIFOs do not exist.
func mkfifo(*testing.T, string) {}
