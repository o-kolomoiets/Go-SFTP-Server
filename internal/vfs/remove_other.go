// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package vfs

import "os"

// removeEntry removes rel; without unlinkat the type is checked by the
// caller only.
func removeEntry(root *os.Root, rel string, _ bool) error { return root.Remove(rel) }
