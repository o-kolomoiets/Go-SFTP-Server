// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package vfs

import "os"

// holdDir holds nothing where there is no Landlock.
func holdDir(*os.Root) (*os.File, uint64, uint64, error) { return nil, 0, 0, nil }
