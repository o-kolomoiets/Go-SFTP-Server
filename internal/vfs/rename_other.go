// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package vfs

import "os"

func renameNoReplace(*os.Root, string, string) error { return errNoAtomicRename }
