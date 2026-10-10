// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cli

import "io/fs"

// chownLike does nothing where files have no Unix owner.
func chownLike(string, fs.FileInfo) {}
