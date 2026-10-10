// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cli

import "io/fs"

// chownLike does nothing where files have no Unix owner.
func chownLike(string, fs.FileInfo) {}

// keyOwner returns nothing to do where files have no Unix owner.
func keyOwner(string) (func(string) error, error) { return nil, nil }
