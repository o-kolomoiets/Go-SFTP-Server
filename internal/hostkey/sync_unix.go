// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hostkey

import "os"

// SyncDir makes the links, renames and removals in dir durable, as far as
// the filesystem allows.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	_ = d.Sync() // some filesystems cannot sync a directory
	return nil
}
