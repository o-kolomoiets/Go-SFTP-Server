// SPDX-License-Identifier: Apache-2.0

package config

import "golang.org/x/sys/unix"

// statfsReadOnly reports whether path lies on a file system mounted
// read-only, also through a read-only bind mount (systemd's
// ProtectSystem=strict outside ReadWritePaths=).
func statfsReadOnly(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}
