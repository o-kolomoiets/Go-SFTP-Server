// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd

package vfs

// fsid packs the two words of a filesystem ID into one number.
func fsid(val [2]int32) uint64 {
	return uint64(uint32(val[0]))<<32 | uint64(uint32(val[1])) //nolint:gosec // G115: bit reinterpretation is intended
}
