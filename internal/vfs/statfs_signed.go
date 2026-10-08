// SPDX-License-Identifier: Apache-2.0

//go:build linux || freebsd

package vfs

// nonNegative converts a statfs counter, whose type differs by
// architecture, clamping negative values to 0.
func nonNegative[T ~int32 | ~int64 | ~uint32 | ~uint64](n T) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
