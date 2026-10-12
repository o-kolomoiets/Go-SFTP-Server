// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !freebsd

package config

// statfsReadOnly cannot tell a read-only file system here, so there is no
// warning about one.
func statfsReadOnly(string) (bool, error) { return false, nil }
