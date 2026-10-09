// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package config

// readMountInfo is nil where /proc/self/mountinfo does not exist: bind
// mounts are not recognized there.
func readMountInfo() mountInfo { return nil }
