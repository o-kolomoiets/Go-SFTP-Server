// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

import "io/fs"

// checkOwner is a no-op where Unix permissions do not exist; access is
// governed by ACLs there.
func checkOwner(string, fs.FileInfo) error { return nil }

func worldReadable(fs.FileInfo) bool { return false }

func sameDevice(fs.FileInfo, fs.FileInfo) (same, known bool) { return false, false }
