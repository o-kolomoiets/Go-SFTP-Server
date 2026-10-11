// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// checkOwner is a no-op where Unix permissions do not exist; access is
// governed by ACLs there.
func checkOwner(string, fs.FileInfo) error { return nil }

func worldReadable(fs.FileInfo) bool { return false }

func sameDevice(fs.FileInfo, fs.FileInfo) (same, known bool) { return false, false }

func checkSecretMode(string, fs.FileInfo) error { return nil }

// executable reports whether Windows runs the file as a program: there
// are no execute bits, so its extension decides, as exec.LookPath does.
func executable(fi fs.FileInfo) bool {
	exts := os.Getenv("PATHEXT")
	if exts == "" {
		exts = ".com;.exe;.bat;.cmd"
	}
	ext := strings.ToLower(filepath.Ext(fi.Name()))
	for e := range strings.SplitSeq(strings.ToLower(exts), ";") {
		if e != "" && e == ext {
			return true
		}
	}
	return false
}
