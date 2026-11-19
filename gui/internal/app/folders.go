// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// maxFolderName is the longest mount name gosftpd accepts.
const maxFolderName = 64

// windowsDeviceNames are refused as mount names on every platform, as
// gosftpd refuses them.
var windowsDeviceNames = []string{
	"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

// FolderName returns the name the folder at path is shared under: its
// base name made a mount name gosftpd accepts (letters, digits, ".", "_",
// "-" and spaces, starting with a letter or digit, at most 64 bytes), and
// unlike every name of taken, ignoring case. A name with nothing usable
// becomes "Folder". People see the name as a directory when more than one
// folder is shared.
func FolderName(path string, taken []string) string {
	base := sanitize(filepath.Base(filepath.Clean(path)))
	if base == "" {
		base = "Folder"
	}
	if device(base) {
		base = truncate("Folder "+base, maxFolderName)
	}
	name := base
	for n := 2; slices.ContainsFunc(taken, func(t string) bool { return strings.EqualFold(t, name) }); n++ {
		suffix := fmt.Sprintf(" %d", n)
		name = strings.TrimRight(truncate(base, maxFolderName-len(suffix)), " .") + suffix
	}
	return name
}

// sanitize keeps the characters a mount name may hold, writes "-" for a
// run of others, and trims what may not start or end a name.
func sanitize(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case alnum(r), r == '.', r == '_', r == '-', r == ' ':
			b.WriteRune(r)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimLeftFunc(b.String(), func(r rune) bool { return !alnum(r) })
	return strings.TrimRight(truncate(out, maxFolderName), " .-")
}

// alnum reports whether r is an ASCII letter or digit.
func alnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

// truncate cuts s to at most n bytes; s is ASCII.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// device reports whether gosftpd would refuse name as a Windows device
// name: its part before the first dot, without trailing spaces.
func device(name string) bool {
	base, _, _ := strings.Cut(name, ".")
	base = strings.TrimRight(base, " ")
	return slices.ContainsFunc(windowsDeviceNames, func(d string) bool { return strings.EqualFold(base, d) })
}
