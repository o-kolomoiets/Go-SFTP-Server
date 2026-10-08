// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"fmt"
	"strings"
)

// Perm is a set of permission flags a user has on a mount (ROADMAP §6.3).
type Perm uint16

// Permission flags.
const (
	PermList      Perm = 1 << iota // list directories, stat
	PermRead                       // download
	PermWrite                      // create new files
	PermOverwrite                  // change existing files, including truncation
	PermDelete                     // remove files
	PermRename                     // rename any file
	PermMkdir                      // create directories
	PermRmdir                      // remove empty directories
	PermSetstat                    // change times of any file

	PermNone Perm = 0
	PermAll       = PermList | PermRead | PermWrite | PermOverwrite | PermDelete | PermRename | PermMkdir | PermRmdir | PermSetstat
	// PermReadOnly is what a read-only mount leaves of any grant.
	PermReadOnly = PermList | PermRead
	// permModify is every flag that changes data.
	permModify = PermAll &^ PermReadOnly
)

var permNames = []struct {
	p    Perm
	name string
}{
	{PermList, "list"},
	{PermRead, "read"},
	{PermWrite, "write"},
	{PermOverwrite, "overwrite"},
	{PermDelete, "delete"},
	{PermRename, "rename"},
	{PermMkdir, "mkdir"},
	{PermRmdir, "rmdir"},
	{PermSetstat, "setstat"},
}

// Presets are named permission sets.
var presets = []struct {
	name string
	p    Perm
}{
	{"read", PermList | PermRead},
	{"upload", PermList | PermWrite | PermMkdir},
	{"readwrite", PermList | PermRead | PermWrite | PermOverwrite | PermRename | PermMkdir | PermSetstat},
	{"full", PermAll},
}

// ParsePerm parses a preset name ("read", "upload", "readwrite", "full") or a
// comma-separated list of flags ("list,write").
func ParsePerm(s string) (Perm, error) {
	s = strings.TrimSpace(s)
	for _, pr := range presets {
		if s == pr.name {
			return pr.p, nil
		}
	}
	var p Perm
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		found := false
		for _, n := range permNames {
			if f == n.name {
				p |= n.p
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown permission %q (presets: read, upload, readwrite, full; flags: %s)", f, PermAll.Flags())
		}
	}
	return p, nil
}

// Has reports whether p includes all flags in q.
func (p Perm) Has(q Perm) bool { return p&q == q }

// String returns the preset name if p equals one, else the flag list.
func (p Perm) String() string {
	for _, pr := range presets {
		if p == pr.p {
			return pr.name
		}
	}
	return p.Flags()
}

// Flags returns p as a comma-separated flag list.
func (p Perm) Flags() string {
	var parts []string
	for _, n := range permNames {
		if p&n.p != 0 {
			parts = append(parts, n.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}
