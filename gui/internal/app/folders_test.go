// SPDX-License-Identifier: Apache-2.0

package app

import (
	"regexp"
	"strings"
	"testing"
)

// mountName is gosftpd's rule for a mount name (vfs.ValidMountName).
var mountName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)

func TestFolderName(t *testing.T) {
	long := strings.Repeat("a", 80)
	for _, tc := range []struct {
		path  string
		taken []string
		want  string
	}{
		{"/home/alex/Inbox", nil, "Inbox"},
		{"/home/alex/Inbox/", nil, "Inbox"},
		{"/home/alex/Reports 2026", nil, "Reports 2026"},
		{"/home/alex/inbox", []string{"Inbox"}, "inbox 2"},
		{"/data/Inbox", []string{"Inbox", "Inbox 2"}, "Inbox 3"},
		{"/home/alex/Входящие", nil, "Folder"},
		{"/home/alex/Мои файлы", []string{"Folder"}, "Folder 2"},
		{"/home/alex/отчёты-2026", nil, "2026"},
		{"/home/alex/.config", nil, "config"},
		{"/home/alex/my+files", nil, "my-files"},
		{"/home/alex/a+++b", nil, "a-b"},
		{"/home/alex/files.", nil, "files"},
		{"/media/con", nil, "Folder con"},
		{"/media/COM1.txt", nil, "Folder COM1.txt"},
		{"/", nil, "Folder"},
		{"/data/" + long, nil, strings.Repeat("a", 64)},
		{"/data/" + long, []string{strings.Repeat("a", 64)}, strings.Repeat("a", 62) + " 2"},
	} {
		got := FolderName(tc.path, tc.taken)
		if got != tc.want {
			t.Errorf("FolderName(%q, %q) = %q, want %q", tc.path, tc.taken, got, tc.want)
		}
		if !mountName.MatchString(got) || device(got) {
			t.Errorf("FolderName(%q) = %q: not a mount name gosftpd accepts", tc.path, got)
		}
	}
}

func FuzzFolderName(f *testing.F) {
	for _, s := range []string{"/home/alex/Inbox", "/", "Входящие", "con", "a.b.c", " x "} {
		f.Add(s, "Inbox")
	}
	f.Fuzz(func(t *testing.T, path, taken string) {
		got := FolderName(path, []string{taken})
		if !mountName.MatchString(got) || device(got) || strings.EqualFold(got, taken) {
			t.Fatalf("FolderName(%q, %q) = %q", path, taken, got)
		}
	})
}
