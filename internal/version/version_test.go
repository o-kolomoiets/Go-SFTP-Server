// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	t.Parallel()

	vcs := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
		{Key: "vcs.time", Value: "2026-10-07T12:00:00Z"},
		{Key: "vcs.modified", Value: "true"},
	}

	tests := []struct {
		name string
		in   Info
		bi   debug.BuildInfo
		want Info
	}{
		{
			name: "go install of a tagged module",
			bi:   debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			want: Info{Version: "v0.1.0"},
		},
		{
			name: "local build uses VCS stamps",
			bi:   debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs},
			want: Info{Commit: vcs[0].Value, Date: vcs[1].Value, Modified: true},
		},
		{
			name: "link-time values win",
			in:   Info{Version: "v1.2.3", Commit: "abc", Date: "2026-01-01"},
			bi:   debug.BuildInfo{Main: debug.Module{Version: "v0.0.1"}, Settings: vcs},
			want: Info{Version: "v1.2.3", Commit: "abc", Date: "2026-01-01"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := fromBuildInfo(tt.in, &tt.bi); got != tt.want {
				t.Errorf("fromBuildInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	got := Info{
		Version:   "v0.1.0",
		Commit:    "0123456789abcdef",
		Modified:  true,
		Date:      "2026-10-07T12:00:00Z",
		GoVersion: "go1.27.1",
		Platform:  "linux/amd64",
	}.String()
	want := "gosftpd v0.1.0 (commit 0123456789ab-dirty, 2026-10-07T12:00:00Z, go1.27.1 linux/amd64)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	info := Get()
	if info.Version == "" || info.GoVersion == "" || !strings.Contains(info.Platform, "/") {
		t.Errorf("Get() returned incomplete info: %+v", info)
	}
}
