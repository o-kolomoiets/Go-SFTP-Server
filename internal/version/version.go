// SPDX-License-Identifier: Apache-2.0

// Package version reports build information about the running gosftpd binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Build metadata injected by the release pipeline with -ldflags, e.g.
//
//	-X github.com/o-kolomoiets/go-sftp-server/internal/version.Version=v0.1.0
//
// When they are empty (go install, go build), Get falls back to the
// information the Go toolchain embeds in the binary.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info describes a gosftpd build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build information of the running binary.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info = fromBuildInfo(info, bi)
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

// fromBuildInfo fills the fields that were not set at link time.
func fromBuildInfo(info Info, bi *debug.BuildInfo) Info {
	if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	if info.Commit != "" {
		return info
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}

// String formats the information for humans, e.g.
// "gosftpd v0.1.0 (commit 0123456789ab, 2026-10-07T12:00:00Z, go1.27.1 linux/amd64)".
func (i Info) String() string {
	details := make([]string, 0, 3)
	if i.Commit != "" {
		commit := i.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		if i.Modified {
			commit += "-dirty"
		}
		details = append(details, "commit "+commit)
	}
	if i.Date != "" {
		details = append(details, i.Date)
	}
	details = append(details, i.GoVersion+" "+i.Platform)
	return fmt.Sprintf("gosftpd %s (%s)", i.Version, strings.Join(details, ", "))
}
