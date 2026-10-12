// SPDX-License-Identifier: Apache-2.0

package sdnotify

import (
	"strings"
	"testing"
)

func TestReloadStatus(t *testing.T) {
	t.Parallel()

	keys := func(n int) []string {
		var ks []string
		for i := range n {
			ks = append(ks, "mounts.m"+strings.Repeat("x", i)+".path")
		}
		return ks
	}
	for _, tt := range []struct {
		name    string
		ok      bool
		restart []string
		want    string
	}{
		{"ok", true, nil, "configuration reloaded"},
		{"failed", false, nil, "configuration reload failed, see the log"},
		{"failed with keys", false, []string{"server.listen"}, "configuration reload failed, see the log"},
		{"one key", true, []string{"server.listen"}, "configuration reloaded; restart needed for: server.listen"},
		{"two keys", true, []string{"server.listen", "metrics.listen"}, "configuration reloaded; restart needed for: server.listen, metrics.listen"},
		{
			"five keys", true, keys(5),
			"configuration reloaded; restart needed for: mounts.m.path, mounts.mx.path, mounts.mxx.path, mounts.mxxx.path, mounts.mxxxx.path",
		},
		{
			"six keys", true, keys(6),
			"configuration reloaded; restart needed for: mounts.m.path, mounts.mx.path, mounts.mxx.path, mounts.mxxx.path, mounts.mxxxx.path and 1 more; see the log",
		},
		{
			"nine keys", true, keys(9),
			"configuration reloaded; restart needed for: mounts.m.path, mounts.mx.path, mounts.mxx.path, mounts.mxxx.path, mounts.mxxxx.path and 4 more; see the log",
		},
	} {
		if got := ReloadStatus(tt.ok, tt.restart); got != tt.want {
			t.Errorf("%s: ReloadStatus = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// A status names at most five keys, so that READY=1 always fits systemd's
// 4096-byte limit: keys are at most 64-character mount names.
func TestReloadStatusFits(t *testing.T) {
	t.Parallel()

	long := make([]string, 1000)
	for i := range long {
		long[i] = `mounts."` + strings.Repeat("n", 64) + `".read_only`
	}
	if msg := "READY=1\nSTATUS=" + ReloadStatus(true, long); len(msg) > 4096 || strings.Contains(msg[8:], "\n") {
		t.Errorf("%d bytes: %q", len(msg), msg)
	}
}
