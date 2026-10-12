// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"strconv"
	"syscall"
	"testing"
)

// TestClassify: Landlock is used only when the child exits 0 with all four
// results; ENOSYS or EOPNOTSUPP from its ABI query means unavailable, any
// other end blocked.
func TestClassify(t *testing.T) {
	t.Parallel()
	errno := func(e syscall.Errno) string { return "errno " + strconv.Itoa(int(e)) }
	for _, tc := range []struct {
		name   string
		r      probeResult
		status string // "" for usable
		reason string
	}{
		{"all four", probeResult{output: probeOK}, "", ""},
		{"all four, CRLF and noise", probeResult{output: "noise\r\nabi 2\r\nruleset ok\r\nrule ok\r\nrestrict ok\r\n"}, "", ""},
		{"ENOSYS", probeResult{output: "abi " + errno(syscall.ENOSYS)}, StatusUnavailable, reasonNoLandlock},
		{"EOPNOTSUPP", probeResult{output: "abi " + errno(syscall.EOPNOTSUPP)}, StatusUnavailable, reasonDisabled},
		{"EPERM", probeResult{output: "abi " + errno(syscall.EPERM)}, StatusBlocked, reasonBlocked},
		{"EACCES from SystemCallErrorNumber", probeResult{output: "abi " + errno(syscall.EACCES)}, StatusBlocked, reasonBlocked},
		{"ENOSYS from a later call", probeResult{output: "abi 7\nruleset " + errno(syscall.ENOSYS)}, StatusBlocked, reasonBlocked},
		{"the rule refused", probeResult{output: "abi 7\nruleset ok\nrule " + errno(syscall.EPERM)}, StatusBlocked, reasonBlocked},
		{"restrict missing", probeResult{output: "abi 7\nruleset ok\nrule ok\n"}, StatusBlocked, reasonBlocked},
		{"ABI 0", probeResult{output: "abi 0\nruleset ok\nrule ok\nrestrict ok\n"}, StatusBlocked, reasonBlocked},
		{"setup refused", probeResult{output: "setup " + errno(syscall.EPERM)}, StatusBlocked, reasonBlocked},
		{"no output", probeResult{}, StatusBlocked, reasonBlocked},
		{"killed", probeResult{output: probeOK[:6], exitCode: -1, signal: "bad system call"}, StatusBlocked, reasonKilled},
		{"exit status 2 (a trap)", probeResult{exitCode: 2}, StatusBlocked, reasonKilled},
		{"all four, but exit status 1", probeResult{output: probeOK, exitCode: 1}, StatusBlocked, reasonKilled},
		{"time limit", probeResult{output: "abi 7\n", timedOut: true, exitCode: -1}, StatusBlocked, reasonHung},
	} {
		s, err := classify(tc.r)
		switch {
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.status == "" && s != nil:
			t.Errorf("%s: %+v, want usable", tc.name, *s)
		case tc.status != "" && (s == nil || s.status != tc.status || s.reason != tc.reason):
			t.Errorf("%s: %+v, want %s: %s", tc.name, s, tc.status, tc.reason)
		case s != nil && (s.status == StatusBlocked) != (s.hint == seccompHint):
			t.Errorf("%s: hint %q", tc.name, s.hint)
		}
	}
	if s, err := classify(probeResult{err: errors.New("exec: no such file")}); s != nil || err == nil {
		t.Errorf("a child that cannot start: %v, %v", s, err)
	}
}
