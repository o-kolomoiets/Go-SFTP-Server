// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package vfs

import "testing"

// checkHeld: nothing is held where there is no Landlock.
func checkHeld(t *testing.T, h HeldDir, _ string) {
	t.Helper()
	if h.FD != -1 {
		t.Errorf("%s: descriptor %d", h.Mount, h.FD)
	}
}
