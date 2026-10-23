// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"strings"
	"testing"
)

// TestEphemeralReadyAfterDetails: serve --ephemeral prints its line just
// before it reports ready.
func TestEphemeralReadyAfterDetails(t *testing.T) {
	isolate(t)
	ephemeralTemp(t)
	next := notifySocket(t)
	ts := startServe(t, "--ephemeral")
	next("READY=1")
	if out := ts.stdout.String(); !strings.HasSuffix(out, "}\n") {
		t.Errorf("READY=1 before the details; stdout %q", out)
	}
	decodeDetails(t, ts.stdout.String())
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
}
