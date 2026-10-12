// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
)

// TestMain dispatches the probe child, which the sandbox starts from
// /proc/self/exe (this test binary), and keeps Landlock out of the test
// process: a ruleset cannot be lifted. The tests that apply it run serve
// in a re-executed child, which puts sandbox.Start back.
func TestMain(m *testing.M) {
	sandbox.ProbeMain()
	startSandbox = noSandbox
	os.Exit(m.Run())
}

// noSandbox stands for sandbox.Start in the test process: it applies
// nothing.
func noSandbox(context.Context, sandbox.Options) (sandbox.Result, error) {
	return sandbox.Result{}, nil
}
