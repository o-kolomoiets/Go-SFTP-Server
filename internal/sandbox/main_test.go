// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"testing"
)

// TestMain dispatches the probe child, which Start starts from
// /proc/self/exe: the test binary here.
func TestMain(m *testing.M) {
	ProbeMain()
	helperMain()
	os.Exit(m.Run())
}
