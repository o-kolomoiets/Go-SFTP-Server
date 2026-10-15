// SPDX-License-Identifier: Apache-2.0

package sandbox

import "runtime/debug"

// coverDirOf returns where a build writes its coverage counters at exit:
// in a -cover build, the -test.gocoverdir flag of a test binary (flag),
// else $GOCOVERDIR (env); otherwise "". GOCOVERDIR alone never adds the
// rule: a binary built without -cover writes nothing.
func coverDirOf(settings []debug.BuildSetting, flag, env string) string {
	for _, s := range settings {
		if s.Key == "-cover" && s.Value == "true" {
			if flag != "" {
				return flag
			}
			return env
		}
	}
	return ""
}
