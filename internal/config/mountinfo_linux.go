// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strconv"
	"strings"
)

// readMountInfo parses /proc/self/mountinfo; nil if it cannot be read.
func readMountInfo() mountInfo {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	var mi mountInfo
	for line := range strings.SplitSeq(string(data), "\n") {
		// ID parent major:minor root mount-point options ...
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mi = append(mi, struct{ dev, root, point string }{f[2], unescapeMount(f[3]), unescapeMount(f[4])})
	}
	return mi
}

// unescapeMount decodes the octal escapes (\040 for a space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
