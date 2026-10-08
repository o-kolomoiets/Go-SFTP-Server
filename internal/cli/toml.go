// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"regexp"
	"strings"
)

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

var bareKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// tomlKey returns k as a bare key if possible, else quoted.
func tomlKey(k string) string {
	if bareKeyRE.MatchString(k) {
		return k
	}
	return tomlString(k)
}

// tomlStrings formats a TOML array of strings, one per line if long.
func tomlStrings(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = tomlString(s)
	}
	one := "[" + strings.Join(quoted, ", ") + "]"
	if len(one) <= 80 {
		return one
	}
	return "[\n  " + strings.Join(quoted, ",\n  ") + ",\n]"
}
