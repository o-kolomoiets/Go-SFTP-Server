// SPDX-License-Identifier: Apache-2.0

package config

import _ "embed"

var (
	//go:embed example.toml
	exampleMinimal []byte
	//go:embed example-full.toml
	exampleFull []byte
)

// Example returns the minimal working configuration (gosftpd config
// example) or, with full set, the reference of every key (--full).
func Example(full bool) []byte {
	if full {
		return exampleFull
	}
	return exampleMinimal
}
