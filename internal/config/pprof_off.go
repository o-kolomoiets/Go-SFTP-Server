// SPDX-License-Identifier: Apache-2.0

//go:build !pprof

package config

// pprofBuilt reports whether this binary serves /debug/pprof (internal/obs
// has the same build tag).
const pprofBuilt = false
