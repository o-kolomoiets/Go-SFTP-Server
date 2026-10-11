// SPDX-License-Identifier: Apache-2.0

//go:build !pprof

package obs

import "net/http"

// PprofBuilt reports whether this binary contains /debug/pprof (built
// with -tags pprof).
const PprofBuilt = false

func servePprof(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }
