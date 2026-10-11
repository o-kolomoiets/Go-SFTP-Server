// SPDX-License-Identifier: Apache-2.0

//go:build pprof

package obs

import (
	"net/http"
	"net/http/pprof"
)

// PprofBuilt reports whether this binary contains /debug/pprof (built
// with -tags pprof).
const PprofBuilt = true

// servePprof serves the profiles; /debug/pprof/cmdline is not served, as
// the command line holds host paths.
func servePprof(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/debug/pprof/profile":
		pprof.Profile(w, r)
	case "/debug/pprof/trace":
		pprof.Trace(w, r)
	case "/debug/pprof/symbol":
		pprof.Symbol(w, r)
	case "/debug/pprof/cmdline":
		http.NotFound(w, r)
	default:
		pprof.Index(w, r) // the index and the named profiles
	}
}
