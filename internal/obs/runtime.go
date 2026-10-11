// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"
)

// processStart is when the process started, as far as gosftpd can tell
// without /proc/<pid>/stat, which the systemd sandbox hides.
var processStart = time.Now()

// registerRuntime adds the Go runtime and process metrics, with the names
// client_golang uses, so that existing dashboards work. None of them stops
// the world (no runtime.ReadMemStats).
func registerRuntime(r *Registry) {
	newInfo(r, "go_info", "Information about the Go environment.", map[string]string{"version": runtime.Version()})
	newFunc(r, typeGauge, "go_goroutines", "Number of goroutines that currently exist.", func() (float64, bool) {
		return float64(runtime.NumGoroutine()), true
	})
	newFunc(r, typeGauge, "go_threads", "Number of OS threads created.", func() (float64, bool) {
		n, _ := runtime.ThreadCreateProfile(nil)
		return float64(n), true
	})
	newFunc(r, typeGauge, "go_memstats_heap_alloc_bytes", "Number of heap bytes allocated and still in use.", func() (float64, bool) {
		return readRuntime("/memory/classes/heap/objects:bytes")
	})
	newFunc(r, typeGauge, "go_memstats_sys_bytes", "Number of bytes obtained from the OS.", func() (float64, bool) {
		return readRuntime("/memory/classes/total:bytes")
	})
	newSummaryFunc(r, "go_gc_duration_seconds", "A summary of the wall-time pause (stop-the-world) duration in garbage collection cycles.", gcPauses)
	newFunc(r, typeGauge, "process_start_time_seconds", "Start time of the process since unix epoch in seconds.", func() (float64, bool) {
		return unixSeconds(processStart), true
	})
	registerProcess(r)
}

// readRuntime reads one runtime/metrics value; false when this Go version
// does not have it.
func readRuntime(name string) (float64, bool) {
	s := []metrics.Sample{{Name: name}}
	metrics.Read(s)
	switch s[0].Value.Kind() {
	case metrics.KindUint64:
		return float64(s[0].Value.Uint64()), true
	case metrics.KindFloat64:
		return s[0].Value.Float64(), true
	case metrics.KindBad, metrics.KindFloat64Histogram:
	}
	return 0, false
}

// gcPauses returns the quantiles of the recent GC pauses (the runtime
// keeps the last 256), their total and the number of cycles.
func gcPauses() ([]Quantile, float64, uint64) {
	var st debug.GCStats
	st.PauseQuantiles = make([]time.Duration, 5)
	debug.ReadGCStats(&st)
	qs := make([]Quantile, 5)
	for i, q := range []float64{0, 0.25, 0.5, 0.75, 1} {
		qs[i] = Quantile{q, st.PauseQuantiles[i].Seconds()}
	}
	return qs, st.PauseTotal.Seconds(), uint64(max(st.NumGC, 0))
}
