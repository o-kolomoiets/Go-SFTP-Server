// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"bytes"
	"os"
	"strconv"
)

// registerProcfs adds the metrics read from /proc/self. A value that
// cannot be read is left out, never reported as 0.
func registerProcfs(r *Registry) {
	newFunc(r, typeGauge, "process_resident_memory_bytes", "Resident memory size in bytes.", func() (float64, bool) {
		return statm(1)
	})
	newFunc(r, typeGauge, "process_virtual_memory_bytes", "Virtual memory size in bytes.", func() (float64, bool) {
		return statm(0)
	})
	newFunc(r, typeGauge, "process_open_fds", "Number of open file descriptors.", func() (float64, bool) {
		d, err := os.Open("/proc/self/fd")
		if err != nil {
			return 0, false
		}
		defer d.Close()
		names, err := d.Readdirnames(-1)
		if err != nil {
			return 0, false
		}
		return float64(len(names) - 1), true // without d itself
	})
}

// statm returns field i of /proc/self/statm (in pages) in bytes.
func statm(i int) (float64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := bytes.Fields(data)
	if len(fields) <= i {
		return 0, false
	}
	pages, err := strconv.ParseUint(string(fields[i]), 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(pages) * float64(os.Getpagesize()), true
}
