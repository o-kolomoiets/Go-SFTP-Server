// SPDX-License-Identifier: Apache-2.0

//go:build unix

package obs

import (
	"syscall"
	"time"
)

func registerProcess(r *Registry) {
	newFunc(r, typeCounter, "process_cpu_seconds_total", "Total user and system CPU time spent in seconds.", func() (float64, bool) {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			return 0, false
		}
		return (time.Duration(ru.Utime.Nano()) + time.Duration(ru.Stime.Nano())).Seconds(), true
	})
	newFunc(r, typeGauge, "process_max_fds", "Maximum number of open file descriptors.", func() (float64, bool) {
		var l syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &l); err != nil {
			return 0, false
		}
		return float64(l.Cur), true
	})
	registerProcfs(r)
}
