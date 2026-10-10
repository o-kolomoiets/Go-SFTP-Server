// SPDX-License-Identifier: Apache-2.0

package sdnotify

import "golang.org/x/sys/unix"

// monotonicUsec returns CLOCK_MONOTONIC in microseconds, the clock systemd
// compares MONOTONIC_USEC with.
func monotonicUsec() int64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return ts.Nano() / 1000
}
