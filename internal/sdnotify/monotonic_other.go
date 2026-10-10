// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sdnotify

// monotonicUsec is not needed outside Linux: there is no systemd.
func monotonicUsec() int64 { return 0 }
