// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux

package obs

func registerProcfs(*Registry) {}
