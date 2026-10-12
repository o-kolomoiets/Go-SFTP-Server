// SPDX-License-Identifier: Apache-2.0

//go:build landlockprobe

package sandbox

// probeBuild: a binary built with -tags landlockprobe proves the ruleset
// in its log, for the systemd CI job (ROADMAP M4 Definition of Done).
const probeBuild = true
