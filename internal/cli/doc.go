// SPDX-License-Identifier: Apache-2.0

// Package cli implements the gosftpd command-line interface.
package cli

// The man pages and shell completions of the release archives and
// packages, into out/ at the root of the repository, which git ignores
// (ADR 0012). make generate runs this with SOURCE_DATE_EPOCH set to the
// commit time, which dates the pages.
//go:generate go run ./gendocs ../../out
