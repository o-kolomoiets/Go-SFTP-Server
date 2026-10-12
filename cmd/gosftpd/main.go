// SPDX-License-Identifier: Apache-2.0

// Command gosftpd turns a folder into an SFTP drop-box with an audit log.
package main

import (
	"context"
	"os"

	"github.com/o-kolomoiets/go-sftp-server/internal/cli"
	"github.com/o-kolomoiets/go-sftp-server/internal/sandbox"
)

func main() {
	// Before anything else: serve starts gosftpd again to try the
	// Landlock calls under a seccomp filter (ADR 0011).
	sandbox.ProbeMain()
	os.Exit(cli.Run(context.Background(), os.Args))
}
