// SPDX-License-Identifier: Apache-2.0

// Command gosftpd turns a folder into an SFTP drop-box with an audit log.
package main

import (
	"context"
	"os"

	"github.com/o-kolomoiets/go-sftp-server/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args))
}
