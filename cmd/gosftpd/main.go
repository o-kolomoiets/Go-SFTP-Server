// SPDX-License-Identifier: Apache-2.0

// Command gosftpd is a secure-by-default SFTP server.
package main

import (
	"context"
	"os"

	"github.com/o-kolomoiets/go-sftp-server/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args))
}
