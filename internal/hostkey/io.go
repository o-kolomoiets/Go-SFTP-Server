// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"encoding/pem"
	"fmt"
	"io"
)

// maxKeySize bounds how much of a key file is read; real keys are a few KiB.
const maxKeySize = 64 << 10

func readAll(r io.Reader, size int64) ([]byte, error) {
	if size > maxKeySize {
		return nil, fmt.Errorf("host key file is larger than %d bytes", maxKeySize)
	}
	return io.ReadAll(io.LimitReader(r, maxKeySize))
}

func writePEM(w io.Writer, block *pem.Block) error {
	return pem.Encode(w, block)
}
