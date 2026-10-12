// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package hooks

import (
	"os"
	"os/exec"
)

const defaultPath = `C:\Windows\System32;C:\Windows`

// workDir is the system directory, never a served one: cmd.exe looks for
// commands in the working directory first.
func workDir() string {
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return `C:\Windows`
}

// ownGroup does nothing: only the process itself is killed (ADR 0010).
func ownGroup(*exec.Cmd) {}

func killGroup(int) {}

// untrusted is a no-op where Unix permissions do not exist.
func untrusted([]string) error { return nil }
