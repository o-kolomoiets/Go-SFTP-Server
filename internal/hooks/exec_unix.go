// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const defaultPath = "/usr/local/bin:/usr/bin:/bin"

func workDir() string { return "/" }

// ownGroup runs the program in a process group of its own, which the
// timeout kills as a whole.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		killGroup(cmd.Process.Pid)
		return nil
	}
}

// killGroup kills the process group led by pid; a group that is gone is
// fine. While members of the group live, the leader's ID stays allocated
// even after the leader was waited for, so the signal reaches only them.
func killGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// untrusted checks, just before a run, the files a hook runs as they are
// at that moment: the program, and every other absolute argv element that
// is a regular file, must belong to root or to gosftpd's user and not be
// writable by group or others. Start and reload check where they lie.
func untrusted(argv []string) error {
	for i, a := range argv {
		if !filepath.IsAbs(a) {
			continue
		}
		fi, err := os.Stat(a)
		switch {
		case err != nil && i == 0:
			return err
		case err != nil, !fi.Mode().IsRegular():
			continue
		}
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s: writable by group or others (mode %04o)", a, perm)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Getuid() {
			return fmt.Errorf("%s: owned by uid %d, not root or gosftpd's user", a, st.Uid)
		}
	}
	return nil
}
