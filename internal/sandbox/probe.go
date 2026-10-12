// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// probeArg is the only argument of the probe child: gosftpd started again
// from /proc/self/exe to make the Landlock calls under the seccomp filter
// it inherits.
const probeArg = "__gosftpd_landlock_probe"

// probeTimeout bounds the probe child: a filter that kills only the
// calling thread (systemd before 243) leaves a Go process hanging.
const probeTimeout = 5 * time.Second

// probeSteps are the calls the child makes, in order. It prints one line
// per step, "STEP ok" ("abi N" for the ABI query) or "STEP errno N", and
// stops at the first step that fails.
var probeSteps = [...]string{"abi", "ruleset", "rule", "restrict"}

// ProbeMain runs the probe and exits when the process was started as the
// probe child of Start; otherwise it returns at once. The main function,
// and the TestMain of every package whose tests reach Start, call it
// before anything else.
func ProbeMain() {
	if len(os.Args) == 2 && os.Args[1] == probeArg {
		os.Exit(probeChild(os.Stdout))
	}
}

// probeResult is how the probe child ended.
type probeResult struct {
	output   string
	exitCode int    // the exit status; -1 when a signal killed the child
	signal   string // the signal that killed it
	timedOut bool   // killed at probeTimeout
	err      error  // the child could not be started
}

// classify turns the probe's result into nil (Landlock can be used), a
// skip, or an error that fails the start. Landlock is used only when the
// child exits 0 with all four results.
func classify(r probeResult) (*skip, error) {
	blocked := func(reason string) (*skip, error) {
		return &skip{status: StatusBlocked, reason: reason, hint: seccompHint}, nil
	}
	switch {
	case r.err != nil:
		return nil, fmt.Errorf("probe child: %w", r.err)
	case r.timedOut:
		return blocked(reasonHung)
	case r.exitCode != 0:
		// A SECCOMP_RET_KILL_PROCESS filter kills the child with SIGSYS;
		// with SECCOMP_RET_TRAP the Go runtime dies of it, with status 2.
		return blocked(reasonKilled)
	}
	results := map[string]string{}
	for line := range strings.SplitSeq(r.output, "\n") {
		if step, result, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			results[step] = result
		}
	}
	// No Landlock, or disabled at boot; securityfs, which Start looks at
	// first, is not mounted in containers.
	switch results["abi"] {
	case "errno " + strconv.Itoa(int(syscall.ENOSYS)):
		return &skip{status: StatusUnavailable, reason: reasonNoLandlock}, nil
	case "errno " + strconv.Itoa(int(syscall.EOPNOTSUPP)):
		return &skip{status: StatusUnavailable, reason: reasonDisabled}, nil
	}
	if v, err := strconv.Atoi(results["abi"]); err != nil || v < 1 {
		return blocked(reasonBlocked)
	}
	for _, step := range probeSteps[1:] {
		if results[step] != "ok" {
			return blocked(reasonBlocked)
		}
	}
	return nil, nil
}
