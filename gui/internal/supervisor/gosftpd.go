// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Gosftpd runs the gosftpd at Bin on the configuration of Layout.
type Gosftpd struct {
	Bin    string
	Layout Layout
}

// CommandError is a gosftpd command that failed. Stderr is what gosftpd
// wrote, which the GUI shows as it is (ADR 0013, "Look and behaviour").
type CommandError struct {
	Args   []string
	Code   int
	Stderr string
}

func (e *CommandError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	msg = strings.TrimPrefix(msg, "Error: ")
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", e.Code)
	}
	return fmt.Sprintf("gosftpd %s: %s", strings.Join(e.Args, " "), msg)
}

// childEnv is env without what would change the gosftpd the GUI starts:
// the GOSFTPD_* variables (GOSFTPD_LISTEN overrides where it listens) and
// NOTIFY_SOCKET (it would send READY=1 to a systemd unit that started the
// GUI).
func childEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GOSFTPD_") || name == "NOTIFY_SOCKET" {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func (g Gosftpd) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, g.Bin, args...) //nolint:gosec // G204: the gosftpd shipped with the GUI, with its own arguments
	cmd.Env = childEnv(os.Environ())
	cmd.Dir = g.Layout.Dir
	return cmd
}

// run runs gosftpd with args and stdin. It returns stdout, and stderr,
// which holds the warnings of a command that succeeded.
func (g Gosftpd) run(ctx context.Context, stdin io.Reader, args ...string) (stdout []byte, stderr string, err error) {
	cmd := g.command(ctx, args...)
	if cmd.Dir != "" {
		if _, err := os.Stat(cmd.Dir); err != nil {
			cmd.Dir = ""
		}
	}
	cmd.Stdin = stdin
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			return out.Bytes(), errOut.String(), &CommandError{Args: args, Code: exit.ExitCode(), Stderr: errOut.String()}
		}
		return out.Bytes(), errOut.String(), fmt.Errorf("gosftpd %s: %w", strings.Join(args, " "), err)
	}
	return out.Bytes(), errOut.String(), nil
}

// runJSON runs gosftpd with args and decodes its stdout into v.
func (g Gosftpd) runJSON(ctx context.Context, v any, args ...string) error {
	out, _, err := g.run(ctx, nil, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("gosftpd %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// Version is gosftpd version --json.
func (g Gosftpd) Version(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	if err := g.runJSON(ctx, &v, "version", "--json"); err != nil {
		return "", err
	}
	return v.Version, nil
}

// VersionError is a gosftpd of another version than the GUI's.
type VersionError struct {
	Bin, Found, Want string
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("%s is gosftpd %s, but gosftpd-gui %s needs gosftpd %s: install the two from the same release", e.Bin, e.Found, e.Want, e.Want)
}

// CheckVersion refuses a gosftpd whose version is not want, the GUI's
// own. It runs before every serve: a package upgrade can replace gosftpd
// under a running GUI.
func (g Gosftpd) CheckVersion(ctx context.Context, want string) error {
	found, err := g.Version(ctx)
	if err != nil {
		return err
	}
	if found != want {
		return &VersionError{Bin: g.Bin, Found: found, Want: want}
	}
	return nil
}
