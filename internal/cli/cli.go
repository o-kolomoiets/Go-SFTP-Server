// SPDX-License-Identifier: Apache-2.0

// Package cli implements the gosftpd command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes are part of the public contract (see ROADMAP.md §6.7).
const (
	exitOK      = 0
	exitFailure = 1 // runtime error
	exitUsage   = 2 // invalid usage or configuration
)

// Run executes the command line in args (args[0] is the program name) and
// returns the process exit code.
func Run(ctx context.Context, args []string) int {
	return run(ctx, args[1:], os.Stdout, os.Stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(stderr, "Error:", err)
	switch {
	case errors.As(err, new(usageError)):
		fmt.Fprintf(stderr, "Run '%s --help' for usage.\n", root.CommandPath())
		return exitUsage
	case errors.As(err, new(configError)):
		return exitUsage
	}
	return exitFailure
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "gosftpd",
		Short:         "A secure-by-default SFTP server",
		Args:          noArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.AddCommand(newVersionCmd(), newServeCmd(), newInitCmd(), newConfigCmd(), newUserCmd(), newHostkeyCmd())
	return root
}

// usageError marks errors caused by invalid command-line usage.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// configError marks invalid configuration (bad keys, paths, permissions).
type configError struct{ err error }

func (e configError) Error() string { return e.err.Error() }
func (e configError) Unwrap() error { return e.err }

// noArgs rejects positional arguments, including unknown subcommands.
func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageError{err}
	}
	return nil
}
