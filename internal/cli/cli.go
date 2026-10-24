// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
	root := NewRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	if he, ok := errors.AsType[healthError](err); ok {
		fmt.Fprintln(stderr, he.msg) // exactly one line
		return exitFailure
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

// NewRootCommand returns the gosftpd command with all its subcommands, as
// Run executes it; exported for the generator of the man pages and shell
// completions (ADR 0012).
func NewRootCommand() *cobra.Command {
	var o serveOptions
	root := &cobra.Command{
		Use:   "gosftpd [USER:PASS[:e][:UID[:GID[:DIR[,DIR]...]]]...]",
		Short: "Turn a folder into an SFTP drop-box with an audit log",
		Long: `Turn a folder into an SFTP drop-box with an audit log.

Given atmoz/sftp user specs as arguments, gosftpd serves those users as the
atmoz/sftp image does (atmoz mode): user foo with directory upload sees
/upload, stored in /home/foo/upload, and logs in with the password or with
the keys in /home/foo/.ssh/keys/. Uploads overwrite an existing file. The
users of --users-conf and $SFTP_USERS are added, and a configuration file
is ignored. The users, keys and directories are read once, at start;
SIGHUP changes nothing. See docs/migrate-from-atmoz.md.`,
		Example: `  gosftpd 'foo:pass:::upload'
  gosftpd --listen :2222 'foo::1001:100:share' 'bar:$2b$10$...:e:::inbox'`,
		Args:          rootArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if cmd.Flags().NFlag() > 0 {
					return usageError{errors.New("these flags need atmoz user specs as arguments; without specs use 'gosftpd serve'")}
				}
				return cmd.Help()
			}
			o.specs = args
			return runServe(cmd.Context(), cmd.Flags(), o, os.Getenv, cmd.ErrOrStderr(), cmd.OutOrStdout())
		},
	}
	serveFlags(root.Flags(), &o, true)
	root.SetFlagErrorFunc(flagError)
	root.AddCommand(newVersionCmd(), newServeCmd(), newInitCmd(), newConfigCmd(), newUserCmd(), newHostkeyCmd(), newHealthcheckCmd())
	return root
}

// flagError makes a flag error a usage error. pflag repeats an unknown
// flag whole, and a value it cannot parse: one with ':', such as -x:pass or
// --read-only=foo:pass, may be an atmoz user spec with its password, and
// is not shown (ADR 0012). No valid value of a flag that pflag parses
// (booleans, a duration) contains ':'.
func flagError(_ *cobra.Command, err error) error {
	var (
		ne *pflag.NotExistError
		se *pflag.InvalidSyntaxError
		ve *pflag.InvalidValueError
	)
	switch {
	case errors.As(err, &ne) && strings.Contains(ne.GetSpecifiedName()+ne.GetSpecifiedShortnames(), ":"),
		errors.As(err, &se) && strings.Contains(se.GetSpecifiedFlag(), ":"):
		err = errors.New("unknown flag (not shown: it contains ':', as an atmoz user spec does)")
	case errors.As(err, &ve) && strings.Contains(ve.GetValue(), ":"):
		err = fmt.Errorf("invalid argument for --%s (not shown: it contains ':', as an atmoz user spec does)", ve.GetFlag().Name)
	}
	return usageError{err}
}

// usageError marks errors caused by invalid command-line usage.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// configError marks invalid configuration (bad keys, paths, permissions).
type configError struct{ err error }

func (e configError) Error() string { return e.err.Error() }
func (e configError) Unwrap() error { return e.err }

// showHelp makes a command group runnable, so that noArgs rejects unknown
// subcommands with exit code 2 instead of cobra printing help with 0.
func showHelp(cmd *cobra.Command, _ []string) error { return cmd.Help() }

// noArgs rejects positional arguments, including unknown subcommands.
// cobra's message repeats the first argument; one with ':' may be an atmoz
// user spec with its password, given after a command or with a space
// before it, and only its position is given (ADR 0012).
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 && strings.Contains(args[0], ":") {
		if !cmd.HasParent() {
			return usageError{errors.New("unknown command (argument 1, not shown: it looks like an atmoz user spec, but a spec starts with the user name and ':', without white space)")}
		}
		path := strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")
		return usageError{fmt.Errorf("unknown command (argument 1, not shown: it looks like an atmoz user spec; give specs directly after the image name, without '%s')", path)}
	}
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageError{err}
	}
	return nil
}
