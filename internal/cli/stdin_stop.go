// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// serve --stop-on-stdin-eof (ADR 0013): serve stops, as on SIGTERM, when
// its stdin reaches end of file. The program that starts gosftpd, such as
// gosftpd-gui, holds the write end of a pipe; when it exits for any
// reason, even SIGKILL or a crash, the kernel closes it, and gosftpd stops
// instead of serving on unseen.

// stdinKey carries the file that stands for stdin (tests).
type stdinKey struct{}

// stopStdin returns stdin for --stop-on-stdin-eof, which must be a pipe or
// a socket: a file or a terminal never reaches end of file when the
// program that started gosftpd exits.
func stopStdin(ctx context.Context) (*os.File, error) {
	f, ok := ctx.Value(stdinKey{}).(*os.File)
	if !ok {
		f = os.Stdin
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, usageError{fmt.Errorf("--stop-on-stdin-eof needs stdin to be a pipe or a socket: %w", err)}
	}
	if fi.Mode()&(fs.ModeNamedPipe|fs.ModeSocket) == 0 {
		return nil, usageError{fmt.Errorf("--stop-on-stdin-eof needs stdin to be a pipe or a socket whose other end the program that starts gosftpd holds; stdin is %s", fileKind(fi.Mode()))}
	}
	return f, nil
}

// fileKind names the kind of a file that is neither a pipe nor a socket.
func fileKind(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "a file"
	case m.IsDir():
		return "a directory"
	case m&fs.ModeCharDevice != 0:
		return "a terminal or another character device, such as /dev/null"
	}
	return "a device"
}

// watchStdin reads stdin and discards what it reads until end of file or
// an error, then calls stop, which stops serve as the first SIGTERM does.
// A read of stdin cannot be interrupted, so it may last until the process
// exits.
func watchStdin(ctx context.Context, stdin io.Reader, log *slog.Logger, stop context.CancelFunc) {
	_, err := io.Copy(io.Discard, stdin)
	if ctx.Err() == nil { // not stopping already
		if err != nil {
			log.WarnContext(ctx, "stdin cannot be read; stopping as on SIGTERM", "err", err)
		} else {
			log.InfoContext(ctx, "stdin reached end of file; stopping as on SIGTERM")
		}
	}
	stop()
}

// catchSIGPIPE makes a write to a stdout or stderr whose reader has gone
// fail with EPIPE: SIGPIPE, which it raises, would otherwise kill the
// process (Go's default for fd 1 and 2) before the drain, server.stop and
// any clean-up. Caught, not ignored, which the processes gosftpd starts
// (the Landlock probe, exec hooks) would inherit; never stopped, as the
// drain and the clean-up come last.
func catchSIGPIPE() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}
