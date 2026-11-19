// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Command gosftpd-gui shares folders over SFTP from a window: it runs the
// gosftpd shipped with it as a child process and changes its
// configuration only through gosftpd's commands (ADR 0013).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	qt "github.com/mappu/miqt/qt6"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/app"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/qtui"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

// version is the release, set at build time with -ldflags "-X
// main.version=..."; "dev" for a development build.
var version = "dev"

func init() {
	// Qt keeps its widgets on the thread that created the application:
	// the main thread, which main must not leave.
	runtime.LockOSThread()
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gosftpd-gui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	startSharing := fs.Bool("start-sharing", false, "start sharing at launch, as the Start sharing button does, if a folder was shared before")
	gosftpd := fs.String("gosftpd", "", "the gosftpd to run (development builds only; a release runs the one shipped with it)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "gosftpd-gui: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "gosftpd-gui", version)
		return 0
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "gosftpd-gui: refusing to run as root: start it as the desktop user, as gosftpd runs")
		return 1
	}
	if *gosftpd != "" && version != "dev" {
		fmt.Fprintln(stderr, "gosftpd-gui: --gosftpd is for development builds: a release runs the gosftpd shipped with it")
		return 2
	}

	setPlatform()
	// Only the program's name: Qt reads options such as -platform from
	// its arguments.
	qt.NewQApplication([]string{os.Args[0]})
	qt.QCoreApplication_SetApplicationName("gosftpd-gui")
	qt.QGuiApplication_SetApplicationDisplayName("gosftpd")
	qt.QGuiApplication_SetDesktopFileName("gosftpd-gui")

	a, lock, err := setup(*gosftpd)
	if err != nil {
		fmt.Fprintln(stderr, "gosftpd-gui:", err)
		qt.QMessageBox_Critical(nil, "gosftpd", err.Error())
		return 1
	}
	defer func() { _ = lock.Release() }()

	w := qtui.New(a, qtui.Options{StartSharing: *startSharing})
	w.Show()
	// A gosftpd still running when the GUI exits stops as on SIGTERM: its
	// stdin, a pipe the GUI holds, reaches end of file.
	return qt.QApplication_Exec()
}

// setup finds the state directory and gosftpd, and takes the lock of the
// one GUI a user runs.
func setup(gosftpd string) (*app.App, *supervisor.Lock, error) {
	layout, err := supervisor.DefaultLayout()
	if err != nil {
		return nil, nil, err
	}
	rt, err := supervisor.RuntimeDir()
	if err != nil {
		return nil, nil, err
	}
	lock, err := supervisor.AcquireLock(rt)
	if errors.Is(err, supervisor.ErrRunning) {
		return nil, nil, errors.New("gosftpd-gui is already running: switch to its window")
	}
	if err != nil {
		return nil, nil, err
	}
	bin := gosftpd
	if bin != "" {
		// gosftpd runs in the state directory: a relative path would
		// resolve there.
		if bin, err = filepath.Abs(bin); err != nil {
			_ = lock.Release()
			return nil, nil, err
		}
	} else {
		if bin, err = supervisor.FindGosftpd(); err != nil {
			_ = lock.Release()
			return nil, nil, fmt.Errorf("%w: install gosftpd-gui again", err)
		}
	}
	a := &app.App{G: supervisor.Gosftpd{Bin: bin, Layout: layout}, Lock: lock}
	if version != "dev" {
		a.Version = version
	}
	// Without it, Clear activity holds only until the GUI quits.
	if p, err := app.DefaultPrefsPath(); err == nil {
		a.PrefsPath = p
	}
	return a, lock, nil
}

// allowedPlatforms are the Qt platform plugins the GUI runs on. Others
// are refused: Qt's vnc plugin, for one, opens a network listener (ADR
// 0013, "Security model").
var allowedPlatforms = []string{"xcb", "wayland", "cocoa"}

// setPlatform keeps only the allowed plugins of QT_QPA_PLATFORM, a list
// separated by ";" whose entries may carry options after ":", and
// removes the variable when none is left: Qt then picks the session's.
// It removes QT_QPA_GENERIC_PLUGINS: the GUI needs no generic plugin, and
// Qt's tuiotouch listens on UDP port 3333 of every interface.
func setPlatform() {
	_ = os.Unsetenv("QT_QPA_GENERIC_PLUGINS")
	v, ok := os.LookupEnv("QT_QPA_PLATFORM")
	if !ok {
		return
	}
	if kept := allowedPlatform(v); kept != "" {
		_ = os.Setenv("QT_QPA_PLATFORM", kept)
	} else {
		_ = os.Unsetenv("QT_QPA_PLATFORM")
	}
}

func allowedPlatform(v string) string {
	var keep []string
	for entry := range strings.SplitSeq(v, ";") {
		name, _, _ := strings.Cut(entry, ":")
		if slices.Contains(allowedPlatforms, strings.TrimSpace(name)) {
			keep = append(keep, strings.TrimSpace(entry))
		}
	}
	return strings.Join(keep, ";")
}
