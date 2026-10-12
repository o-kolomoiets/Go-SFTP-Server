// SPDX-License-Identifier: Apache-2.0

// Package sdnotify reports the service state to systemd (sd_notify(3)): one
// datagram to the socket in $NOTIFY_SOCKET per state change. Without that
// variable, as outside systemd, every call does nothing.
package sdnotify

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Ready reports that the service has started.
func Ready() error { return Notify("READY=1") }

// Reloaded reports that a reload has finished, with its result as the
// status that systemctl status shows: under Type=notify-reload, systemctl
// reload succeeds whatever the result.
func Reloaded(ok bool, restartRequired []string) error {
	return Notify("READY=1\nSTATUS=" + ReloadStatus(ok, restartRequired))
}

// maxStatusKeys is how many keys of restart_required a reload status
// names. systemd drops a notify message over 4096 bytes whole, READY=1
// with it, and the reload would then time out.
const maxStatusKeys = 5

// ReloadStatus is the STATUS= text after a reload: whether it worked, and
// the settings that need a restart to change.
func ReloadStatus(ok bool, restartRequired []string) string {
	switch {
	case !ok:
		return "configuration reload failed, see the log"
	case len(restartRequired) == 0:
		return "configuration reloaded"
	case len(restartRequired) <= maxStatusKeys:
		return "configuration reloaded; restart needed for: " + strings.Join(restartRequired, ", ")
	}
	return "configuration reloaded; restart needed for: " + strings.Join(restartRequired[:maxStatusKeys], ", ") +
		" and " + strconv.Itoa(len(restartRequired)-maxStatusKeys) + " more; see the log"
}

// ExtendTimeout asks systemd for d more time, from now, to finish the
// current state, such as stopping: TimeoutStopSec is fixed, while the
// time a stop needs can change at a reload. systemd only ever extends.
func ExtendTimeout(d time.Duration) error {
	return Notify("EXTEND_TIMEOUT_USEC=" + strconv.FormatInt(d.Microseconds(), 10))
}

// Reloading reports that a reload has started. systemd ≥ 253 needs the
// monotonic timestamp for Type=notify-reload.
func Reloading() error {
	state := "RELOADING=1"
	if usec := monotonicUsec(); usec > 0 {
		state += "\nMONOTONIC_USEC=" + strconv.FormatInt(usec, 10)
	}
	return Notify(state)
}

// Stopping reports that the service is shutting down.
func Stopping() error { return Notify("STOPPING=1") }

// Notify sends state, newline-separated KEY=VALUE assignments, to the
// socket in $NOTIFY_SOCKET.
func Notify(state string) error { return send(os.Getenv("NOTIFY_SOCKET"), state) }

func send(socket, state string) error {
	switch {
	case socket == "":
		return nil
	case socket[0] != '/' && socket[0] != '@':
		// vsock: and other address families are for virtual machines.
		return errors.New("sdnotify: unsupported NOTIFY_SOCKET " + strconv.Quote(socket))
	}
	// A leading '@' names an abstract socket; package net maps it.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
