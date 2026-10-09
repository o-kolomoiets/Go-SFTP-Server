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
)

// Ready reports that the service has started, or finished a reload.
func Ready() error { return Notify("READY=1") }

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
