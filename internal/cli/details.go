// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/version"
)

// serve --print-details (ADR 0013), for a program that starts gosftpd and
// reads its output, such as gosftpd-gui: once it serves, where --ephemeral
// prints its line, one JSON line on stdout gives the connection details. A
// start that fails prints one JSON line with the error instead. The banner
// is not printed, and stdout carries nothing else: the audit log must go
// to a file.

// serveDetails is the line of serve --print-details. The fields it shares
// with the line of serve --ephemeral keep their names and come first; they
// describe the first listener and the first host key, as the banner's
// connect: line does. Fields may be added later, never removed or renamed.
type serveDetails struct {
	Host               string           `json:"host"`
	Port               int              `json:"port"`
	HostKeyFingerprint string           `json:"host_key_fingerprint"`
	KnownHosts         string           `json:"known_hosts"`
	PID                int              `json:"pid"`
	Version            string           `json:"version"`
	Listen             []string         `json:"listen"`
	HostKeys           []hostKeyDetails `json:"host_keys"`
	Addresses          []string         `json:"addresses"`
}

// hostKeyDetails is a host key in use, of serveDetails.
type hostKeyDetails struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// startFailure is the line of serve --print-details when the start fails.
type startFailure struct {
	Error   string `json:"error"`
	Kind    string `json:"kind"`
	Address string `json:"address"` // the address of kind "listen", else empty
}

// The kinds of startFailure.
const (
	failListen  = "listen"  // an address cannot be listened on, such as a port in use
	failConfig  = "config"  // the command line or the configuration (exit status 2)
	failSandbox = "sandbox" // the sandbox step (ADR 0011)
	failOther   = "other"
)

// listenError is an address that cannot be listened on.
type listenError struct {
	addr string // as configured
	err  error
}

func (e listenError) Error() string { return e.err.Error() }
func (e listenError) Unwrap() error { return e.err }

// sandboxError is a failure of the sandbox step; the exit status is that
// of the error it wraps.
type sandboxError struct{ err error }

func (e sandboxError) Error() string { return e.err.Error() }
func (e sandboxError) Unwrap() error { return e.err }

// failureKind returns the kind of a failed start and, for kind "listen",
// the address.
func failureKind(err error) (kind, addr string) {
	if le, ok := errors.AsType[listenError](err); ok {
		return failListen, le.addr
	}
	switch {
	case errors.As(err, new(sandboxError)):
		return failSandbox, ""
	case errors.As(err, new(configError)), errors.As(err, new(usageError)):
		return failConfig, ""
	}
	return failOther, ""
}

// reportFailure writes the line of a start that failed with err. A write
// that fails is not reported: the error goes to stderr too.
func reportFailure(w io.Writer, err error) {
	kind, addr := failureKind(err)
	_ = writeLine(w, startFailure{Error: err.Error(), Kind: kind, Address: addr})
}

// checkDetailsFlags refuses --print-details with --ephemeral, which prints
// a line of its own, and with the audit log on stdout.
func checkDetailsFlags(flags *pflag.FlagSet, o serveOptions) error {
	switch {
	case !o.printDetails:
		return nil
	case o.ephemeral:
		return usageError{errors.New("--print-details and --ephemeral cannot be used together: --ephemeral prints its own line of connection details")}
	case flags.Changed("audit-output") && isStdout(o.auditOutput):
		return usageError{errors.New("--audit-output stdout cannot be used with --print-details, whose stdout carries only the connection details; name a file for the audit log")}
	}
	return nil
}

// checkDetailsAudit refuses, with --print-details, an audit log on stdout
// that the configuration file sets or leaves as the default; at start and
// on reload.
func checkDetailsAudit(o serveOptions, c *config.Config) error {
	if !o.printDetails || !isStdout(c.Audit.Output) {
		return nil
	}
	if c.File != "" && c.Defined("audit.output") {
		return configError{fmt.Errorf("audit.output = %q in %s cannot be used with --print-details, whose stdout carries only the connection details; set it to a file", c.Audit.Output, c.File)}
	}
	return configError{errors.New("--print-details needs the audit log in a file: its stdout carries only the connection details, and audit.output is \"stdout\" by default; set audit.output, or pass --audit-output FILE")}
}

// announceDetails writes the details of the server listening on listeners
// with keys to w.
func announceDetails(ctx context.Context, w io.Writer, listeners []net.Listener, keys hostKeys, log *slog.Logger) error {
	ifAddrs, err := interfaceAddrs()
	if err != nil {
		log.WarnContext(ctx, "cannot list the addresses of the network interfaces; the connection details name none", "err", err)
	}
	if err := writeLine(w, newServeDetails(listeners, keys, remoteAddresses(ifAddrs))); err != nil {
		return fmt.Errorf("writing the connection details: %w", err)
	}
	return nil
}

// newServeDetails describes the server listening on listeners with keys;
// addresses are those of the interfaces. For an unspecified address such
// as :2022, host is this machine's name, as in the banner, and known_hosts
// names it and every address, so that the line holds whichever one a
// person types.
func newServeDetails(listeners []net.Listener, keys hostKeys, addresses []string) serveDetails {
	first := listeners[0].Addr()
	host, port := connectHost(first)
	d := serveDetails{
		Host: host, Port: port, PID: os.Getpid(), Version: version.Get().Version,
		Listen: make([]string, len(listeners)), HostKeys: make([]hostKeyDetails, len(keys)), Addresses: addresses,
	}
	for i, ln := range listeners {
		d.Listen[i] = ln.Addr().String()
	}
	for i, k := range keys {
		d.HostKeys[i] = hostKeyDetails{Type: k.cur.pub.Type(), Fingerprint: hostkey.Fingerprint(k.cur.pub)}
	}
	if len(keys) > 0 {
		hosts := []string{host}
		if h, _, _ := net.SplitHostPort(first.String()); net.ParseIP(h).IsUnspecified() {
			hosts = append(hosts, addresses...)
		}
		d.HostKeyFingerprint = hostkey.Fingerprint(keys[0].cur.pub)
		d.KnownHosts = knownHostsLine(hosts, port, keys[0].cur.pub)
	}
	return d
}

// knownHostsLine returns the known_hosts line of key served on port of
// every host, as hostkey.KnownHostsLine does for one.
func knownHostsLine(hosts []string, port int, key ssh.PublicKey) string {
	patterns := make([]string, 0, len(hosts))
	for _, h := range hosts {
		// JoinHostPort brackets an IPv6 address, so that Normalize can split it.
		p := knownhosts.Normalize(net.JoinHostPort(h, strconv.Itoa(port)))
		if !slices.Contains(patterns, p) {
			patterns = append(patterns, p)
		}
	}
	return knownhosts.Line(patterns, key)
}

// interfaceAddrs returns the addresses of the network interfaces that are
// up, other than loopback interfaces (a variable for tests). An interface
// whose addresses cannot be read is left out.
var interfaceAddrs = func() ([]net.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var addrs []net.Addr
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if a, err := ifc.Addrs(); err == nil {
			addrs = append(addrs, a...)
		}
	}
	return addrs, nil
}

// remoteAddresses returns the addresses of addrs that another machine can
// connect to, once each: unicast, neither loopback nor link-local, which
// would need a zone.
func remoteAddresses(addrs []net.Addr) []string {
	out := []string{}
	for _, a := range addrs {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		default:
			continue
		}
		if s := ip.String(); ip.IsGlobalUnicast() && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// writeLine writes v to w as one JSON line, in one write.
func writeLine(w io.Writer, v any) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b) // a newline after the object
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}
