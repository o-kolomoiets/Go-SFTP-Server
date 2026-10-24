// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pires/go-proxyproto"
	"github.com/spf13/cobra"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// healthError fails gosftpd healthcheck with exit code 1, whatever went
// wrong: Docker reserves 2 for HEALTHCHECK (ADR 0009).
type healthError struct{ msg string }

func (e healthError) Error() string { return e.msg }

func unhealthy(format string, args ...any) error {
	return healthError{"unhealthy: " + oneLine(fmt.Sprintf(format, args...))}
}

func healthUsage(err error) error { return healthError{oneLine(err.Error())} }

// oneLine keeps a message on one line, so that the check prints exactly one.
func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }), "; ")
}

type healthOptions struct {
	config  string
	address string
	url     string
	timeout time.Duration
	ready   bool
}

const (
	defaultHealthTimeout = 5 * time.Second
	maxHealthTimeout     = 5 * time.Minute
	maxBannerBytes       = 255
)

func newHealthcheckCmd() *cobra.Command {
	var o healthOptions
	cmd := &cobra.Command{
		Use:   "healthcheck [--address HOST:PORT | --url URL]",
		Short: "Check that the server answers (for container health checks)",
		Long: `Check that the server answers. It exits with 0 when it does and with 1
otherwise, also for usage errors (Docker reserves 2 for HEALTHCHECK).

Without --url it connects to the SSH listener and waits for the server's
SSH banner, then closes the connection without sending its own: such a probe
leaves no trace in the audit log. The address is --address, else
$GOSFTPD_LISTEN, else the first server.listen of the configuration file that
serve would read, else :2022. A wildcard address is checked on 127.0.0.1,
then on ::1. A server that accepts the connection and closes it at once is
alive but refuses new connections (limits, a ban, or an unavailable audit
log): that is healthy, unless --ready is given.

From the same file it reads server.trusted_proxies, also with --address or
$GOSFTPD_LISTEN: when its own address is a trusted proxy, it sends a PROXY
protocol LOCAL header before it waits for the banner. Of the file only
server.listen is read strictly; what cannot be used of
server.trusted_proxies is named at the end of the line it prints.

With --url it sends GET URL to the admin listener ([metrics] listen); any 2xx
status is healthy. Use /healthz for liveness and /readyz for readiness.`,
		Example: `  gosftpd healthcheck
  gosftpd healthcheck --address 127.0.0.1:2022 --ready
  gosftpd healthcheck --url http://127.0.0.1:9090/readyz`,
		// noArgs never shows an argument with ':', which may be an atmoz
		// user spec with its password; healthUsage keeps the exit code 1.
		Args: func(cmd *cobra.Command, args []string) error {
			if err := noArgs(cmd, args); err != nil {
				return healthUsage(err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHealthcheck(cmd.Context(), o, os.Getenv, cmd.OutOrStdout())
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return healthUsage(err) })
	f := cmd.Flags()
	f.StringVar(&o.config, "config", "", "configuration file to read server.listen from")
	f.StringVar(&o.address, "address", "", "SSH address to check, HOST:PORT")
	f.StringVar(&o.url, "url", "", "admin listener URL to check instead, such as http://127.0.0.1:9090/readyz")
	f.DurationVar(&o.timeout, "timeout", defaultHealthTimeout, "how long to wait for an answer")
	f.BoolVar(&o.ready, "ready", false, "without --url: also fail when the server refuses new connections")
	return cmd
}

func runHealthcheck(ctx context.Context, o healthOptions, getenv func(string) string, stdout io.Writer) error {
	if o.timeout <= 0 || o.timeout > maxHealthTimeout {
		return healthError{fmt.Sprintf("--timeout must be between 1ns and %s", maxHealthTimeout)}
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if o.url != "" {
		if o.address != "" || o.config != "" || o.ready {
			return healthError{"--url cannot be used with --address, --config or --ready (check /readyz for readiness)"}
		}
		return checkURL(ctx, o.url, o.timeout, stdout)
	}
	t, err := healthTargetFor(o, getenv)
	if err != nil {
		return err
	}
	ok, err := checkSSH(ctx, t, o.timeout, o.ready)
	// A server.trusted_proxies that cannot be used is named on the one line
	// the check prints, healthy or not (ADR 0009, ADR 0011).
	if t.note != "" {
		note := " (server.trusted_proxies: " + oneLine(t.note) + ")"
		if he, isHealth := errors.AsType[healthError](err); isHealth {
			return healthError{he.msg + note}
		}
		ok += note
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, ok)
	return nil
}

// healthTarget is what the SSH check connects to.
type healthTarget struct {
	addr string
	// trusted are the server's trusted proxies (server.trusted_proxies):
	// a probe from one of them sends a PROXY protocol LOCAL header.
	trusted []netip.Prefix
	// note says why server.trusted_proxies, or some of its entries, could
	// not be used.
	note string
}

// healthTargetFor returns the SSH address to check: --address, else
// $GOSFTPD_LISTEN, else the first server.listen of the configuration file,
// else :2022; and server.trusted_proxies of that file, found as serve finds
// it also when the address does not come from there. Only server.listen
// can fail the check: server.trusted_proxies is read apart from it, and
// what cannot be used of it goes into the note.
func healthTargetFor(o healthOptions, getenv func(string) string) (healthTarget, error) {
	t := healthTarget{addr: o.address}
	from := "--address"
	if t.addr == "" {
		if v := getenv(config.EnvListen); v != "" {
			t.addr, _, _ = strings.Cut(v, ",")
			from = "$" + config.EnvListen
		}
	}
	path, findErr := config.Find(o.config, getenv)
	if t.addr == "" {
		switch {
		case errors.Is(findErr, config.ErrNotFound):
		case findErr != nil:
			return t, healthError{oneLine(findErr.Error())}
		default:
			listen, err := config.ReadListen(path)
			if err != nil {
				return t, healthError{"cannot read server.listen (pass --address): " + oneLine(err.Error())}
			}
			if len(listen) > 0 {
				t.addr, from = listen[0], "server.listen in "+path
			}
		}
	}
	if t.addr == "" {
		t.addr, from = ":2022", "the default"
	}
	_, port, err := net.SplitHostPort(t.addr)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
		return t, healthError{fmt.Sprintf("%s: %q is not HOST:PORT with a port from 1 to 65535", from, t.addr)}
	}
	switch {
	case errors.Is(findErr, config.ErrNotFound):
	case findErr != nil:
		t.note = findErr.Error() // only with --address or $GOSFTPD_LISTEN
	default:
		var err error
		if t.trusted, err = config.ReadTrustedProxies(path); err != nil {
			t.note = err.Error()
		}
	}
	return t, nil
}

// localHeader is the PROXY protocol v2 header of a proxy's own connection
// (LOCAL, 16 bytes): a probe from a trusted proxy's address sends it, since
// the server waits for a header from there before it sends its banner. It
// is the signature, then version 2 with LOCAL, no address family and an
// address block of length 0.
var localHeader = append(bytes.Clone(proxyproto.SIGV2), byte(proxyproto.LOCAL), byte(proxyproto.UNSPEC), 0, 0)

// trustedSource reports whether the probe's own address on conn is one of
// the server's trusted proxies.
func trustedSource(conn net.Conn, trusted []netip.Prefix) bool {
	ip, ok := auth.SourceAddr(conn.LocalAddr())
	return ok && slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// checkSSH connects to t.addr and waits for the SSH banner, without
// sending its own version: the server writes no conn.accept for such a
// probe. From a trusted proxy's address it first sends a LOCAL header. It
// returns the line to print when the server is healthy.
func checkSSH(ctx context.Context, t healthTarget, timeout time.Duration, ready bool) (string, error) {
	addr := t.addr
	host, port, _ := net.SplitHostPort(addr)
	targets := []string{addr}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		targets = []string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)}
	}
	var (
		d    net.Dialer
		conn net.Conn
		errs []error
	)
	for i, target := range targets {
		// A dial that hangs leaves half the time to the next address.
		dctx, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok && i < len(targets)-1 {
			dctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/2))
		}
		c, err := d.DialContext(dctx, "tcp", target)
		cancel()
		if err == nil {
			conn, addr = c, target
			break
		}
		errs = append(errs, err)
	}
	if conn == nil {
		return "", unhealthy("%s", errors.Join(errs...)) // every address tried
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	via := ""
	if trustedSource(conn, t.trusted) {
		if _, err := conn.Write(localHeader); err != nil {
			return "", unhealthy("%s: cannot send a PROXY protocol LOCAL header: %s", addr, err)
		}
		via = " after a PROXY protocol LOCAL header"
	}
	var got []byte
	buf := make([]byte, maxBannerBytes)
	for len(got) < maxBannerBytes {
		n, err := conn.Read(buf[:maxBannerBytes-len(got)])
		got = append(got, buf[:n]...)
		switch banner(got) {
		case bannerMore:
		case bannerFound:
			return fmt.Sprintf("ok: %s sent an SSH banner%s", addr, via), nil
		case bannerWrong:
			return "", unhealthy("%s answered %q, not SSH-2.0", addr, firstLine(got))
		}
		if err == nil {
			continue
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			return "", unhealthy("%s sent no SSH banner within %s", addr, timeout)
		case len(got) > 0:
			return "", unhealthy("%s closed the connection after %d bytes without an SSH banner", addr, len(got))
		case ready:
			return "", unhealthy("%s accepted the connection and closed it without a banner: the server refuses new connections (connection limits, a ban, or an unavailable audit log)", addr)
		}
		return fmt.Sprintf("ok: %s accepted the connection and closed it without a banner: the server runs but refuses new connections (connection limits, a ban, or an unavailable audit log)", addr), nil
	}
	return "", unhealthy("%s sent no SSH banner in its first %d bytes", addr, maxBannerBytes)
}

type bannerState int

const (
	bannerMore bannerState = iota
	bannerFound
	bannerWrong
)

// banner looks for a line that starts with SSH-2.0- in what the server
// sent so far. RFC 4253 allows other lines before it, but none that starts
// with SSH-.
func banner(got []byte) bannerState {
	const v2 = "SSH-2.0-"
	for line := range bytes.Lines(got) {
		if bytes.HasPrefix(line, []byte(v2)) {
			return bannerFound
		}
		if len(line) < len(v2) && string(line) == v2[:len(line)] {
			return bannerMore // the start of the banner, or of a line ending soon
		}
		if bytes.HasPrefix(line, []byte("SSH-")) {
			return bannerWrong
		}
	}
	return bannerMore
}

// firstLine returns the first line of b, printable and at most 64 bytes.
func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(b, []byte("\n"))
	s := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, string(line))
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return s
}

// checkURL sends GET u, without a proxy and without following redirects.
func checkURL(ctx context.Context, u string, timeout time.Duration, stdout io.Writer) error {
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return healthError{fmt.Sprintf("--url %q: want an http:// or https:// URL", u)}
	}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       timeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return healthError{oneLine(err.Error())}
	}
	resp, err := client.Do(req)
	if err != nil {
		return unhealthy("%s", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return unhealthy("%s answered %s: %s", u, resp.Status, firstLine(body))
	}
	fmt.Fprintf(stdout, "ok: %s answered %s\n", u, resp.Status)
	return nil
}
