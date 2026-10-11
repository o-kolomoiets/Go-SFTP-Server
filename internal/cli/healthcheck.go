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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

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
serve would read (only that key is read), else :2022. A wildcard address is
checked on 127.0.0.1, then on ::1. A server that accepts the connection and
closes it at once is alive but refuses new connections (limits, a ban, or an
unavailable audit log): that is healthy, unless --ready is given.

With --url it sends GET URL to the admin listener ([metrics] listen); any 2xx
status is healthy. Use /healthz for liveness and /readyz for readiness.`,
		Example: `  gosftpd healthcheck
  gosftpd healthcheck --address 127.0.0.1:2022 --ready
  gosftpd healthcheck --url http://127.0.0.1:9090/readyz`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return healthError{fmt.Sprintf("unexpected argument %q", args[0])}
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
	addr, err := healthAddress(o, getenv)
	if err != nil {
		return err
	}
	return checkSSH(ctx, addr, o.timeout, o.ready, stdout)
}

// healthAddress returns the SSH address to check: --address, else
// $GOSFTPD_LISTEN, else the first server.listen of the configuration file,
// else :2022.
func healthAddress(o healthOptions, getenv func(string) string) (string, error) {
	addr := o.address
	from := "--address"
	if addr == "" {
		if v := getenv(config.EnvListen); v != "" {
			addr, _, _ = strings.Cut(v, ",")
			from = "$" + config.EnvListen
		}
	}
	if addr == "" {
		path, err := config.Find(o.config, getenv)
		switch {
		case errors.Is(err, config.ErrNotFound):
		case err != nil:
			return "", healthError{oneLine(err.Error())}
		default:
			listen, err := config.ReadListen(path)
			if err != nil {
				return "", healthError{"cannot read server.listen (pass --address): " + oneLine(err.Error())}
			}
			if len(listen) > 0 {
				addr, from = listen[0], "server.listen in "+path
			}
		}
	}
	if addr == "" {
		addr, from = ":2022", "the default"
	}
	_, port, err := net.SplitHostPort(addr)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
		return "", healthError{fmt.Sprintf("%s: %q is not HOST:PORT with a port from 1 to 65535", from, addr)}
	}
	return addr, nil
}

// checkSSH connects to addr and waits for the SSH banner, without sending
// its own version: the server writes no conn.accept for such a probe.
func checkSSH(ctx context.Context, addr string, timeout time.Duration, ready bool, stdout io.Writer) error {
	host, port, _ := net.SplitHostPort(addr)
	targets := []string{addr}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		targets = []string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)}
	}
	var (
		d    net.Dialer
		conn net.Conn
		err  error
	)
	for _, target := range targets {
		if conn, err = d.DialContext(ctx, "tcp", target); err == nil {
			addr = target
			break
		}
	}
	if err != nil {
		return unhealthy("%s", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	var got []byte
	buf := make([]byte, maxBannerBytes)
	for len(got) < maxBannerBytes {
		n, err := conn.Read(buf[:maxBannerBytes-len(got)])
		got = append(got, buf[:n]...)
		switch banner(got) {
		case bannerMore:
		case bannerFound:
			fmt.Fprintf(stdout, "ok: %s sent an SSH banner\n", addr)
			return nil
		case bannerWrong:
			return unhealthy("%s answered %q, not SSH-2.0", addr, firstLine(got))
		}
		if err == nil {
			continue
		}
		var ne net.Error
		switch {
		case errors.As(err, &ne) && ne.Timeout():
			return unhealthy("%s sent no SSH banner within %s", addr, timeout)
		case len(got) > 0:
			return unhealthy("%s closed the connection after %d bytes without an SSH banner", addr, len(got))
		case ready:
			return unhealthy("%s accepted the connection and closed it without a banner: the server refuses new connections (connection limits, a ban, or an unavailable audit log)", addr)
		}
		fmt.Fprintf(stdout, "ok: %s accepted the connection and closed it without a banner: the server runs but refuses new connections (connection limits, a ban, or an unavailable audit log)\n", addr)
		return nil
	}
	return unhealthy("%s sent no SSH banner in its first %d bytes", addr, maxBannerBytes)
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
