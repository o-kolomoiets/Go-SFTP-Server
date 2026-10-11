// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/hooks"
)

// maxSecretFile bounds what is read of a webhook secret file.
const maxSecretFile = 4096

func (c *Config) validateHooks(p *problems) {
	names := map[string]bool{}
	for i, h := range c.Hooks {
		k := func(parts ...string) string { return hookKey(i, parts...) }
		if h == nil {
			continue
		}
		switch {
		case h.Name == "":
			p.errorf(k("name"), "required")
		case strings.ContainsFunc(h.Name, func(r rune) bool { return r < ' ' || r == 0x7f }):
			p.errorf(k("name"), "contains control characters")
		case names[h.Name]:
			p.errorf(k("name"), "%q is used by another hook", h.Name)
		}
		names[h.Name] = true
		if len(h.On) == 0 {
			p.errorf(k("on"), "required: one or more of %s", strings.Join(hooks.Events, ", "))
		}
		for _, e := range h.On {
			if !slices.Contains(hooks.Events, e) {
				p.errorf(k("on"), "unknown event %q; want one of %s", e, strings.Join(hooks.Events, ", "))
			}
		}
		for _, m := range h.Mounts {
			if c.mountName(m) == "" {
				p.errorf(k("mounts"), "no mount named %q", m)
			}
		}
		for _, list := range []struct {
			name     string
			patterns []string
		}{{"glob", h.Glob}, {"exclude", h.Exclude}} {
			for _, pat := range list.patterns {
				if _, err := path.Match(pat, ""); err != nil || pat == "" || strings.Contains(pat, "/") {
					p.errorf(k(list.name), "invalid pattern %q: a file name pattern such as \"*.pdf\"", pat)
				}
			}
		}
		if d := time.Duration(h.Delay); d < 0 || d > hooks.MaxDelay {
			p.errorf(k("delay"), "must be between 0 and %s", hooks.MaxDelay)
		}
		if h.Concurrency < 0 || h.Concurrency > hooks.MaxConcurrency {
			p.errorf(k("concurrency"), "must be between 1 and %d", hooks.MaxConcurrency)
		}
		if h.Queue < 0 || h.Queue > hooks.MaxQueue {
			p.errorf(k("queue"), "must be between 1 and %d", hooks.MaxQueue)
		}
		switch {
		case h.Exec != nil && h.Webhook != nil:
			p.errorf(k(), "has both exec and webhook; a hook has exactly one")
		case h.Exec != nil:
			validateExec(p, h.Exec, k)
		case h.Webhook != nil:
			validateWebhook(p, h.Webhook, k)
		default:
			p.errorf(k(), "needs exec or webhook")
		}
	}
}

// hookKey names a key of the i-th [[hooks]] table, such as hooks[0].name.
func hookKey(i int, parts ...string) string {
	k := "hooks[" + strconv.Itoa(i) + "]"
	if len(parts) > 0 {
		k += "." + key(parts...)
	}
	return k
}

// checkHooks checks the files of every hook at start (ADR 0010).
func (c *Config) checkHooks(p *problems) {
	for i, h := range c.Hooks {
		if h == nil {
			continue
		}
		_, argvErr, secretErr := HookFiles(h)
		if argvErr != nil {
			p.errorf(hookKey(i, "exec", "argv"), "%v", argvErr)
		}
		if secretErr != nil {
			p.errorf(hookKey(i, "webhook", "secret_file"), "%v", secretErr)
		}
	}
}

func validateExec(p *problems, e *HookExec, k func(...string) string) {
	switch {
	case len(e.Argv) == 0:
		p.errorf(k("exec", "argv"), "required: the program and its arguments, never run through a shell")
	case !filepath.IsAbs(e.Argv[0]):
		p.errorf(k("exec", "argv"), "%q: the program must be an absolute path", e.Argv[0])
	}
	for _, a := range e.Argv {
		if strings.IndexByte(a, 0) >= 0 {
			p.errorf(k("exec", "argv"), "contains a NUL byte")
		}
	}
	if t := time.Duration(e.Timeout); t < 0 || t > hooks.MaxExecTime {
		p.errorf(k("exec", "timeout"), "must be between 1s and %s", hooks.MaxExecTime)
	}
}

func validateWebhook(p *problems, w *HookWebhook, k func(...string) string) {
	u, err := url.Parse(w.URL)
	switch {
	case w.URL == "":
		p.errorf(k("webhook", "url"), "required")
	case err != nil:
		p.errorf(k("webhook", "url"), "invalid URL")
	case u.Scheme != "https" && u.Scheme != "http":
		p.errorf(k("webhook", "url"), "scheme %q: want https (or http)", u.Scheme)
	case u.Host == "":
		p.errorf(k("webhook", "url"), "no host")
	case u.User != nil:
		p.errorf(k("webhook", "url"), "user info in the URL is not allowed; authenticate the receiver with the signature")
	case u.Scheme == "http" && !loopbackHost(u.Hostname()):
		p.warnf(k("webhook", "url"), "http sends events in the clear; use https")
	}
	if w.SecretFile == "" {
		p.errorf(k("webhook", "secret_file"), "required: a file with at least %d bytes, such as the output of openssl rand -hex 32", hooks.MinSecretLen)
	}
	if t := time.Duration(w.Timeout); t < 0 || t > hooks.MaxHookTime {
		p.errorf(k("webhook", "timeout"), "must be between 1s and %s", hooks.MaxHookTime)
	}
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mountName returns the configured name of a mount, compared
// case-insensitively, or "".
func (c *Config) mountName(name string) string {
	if _, ok := c.Mounts[name]; ok {
		return name
	}
	for m := range c.Mounts {
		if strings.EqualFold(m, name) {
			return m
		}
	}
	return ""
}

// HookSpec converts a validated hook into its runtime form, with the
// mounts' configured names and the defaults; the secret is read
// separately (HookFiles).
func (c *Config) HookSpec(h *Hook, secret []byte) hooks.Spec {
	s := hooks.Spec{
		Name:        h.Name,
		On:          slices.Clone(h.On),
		Glob:        slices.Clone(h.Glob),
		Exclude:     slices.Clone(h.Exclude),
		Delay:       time.Duration(h.Delay),
		Concurrency: h.Concurrency,
		Queue:       h.Queue,
	}
	for _, m := range h.Mounts {
		s.Mounts = append(s.Mounts, c.mountName(m))
	}
	if s.Concurrency == 0 {
		s.Concurrency = 1
	}
	if s.Queue == 0 {
		s.Queue = hooks.DefaultQueue
		if s.Delay > 0 {
			s.Queue = hooks.MaxQueue // a delayed hook holds every event of the last delay
		}
	}
	if h.Exec != nil {
		t := time.Duration(h.Exec.Timeout)
		if t == 0 {
			t = hooks.DefaultExecTime
		}
		s.Exec = &hooks.Exec{Argv: slices.Clone(h.Exec.Argv), Timeout: t}
	} else {
		t := time.Duration(h.Webhook.Timeout)
		if t == 0 {
			t = hooks.DefaultHookTime
		}
		s.Webhook = &hooks.Webhook{URL: h.Webhook.URL, Secret: secret, Timeout: t}
	}
	return s
}

// HookFiles checks the files of a hook and reads its secret. argvErr: the
// program is missing or not executable, or an existing argv file belongs
// to someone else or can be written by group or others. secretErr: the
// secret file has such an owner or mode, or does not hold at least
// hooks.MinSecretLen printable ASCII bytes. On reload the two are handled
// differently (ADR 0010).
func HookFiles(h *Hook) (secret []byte, argvErr, secretErr error) {
	if h.Exec != nil {
		argvErr = checkArgv(h.Exec.Argv)
	}
	if h.Webhook != nil {
		secret, secretErr = readSecret(h.Webhook.SecretFile)
	}
	return secret, argvErr, secretErr
}

func checkArgv(argv []string) error {
	var errs []error
	for i, a := range argv {
		if !filepath.IsAbs(a) {
			continue
		}
		fi, err := os.Stat(a)
		switch {
		case err != nil && i == 0:
			errs = append(errs, fmt.Errorf("%s: %w", a, err))
			continue
		case err != nil, fi.IsDir() && i > 0:
			continue // a file that does not exist yet, or a directory argument
		case i == 0 && (!fi.Mode().IsRegular() || !executable(fi)):
			errs = append(errs, fmt.Errorf("%s: not an executable file", a))
			continue
		case !fi.Mode().IsRegular():
			continue // a device such as /dev/null
		}
		if err := checkOwner(a, fi); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func readSecret(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	if err := checkSecretMode(name, fi); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxSecretFile)
	}
	b = bytes.Trim(b, " \t\r\n\v\f")
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("%s: the secret must be printable ASCII (saved as UTF-16 or with a BOM?)", name)
		}
	}
	if len(b) < hooks.MinSecretLen {
		return nil, fmt.Errorf("%s: the secret has %d bytes; it needs at least %d (openssl rand -hex 32)", name, len(b), hooks.MinSecretLen)
	}
	return b, nil
}

// hookFiles are the files of the hooks that gosftpd trusts: the absolute
// argv elements that are not directories, and the secret files.
func (c *Config) hookFiles() []string {
	var files []string
	for _, h := range c.Hooks {
		if h == nil {
			continue
		}
		if h.Exec != nil {
			for _, a := range h.Exec.Argv {
				if !filepath.IsAbs(a) {
					continue
				}
				if fi, err := os.Stat(a); err == nil && fi.IsDir() {
					continue
				}
				files = append(files, a)
			}
		}
		if h.Webhook != nil && h.Webhook.SecretFile != "" {
			files = append(files, h.Webhook.SecretFile)
		}
	}
	return files
}
