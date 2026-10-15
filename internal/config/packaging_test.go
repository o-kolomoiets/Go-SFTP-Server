// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// packaging is the directory of the files the release archives and the
// packages install (ADR 0011).
var packaging = filepath.Join("..", "..", "packaging")

// unitFile is a parsed systemd unit file or drop-in: the values of each
// "Section.Key", in order, since keys such as SystemCallFilter= add up.
type unitFile map[string][]string

func parseUnit(t *testing.T, name string) unitFile {
	t.Helper()
	f, err := os.Open(filepath.Join(packaging, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	u := unitFile{}
	section := ""
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok || section == "" || strings.HasSuffix(line, `\`) {
				t.Fatalf("%s:%d: not a KEY=VALUE line in a section: %q", name, n, line)
			}
			u[section+"."+k] = append(u[section+"."+k], v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return u
}

// one returns the only value of key.
func (u unitFile) one(t *testing.T, key string) string {
	t.Helper()
	if vs := u[key]; len(vs) == 1 {
		return vs[0]
	}
	t.Fatalf("%s: want one value, have %q", key, u[key])
	return ""
}

// words returns the space-separated values of every key assignment.
func (u unitFile) words(key string) []string {
	var ws []string
	for _, v := range u[key] {
		ws = append(ws, strings.Fields(v)...)
	}
	return ws
}

// lines returns the fields of the lines of a sysusers.d or tmpfiles.d file
// that start with typ, keeping a "quoted field" together.
func lines(t *testing.T, name, typ string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(packaging, name))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for l := range strings.SplitSeq(string(data), "\n") {
		var fields []string
		for i, part := range strings.Split(l, `"`) {
			if i%2 == 1 {
				fields = append(fields, part)
			} else {
				fields = append(fields, strings.Fields(part)...)
			}
		}
		if len(fields) > 0 && fields[0] == typ {
			out = append(out, fields)
		}
	}
	return out
}

// loadPackaged loads packaging/config.toml as installed in /etc/gosftpd,
// below root: absolute Unix paths are not absolute on Windows. unix maps a
// path of the result back to the path on the installed system.
func loadPackaged(t *testing.T) (c *Config, root string, unix func(string) string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(packaging, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	root = t.TempDir()
	etc := filepath.Join(root, "etc", "gosftpd")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	rooted := strings.ReplaceAll(string(data), `"/`, `"`+filepath.ToSlash(root)+"/")
	file := filepath.Join(etc, "config.toml")
	if err := os.WriteFile(file, []byte(rooted), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = Load(file); err != nil {
		t.Fatal(err)
	}
	unix = func(p string) string {
		rel, err := filepath.Rel(root, filepath.FromSlash(p))
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatalf("%s is not below %s", p, root)
		}
		return "/" + filepath.ToSlash(rel)
	}
	return c, root, unix
}

// below reports whether p is dir or lies below it.
func below(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// The packaged configuration validates, and passes --check-fs once
// gosftpd.tmpfiles has created its directories: before the first start,
// without the state directory, as docs/install.md has it.
func TestPackagedConfig(t *testing.T) {
	t.Parallel()

	c, root, _ := loadPackaged(t)
	warns := mustValidate(t, c)
	if want := []string{"users: no users configured: nobody can log in"}; !slices.Equal(warns, want) {
		t.Errorf("warnings %q, want %q", warns, want)
	}
	if !slices.Equal(c.Include, []string{"users.d/*.toml"}) || len(c.Mounts) != 1 || !c.Server.HostKeyAutoGenerate {
		t.Errorf("not the minimal configuration of ROADMAP §9.4: %+v", c)
	}
	tmpfiles := lines(t, "gosftpd.tmpfiles", "d")
	if len(tmpfiles) == 0 {
		t.Fatal("gosftpd.tmpfiles creates no directory")
	}
	for _, l := range tmpfiles {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(l[1])), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if warns, err := c.CheckFS(); err != nil {
		t.Errorf("CheckFS: %v (warnings %q)", err, warns)
	}
}

// The packaged configuration, the unit and the sysusers and tmpfiles files
// agree (ADR 0011).
func TestPackagingAgrees(t *testing.T) {
	t.Parallel()

	c, _, unix := loadPackaged(t)
	unit := parseUnit(t, "systemd/gosftpd.service")

	if got, want := unit.one(t, "Service.ExecStart"), "/usr/bin/gosftpd serve --config /etc/gosftpd/config.toml"; got != want {
		t.Errorf("ExecStart=%s, want %s", got, want)
	}
	// docs/install.md is the documentation until the man page exists (M5).
	doc := unit.one(t, "Unit.Documentation")
	if !strings.HasPrefix(doc, "https://github.com/o-kolomoiets/go-sftp-server/blob/main/") {
		t.Errorf("Documentation=%s", doc)
	} else if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(strings.TrimPrefix(doc, "https://github.com/o-kolomoiets/go-sftp-server/blob/main/")))); err != nil {
		t.Errorf("Documentation=%s: %v", doc, err)
	}

	// The audit log is in LogsDirectory=, the host keys in StateDirectory=.
	if got, want := path.Dir(unix(c.Audit.Output)), "/var/log/"+unit.one(t, "Service.LogsDirectory"); got != want {
		t.Errorf("audit.output is in %s, LogsDirectory= is %s", got, want)
	}
	for _, k := range c.Server.HostKeys {
		if got, want := path.Dir(unix(k)), "/var/lib/"+unit.one(t, "Service.StateDirectory"); got != want {
			t.Errorf("host key in %s, StateDirectory= is %s", got, want)
		}
	}

	// Every mount is writable for the unit, ordered after its file system,
	// and created by tmpfiles: without the directory, ReadWritePaths=-
	// is skipped and the mount is read-only.
	var writable []string
	for _, p := range unit.words("Service.ReadWritePaths") {
		writable = append(writable, strings.TrimPrefix(p, "-"))
	}
	var created []string
	for _, l := range lines(t, "gosftpd.tmpfiles", "d") {
		created = append(created, l[1])
	}
	for name, m := range c.Mounts {
		p := unix(m.Path)
		if !slices.ContainsFunc(writable, func(d string) bool { return below(p, d) }) {
			t.Errorf("mount %s (%s) is not under ReadWritePaths= %q", name, p, writable)
		}
		if !slices.ContainsFunc(unit.words("Unit.RequiresMountsFor"), func(d string) bool { return below(p, d) }) {
			t.Errorf("mount %s (%s) is not under RequiresMountsFor=", name, p)
		}
		if !slices.ContainsFunc(created, func(d string) bool { return below(p, d) }) {
			t.Errorf("mount %s (%s) is not under a directory of gosftpd.tmpfiles", name, p)
		}
	}
	if !slices.Contains(created, path.Dir(unix(c.Audit.Output))) {
		t.Errorf("gosftpd.tmpfiles does not create %s: config validate --check-fs fails before the first start", path.Dir(unix(c.Audit.Output)))
	}

	// The stop may take shutdown_timeout + 10 s (hooks, the audit log);
	// gosftpd asks for more when a reload raised it (EXTEND_TIMEOUT_USEC).
	stop, err := strconv.Atoi(unit.one(t, "Service.TimeoutStopSec"))
	if err != nil {
		t.Fatalf("TimeoutStopSec= is not a number of seconds: %v", err)
	}
	for _, d := range []Duration{Default().Server.ShutdownTimeout, c.Server.ShutdownTimeout} {
		if need := time.Duration(d) + 10*time.Second; time.Duration(stop)*time.Second < need {
			t.Errorf("TimeoutStopSec=%d is below shutdown_timeout %v + 10 s", stop, time.Duration(d))
		}
	}

	// Landlock's system calls are allowed by name: @system-service has
	// none of them, and @sandbox exists only from systemd 254.
	var allowed, denied []string
	for _, v := range unit["Service.SystemCallFilter"] {
		if after, ok := strings.CutPrefix(v, "~"); ok {
			denied = append(denied, strings.Fields(after)...)
		} else {
			allowed = append(allowed, strings.Fields(v)...)
		}
	}
	for _, call := range []string{"landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"} {
		if !slices.Contains(allowed, call) {
			t.Errorf("SystemCallFilter= does not allow %s", call)
		}
	}
	if slices.Contains(allowed, "@sandbox") || !slices.Contains(denied, "@privileged") || !slices.Contains(denied, "@resources") {
		t.Errorf("SystemCallFilter= allows %q, denies %q", allowed, denied)
	}
	// Exit status 2 is a configuration error: a restart does not fix it.
	if unit.one(t, "Service.RestartPreventExitStatus") != "2" || unit.one(t, "Service.Type") != "notify-reload" ||
		unit.one(t, "Service.KillMode") != "mixed" {
		t.Error("RestartPreventExitStatus=2, Type=notify-reload and KillMode=mixed (ADR 0010) are required")
	}

	// The user: as the unit runs it, with the home "/" rather than the
	// state directory, which systemd would make $HOME.
	users := lines(t, "gosftpd.sysusers", "u")
	if len(users) != 1 {
		t.Fatalf("gosftpd.sysusers: %q", users)
	}
	if u := users[0]; u[1] != unit.one(t, "Service.User") || u[1] != unit.one(t, "Service.Group") || len(u) != 5 || u[4] != "-" {
		t.Errorf("gosftpd.sysusers: %q; User=%s", u, unit.one(t, "Service.User"))
	}
	for _, l := range lines(t, "gosftpd.tmpfiles", "d") {
		if len(l) != 6 || l[2] != "0750" || l[3] != users[0][1] || l[4] != users[0][1] {
			t.Errorf("gosftpd.tmpfiles: %q", l)
		}
	}
}

// The drop-in for systemd before 253 replaces the two settings that need
// Type=notify-reload, and nothing else.
func TestLegacyNotifyDropIn(t *testing.T) {
	t.Parallel()

	u := parseUnit(t, "systemd/legacy-notify.conf")
	want := unitFile{"Service.Type": {"notify"}, "Service.ExecReload": {"/bin/kill -HUP $MAINPID"}}
	if len(u) != len(want) {
		t.Errorf("legacy-notify.conf sets %v, want %v", u, want)
	}
	for k, v := range want {
		if !slices.Equal(u[k], v) {
			t.Errorf("%s=%q, want %q", k, u[k], v)
		}
	}
}
