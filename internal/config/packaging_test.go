// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"text/template"
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

	// The unit never reaches atmoz mode, as docs/migrate-from-atmoz.md
	// says: --config is strict, and ProtectHome=yes hides /home, where
	// atmoz mode looks for directories and keys (ADR 0012).
	if got, want := unit.one(t, "Service.ExecStart"), "/usr/bin/gosftpd serve --config /etc/gosftpd/config.toml"; got != want {
		t.Errorf("ExecStart=%s, want %s", got, want)
	}
	if got := unit.one(t, "Service.ProtectHome"); got != "yes" {
		t.Errorf("ProtectHome=%s, want yes", got)
	}
	// The man page that the packages install (make generate writes
	// gosftpd.1), then docs/install.md (ADR 0012).
	const blob = "https://github.com/o-kolomoiets/go-sftp-server/blob/main/"
	doc := unit.words("Unit.Documentation")
	if len(doc) != 2 || doc[0] != "man:gosftpd(1)" || !strings.HasPrefix(doc[1], blob) {
		t.Errorf("Documentation=%q, want man:gosftpd(1) and a page of this repository", doc)
	} else if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(strings.TrimPrefix(doc[1], blob)))); err != nil {
		t.Errorf("Documentation=%s: %v", doc[1], err)
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

// The scripts of the deb, rpm and Arch packages (ADR 0012) run in CI only on
// the systems of the packages job; this checks what can drift without a
// package: postinstall's probe is the documented one, no script enables,
// starts or restarts the service, preremove skips an upgrade by "$1" and
// disables the service also where systemd does not run, postremove deletes
// the drop-in by the unit file and not by "$1", every file of the package
// they use is in .goreleaser.yaml, and the deb's needrestart file names
// exactly gosftpd.service.
func TestPackageScripts(t *testing.T) {
	t.Parallel()

	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	// scripts holds each script without its comment lines.
	scripts := map[string]string{}
	for _, name := range []string{"postinstall", "preremove", "postremove"} {
		s := read("packaging/scripts/" + name + ".sh")
		if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "\nset -e\n") {
			t.Errorf("%s.sh: want #!/bin/sh and set -e", name)
		}
		var code strings.Builder
		for line := range strings.Lines(s) {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				code.WriteString(line)
			}
		}
		scripts[name] = code.String()
	}

	// The probe: the same unit and the same message as docs/install.md and
	// the comment of legacy-notify.conf.
	probe := regexp.MustCompile(`printf '\[Unit\][^']*' >"\$d/gosftpd-probe\.service"|grep -q '[^']*'`)
	want := probe.FindAllString(read("docs/install.md"), -1)
	if len(want) != 2 {
		t.Fatalf("docs/install.md: the probe has %q", want)
	}
	for name, text := range map[string]string{"postinstall.sh": scripts["postinstall"], "legacy-notify.conf": read("packaging/systemd/legacy-notify.conf")} {
		if got := probe.FindAllString(text, -1); !slices.Equal(got, want[:len(got)]) || len(got) == 0 {
			t.Errorf("%s: the probe is %q, docs/install.md's %q", name, got, want)
		}
	}

	// systemctl: only daemon-reload, and on a removal disable --now where
	// systemd runs, else disable, which needs no running systemd (an image
	// build, a chroot). "command -v systemctl" is a guard, not a call.
	systemctl := regexp.MustCompile(`\bcommand -v systemctl\b|\bsystemctl((?:\s+-{0,2}[a-z][a-z.-]*)*)`)
	allowed := map[string][]string{
		"postinstall": {"daemon-reload"},
		"preremove":   {"disable --now gosftpd.service", "disable gosftpd.service"},
		"postremove":  {"daemon-reload"},
	}
	for name, s := range scripts {
		var calls []string
		for _, m := range systemctl.FindAllStringSubmatch(s, -1) {
			if !strings.HasPrefix(m[0], "command") {
				calls = append(calls, strings.TrimSpace(m[1]))
			}
		}
		if !slices.Equal(calls, allowed[name]) {
			t.Errorf("%s.sh runs systemctl %q, want only %q", name, calls, allowed[name])
		}
		for _, verb := range []string{"service gosftpd", "invoke-rc.d", "deb-systemd-invoke", "try-restart"} {
			if strings.Contains(s, verb) {
				t.Errorf("%s.sh uses %s", name, verb)
			}
		}
	}
	if !strings.Contains(scripts["preremove"], "case \"$1\" in\nupgrade | failed-upgrade | 1) exit 0 ;;\nesac\n") {
		t.Error(`preremove.sh does not skip an upgrade: deb passes "upgrade" and rpm 1`)
	}
	if strings.Contains(scripts["postremove"], "$1") ||
		!regexp.MustCompile(`(?s)\nif \[ ! -e /usr/lib/systemd/system/gosftpd\.service \]; then\n\trm -f /etc/systemd/system/gosftpd\.service\.d/legacy-notify\.conf\n.*?\nfi\n`).MatchString(scripts["postremove"]) {
		t.Error("postremove.sh must delete the drop-in only once the unit file is gone, not by $1")
	}

	// The files of the package that the scripts use.
	goreleaser := read(".goreleaser.yaml")
	for _, p := range regexp.MustCompile(`/(?:etc/gosftpd|usr)/[A-Za-z0-9/._-]+`).FindAllString(strings.Join(slices.Collect(maps.Values(scripts)), "\n"), -1) {
		if !strings.Contains(goreleaser, "dst: "+p+",") && !strings.Contains(goreleaser, "dst: "+p+" ") {
			t.Errorf("the scripts use %s, which .goreleaser.yaml does not install", p)
		}
	}

	// needrestart reads Perl; the regular expression is also Go's.
	m := regexp.MustCompile(`(?m)^\$nrconf\{override_rc\}\{qr\((.+)\)\} = 0;$`).FindStringSubmatch(read("packaging/needrestart.conf"))
	if m == nil {
		t.Fatal("packaging/needrestart.conf does not set $nrconf{override_rc}{qr(...)} = 0")
	}
	re := regexp.MustCompile(m[1])
	for unit, match := range map[string]bool{"gosftpd.service": true, "xgosftpd.service": false, "gosftpdXservice": false, "gosftpd.service.d": false} {
		if re.MatchString(unit) != match {
			t.Errorf("needrestart.conf: qr(%s) matches %s: %t", m[1], unit, !match)
		}
	}
}

// license is what go-licenses v2.0.1 passes to a report template for each
// module and license (libraryDataFlat in its report.go).
type license struct {
	Name, Version, LicensePath, LicenseURL, LicenseName string
}

func (l license) LicenseText() (string, error) {
	data, err := os.ReadFile(l.LicensePath)
	return string(data), err
}

// The template of THIRD_PARTY_LICENSES prints each module once, with its
// version, license and license text, never the URL that go-licenses looks
// up online, and libcap/psx, which go-licenses lists under both of its
// licenses, only under BSD-3-Clause (ADR 0012).
func TestThirdPartyLicensesTemplate(t *testing.T) {
	t.Parallel()

	tpl, err := os.ReadFile(filepath.Join(packaging, "third_party_licenses.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("").Parse(string(tpl)) // as go-licenses parses it
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The names differ in more than case: macOS and Windows file systems
	// ignore case.
	file := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	toml := license{"github.com/BurntSushi/toml", "v1.6.0", file("toml-COPYING", "MIT text\n"), "https://example.com/toml", "MIT"}
	psx := file("psx-License", "BSD-3-Clause or GPL-2.0 text\n")
	psxGPL := license{"kernel.org/pub/linux/libs/security/libcap/psx", "v1.2.77", psx, "Unknown", "GPL-2.0"}
	psxBSD := psxGPL
	psxBSD.LicenseName = "BSD-3-Clause"
	sys := license{"golang.org/x/sys", "v0.49.0", file("sys-LICENSE", "BSD text without a final newline"), "https://example.com/sys", "BSD-3-Clause"}
	other := license{"example.com/other", "v1.0.0", file("other-LICENSE", "Apache text\n"), "Unknown", "Apache-2.0"}

	entry := func(l license, text string) string {
		return "\n" + strings.Repeat("=", 80) + "\n" + l.Name + " " + l.Version + "\nLicense: " + l.LicenseName + "\n\n" + text
	}
	header := "gosftpd is licensed under the Apache License 2.0 (see LICENSE). Its binary\n" +
		"includes the following Go modules and, last, the Go standard library and\n" +
		"runtime, each under the license named with it.\n"
	for _, tt := range []struct {
		name string
		libs []license
		want string
	}{
		{
			"go-licenses' order",
			[]license{toml, psxGPL, psxBSD, sys, other},
			header + entry(toml, "MIT text\n") + entry(psxBSD, "BSD-3-Clause or GPL-2.0 text\n") +
				entry(sys, "BSD text without a final newline") + entry(other, "Apache text\n"),
		},
		{
			"psx BSD first",
			[]license{psxBSD, psxGPL, toml},
			header + entry(psxBSD, "BSD-3-Clause or GPL-2.0 text\n") + entry(toml, "MIT text\n"),
		},
		{"none", nil, header},
	} {
		var out strings.Builder
		if err := tmpl.Execute(&out, tt.libs); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if out.String() != tt.want {
			t.Errorf("%s:\n%s\nwant:\n%s", tt.name, out.String(), tt.want)
		}
		if strings.Contains(out.String(), "example.com/toml") || strings.Contains(out.String(), "Unknown") {
			t.Errorf("%s: the output names a license URL:\n%s", tt.name, out.String())
		}
	}
}
