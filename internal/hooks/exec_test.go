// SPDX-License-Identifier: Apache-2.0

//go:build unix

package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
)

// runOne runs one event through an exec hook and waits for it.
func runOne(t *testing.T, s Spec, e *Event) (*obs.Metrics, string) {
	t.Helper()
	m := obs.NewMetrics("test")
	log, logs := testLog()
	d := New(Options{Log: log, Metrics: m})
	s.Name, s.Concurrency, s.Queue = "x", 1, DefaultQueue
	if len(s.On) == 0 {
		s.On = []string{e.Name}
	}
	d.Update([]Spec{s})
	d.Notify(e)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var done float64
		for _, r := range obs.HookResults {
			done += value(m, `gosftpd_hook_deliveries_total{result="`+r+`",type="exec"}`)
		}
		if done > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.Close(time.Now().Add(5 * time.Second))
	return m, logs.String()
}

func sh(script string, timeout time.Duration) Spec {
	return Spec{Exec: &Exec{Argv: []string{"/bin/sh", "-c", script}, Timeout: timeout}}
}

// fileEvent creates a file named name in a new directory and returns an
// upload event for it.
func fileEvent(t *testing.T, name string) (*Event, string) {
	t.Helper()
	dir := t.TempDir()
	host := filepath.Join(dir, name)
	if err := os.WriteFile(host, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(host)
	if err != nil {
		t.Fatal(err)
	}
	e := upload("alice", "/"+name)
	e.HostPath, e.Info = host, fi
	return e, dir
}

// Names from clients reach the program as data: the environment and stdin
// hold them byte for byte, nothing is run, and nothing else is touched.
func TestExecHostileNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"*", "a b", "line\nbreak", "-rf", "$(touch pwned)", "`touch pwned`", "'; touch pwned; '"} {
		e, dir := fileEvent(t, name)
		for _, other := range []string{"payroll-a.csv", "payroll-b.csv"} {
			if err := os.WriteFile(filepath.Join(dir, other), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := filepath.Join(t.TempDir(), "out")
		// The documented pattern: quoted variables, -- before names.
		script := `mkdir -p -- "$OUT.d" && mv -- "$GOSFTPD_HOST_PATH" "$OUT.d/" && printf '%s' "$GOSFTPD_FINAL_PATH" > "$OUT"`
		s := sh(strings.ReplaceAll(script, "$OUT", out), 10*time.Second)
		m, logs := runOne(t, s, e)
		if v := value(m, `gosftpd_hook_deliveries_total{result="ok",type="exec"}`); v != 1 {
			t.Fatalf("%q: ok = %v\n%s", name, v, logs)
		}
		got, err := os.ReadFile(out)
		if err != nil || string(got) != "/"+name {
			t.Errorf("%q: GOSFTPD_FINAL_PATH = %q (%v)", name, got, err)
		}
		moved, _ := os.ReadDir(out + ".d")
		left, _ := os.ReadDir(dir)
		if len(moved) != 1 || moved[0].Name() != name || len(left) != 2 {
			t.Errorf("%q: moved %v, left %v", name, moved, left)
		}
		for _, d := range []string{dir, "/", out + ".d"} {
			if _, err := os.Stat(filepath.Join(d, "pwned")); err == nil {
				t.Errorf("%q: a command ran", name)
			}
		}
	}
}

func TestExecEnvironment(t *testing.T) {
	t.Setenv("PATH", "relative:/usr/bin::/bin:.")
	e, _ := fileEvent(t, "r.pdf")
	e.Name, e.TargetPath, e.Path = "fs.rename", "/r.pdf", "/r.pdf.filepart"
	out := filepath.Join(t.TempDir(), "env")
	s := sh(`{ env; pwd; cat; } > `+out, 10*time.Second)
	if _, logs := runOne(t, s, e); !strings.Contains(logs, "hook ran") {
		t.Fatalf("hook did not run:\n%s", logs)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"PATH=/usr/bin:/bin\n", "GOSFTPD_EVENT=fs.rename\n", "GOSFTPD_USER=alice\n", "GOSFTPD_MOUNT=inbox\n",
		"GOSFTPD_PATH=/r.pdf.filepart\n", "GOSFTPD_FINAL_PATH=/r.pdf\n", "GOSFTPD_TARGET_PATH=/r.pdf\n",
		"GOSFTPD_HOST_PATH=" + e.HostPath + "\n", "GOSFTPD_CONN_ID=c1\n", "\n/\n", string(e.Line),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "HOME=") {
		t.Errorf("gosftpd's environment leaked:\n%s", got)
	}
}

// The identity check skips a run whose file was replaced, also by a
// symlink, or removed.
func TestExecIdentity(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"symlink", "replaced", "removed"} {
		e, dir := fileEvent(t, "a.pdf")
		marker := filepath.Join(dir, "ran")
		switch change {
		case "symlink":
			_ = os.Remove(e.HostPath)
			if err := os.Symlink("/etc/hostname", e.HostPath); err != nil {
				t.Fatal(err)
			}
		case "replaced":
			if err := os.Rename(e.HostPath, e.HostPath+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.HostPath, []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
		case "removed":
			_ = os.Remove(e.HostPath)
		}
		m, logs := runOne(t, sh("touch "+marker, 10*time.Second), e)
		if v := value(m, `gosftpd_hook_deliveries_total{result="skipped",type="exec"}`); v != 1 {
			t.Errorf("%s: skipped = %v\n%s", change, v, logs)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s: the hook ran", change)
		}
	}
	// fs.remove has no file to check.
	e := upload("alice", "/gone")
	e.Name, e.Gone = "fs.remove", true
	if m, _ := runOne(t, sh("true", 10*time.Second), e); value(m, `gosftpd_hook_deliveries_total{result="ok",type="exec"}`) != 1 {
		t.Error("fs.remove hook did not run")
	}
}

// The timeout kills the whole process group, and processes a hook leaves
// behind cannot hold a worker.
func TestExecLifetime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, script string
		timeout      time.Duration
		result       string
		max          time.Duration
	}{
		{"timeout", "sleep 30", time.Second, "failed", 5 * time.Second},
		{"background child", "sleep 30 & echo started", 10 * time.Second, "ok", 5 * time.Second},
		{"setsid grandchild", "setsid sleep 30 & sleep 0.2", 10 * time.Second, "ok", 5 * time.Second},
		{"exit status", "echo out; echo err >&2; exit 3", 10 * time.Second, "failed", 5 * time.Second},
		{"1 MiB of output", "head -c 1048576 /dev/zero; true", 10 * time.Second, "ok", 5 * time.Second},
	}
	for _, c := range cases {
		if strings.HasPrefix(c.script, "setsid ") {
			if _, err := exec.LookPath("setsid"); err != nil {
				t.Logf("%s: no setsid here", c.name) // macOS
				continue
			}
		}
		e, _ := fileEvent(t, "a")
		start := time.Now()
		m, logs := runOne(t, sh(c.script, c.timeout), e)
		if el := time.Since(start); el > c.max {
			t.Errorf("%s: took %v", c.name, el)
		}
		if v := value(m, `gosftpd_hook_deliveries_total{result="`+c.result+`",type="exec"}`); v != 1 {
			t.Errorf("%s: %s = %v\n%s", c.name, c.result, v, logs)
		}
		if c.name == "exit status" && (!strings.Contains(logs, "exit status 3") || !strings.Contains(logs, "stderr=") || !strings.Contains(logs, "err")) {
			t.Errorf("exit status: log %s", logs)
		}
		if c.name == "timeout" && !strings.Contains(logs, "timed out after 1s") {
			t.Errorf("timeout: log %s", logs)
		}
	}
}

func TestCapWriter(t *testing.T) {
	t.Parallel()
	var w capWriter
	for range 10 {
		if n, err := w.Write(make([]byte, 1000)); n != 1000 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if len(w.b) != outputCap {
		t.Errorf("kept %d bytes", len(w.b))
	}
}

func TestCleanPath(t *testing.T) {
	t.Parallel()
	if got := cleanPath(""); got != defaultPath {
		t.Errorf("empty PATH -> %q", got)
	}
	if got := cleanPath(".:bin:/usr/bin"); got != "/usr/bin" {
		t.Errorf("-> %q", got)
	}
}

// A process the hook leaves in its group is killed when the hook exits.
func TestExecKillsLeftovers(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("needs /proc")
	}
	e, dir := fileEvent(t, "a")
	pidFile := filepath.Join(dir, "pid")
	m, logs := runOne(t, sh("sleep 30 & echo $! > "+pidFile, 10*time.Second), e)
	if v := value(m, `gosftpd_hook_deliveries_total{result="ok",type="exec"}`); v != 1 {
		t.Fatalf("ok = %v\n%s", v, logs)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	stat := "/proc/" + strings.TrimSpace(string(b)) + "/stat"
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := os.ReadFile(stat)
		if err != nil || strings.Contains(string(s), ") Z ") {
			return // gone, or dead and waiting to be reaped
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background process lives: %s", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A program that became writable by others after start is not run.
func TestExecUntrustedProgram(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	marker := filepath.Join(dir, "ran")
	if err := os.WriteFile(script, []byte("touch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o766); err != nil {
		t.Fatal(err)
	}
	e, _ := fileEvent(t, "a")
	m, logs := runOne(t, Spec{Exec: &Exec{Argv: []string{"/bin/sh", script}, Timeout: 10 * time.Second}}, e)
	if v := value(m, `gosftpd_hook_deliveries_total{result="failed",type="exec"}`); v != 1 {
		t.Errorf("failed = %v\n%s", v, logs)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("an untrusted script ran")
	}
	if !strings.Contains(logs, "writable by group or others") {
		t.Errorf("log: %s", logs)
	}
}

// A program still running when the hooks' share of the shutdown ends is
// killed, and its event is counted as dropped and logged for replay.
func TestExecKilledAtShutdownIsDropped(t *testing.T) {
	t.Parallel()
	m := obs.NewMetrics("test")
	log, logs := testLog()
	d := New(Options{Log: log, Metrics: m})
	s := sh("sleep 30", time.Minute)
	s.Name, s.On, s.Concurrency, s.Queue = "x", []string{"fs.upload"}, 1, DefaultQueue
	d.Update([]Spec{s})
	e, _ := fileEvent(t, "report.pdf")
	d.Notify(e)
	time.Sleep(300 * time.Millisecond) // running
	start := time.Now()
	d.Close(time.Now().Add(200 * time.Millisecond))
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("Close took %v", el)
	}
	if v := value(m, `gosftpd_hook_deliveries_total{result="dropped",type="exec"}`); v != 1 {
		t.Errorf("dropped = %v, failed = %v", v, value(m, `gosftpd_hook_deliveries_total{result="failed",type="exec"}`))
	}
	if !strings.Contains(logs.String(), "path=/report.pdf") || !strings.Contains(logs.String(), "mount=inbox") {
		t.Errorf("not logged for replay:\n%s", logs)
	}
}
