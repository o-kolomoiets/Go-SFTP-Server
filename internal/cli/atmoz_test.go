// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/atmoz"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
)

// pw is the password of the atmoz tests: no message may show it.
const pw = "SECRET-pw-1"

// atmozEnv isolates the test from the machine: the environment, the
// working directory and atmoz mode's paths (/home, /etc/sftp/users.conf,
// /etc/ssh, /var/lib/gosftpd, /etc/gosftpd) are in a temporary directory,
// whose home it returns. With image the image's conventions apply.
func atmozEnv(t *testing.T, image bool) string {
	t.Helper()
	isolate(t)
	noSystemConfig(t)
	t.Chdir(t.TempDir()) // no ./gosftpd.toml
	base := t.TempDir()
	set := func(p *string, v string) {
		old := *p
		*p = v
		t.Cleanup(func() { *p = old })
	}
	set(&atmozHome, filepath.Join(base, "home"))
	set(&atmozUsersFile, filepath.Join(base, "etc", "sftp", "users.conf"))
	set(&imageStateDir, filepath.Join(base, "var", "lib", "gosftpd"))
	set(&imageConfigDir, filepath.Join(base, "etc", "gosftpd"))
	keys := atmozHostKeys
	atmozHostKeys = []string{filepath.Join(base, "etc", "ssh", "ssh_host_ed25519_key"), filepath.Join(base, "etc", "ssh", "ssh_host_rsa_key")}
	t.Cleanup(func() { atmozHostKeys = keys })
	if image {
		t.Setenv(envImage, "1")
	}
	if err := os.MkdirAll(atmozHome, 0o755); err != nil {
		t.Fatal(err)
	}
	return atmozHome
}

// writeAll writes path, creating its directory, 0644 as Docker's bind
// mounts of a host file usually are.
func writeAll(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// atmozLogin logs in to addr as user.
func atmozLogin(t *testing.T, addr, user string, auth ssh.AuthMethod) (*sftpConn, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sc := &sftpConn{Client: c, conn: conn}
	t.Cleanup(sc.Close)
	return sc, nil
}

// mustLogin logs in or fails the test.
func mustLogin(t *testing.T, addr, user string, auth ssh.AuthMethod) *sftpConn {
	t.Helper()
	c, err := atmozLogin(t, addr, user, auth)
	if err != nil {
		t.Fatalf("login as %s: %v", user, err)
	}
	return c
}

// names lists dir on the server, sorted: the server lists a directory in
// the order the file system reads it, which on ext4 follows the hash of
// the names with the file system's own seed, and sftp sorts it for display.
func names(t *testing.T, c *sftpConn, dir string) []string {
	t.Helper()
	fis, err := c.ReadDir(dir)
	if err != nil {
		t.Fatalf("ls %s: %v", dir, err)
	}
	out := []string{}
	for _, fi := range fis {
		out = append(out, fi.Name())
	}
	slices.Sort(out)
	return out
}

// getFile downloads path.
func getFile(t *testing.T, c *sftpConn, path string) string {
	t.Helper()
	f, err := c.Open(path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readHost(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// noSecret fails if the server's output shows the password.
func noSecret(t *testing.T, ts *testServer) {
	t.Helper()
	for what, out := range map[string]string{"stderr": ts.stderr.String(), "stdout": ts.stdout.String()} {
		if strings.Contains(out, pw) {
			t.Errorf("%s shows the password:\n%s", what, out)
		}
	}
}

func bcryptOf(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// TestAtmozArgs: the atmoz README's simplest example, docker run IMAGE
// foo:pass:::upload, runs the root command with the spec. foo logs in with
// the password and sees /upload, stored in /home/foo/upload; a second
// upload of the same name overwrites the first; the root is read-only. The
// audit log and the hooks' mount is the directory's name, and SIGHUP is
// logged and changes nothing.
func TestAtmozArgs(t *testing.T) {
	home := atmozEnv(t, false)
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::upload")
	c := mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	if got := names(t, c, "/"); !slices.Equal(got, []string{"upload"}) {
		t.Errorf("/ lists %v", got)
	}
	for _, data := range []string{"the first version, which is longer", "second"} {
		if err := putFile(c, "/upload/a.txt", data); err != nil {
			t.Fatal(err)
		}
	}
	host := filepath.Join(home, "foo", "upload")
	if got := readHost(t, filepath.Join(host, "a.txt")); got != "second" {
		t.Errorf("a.txt = %q, want the second upload", got)
	}
	if got := names(t, c, "/upload"); !slices.Equal(got, []string{"a.txt"}) {
		t.Errorf("/upload lists %v", got)
	}
	if err := putFile(c, "/new.txt", "x"); err == nil {
		t.Error("an upload into the root succeeded")
	}
	if err := c.Mkdir("/dir"); err == nil {
		t.Error("mkdir in the root succeeded")
	}
	for _, login := range []struct {
		user string
		auth ssh.AuthMethod
	}{{"foo", ssh.Password("wrong")}, {"bar", ssh.Password(pw)}, {"foo", ssh.PublicKeys(newSigner(t))}} {
		if _, err := atmozLogin(t, ts.addr, login.user, login.auth); err == nil {
			t.Errorf("login as %s succeeded", login.user)
		}
	}

	ts.hup <- syscall.SIGHUP
	waitLog(t, ts.stderr.String, `msg="SIGHUP ignored" reason="`+atmozNoReload+`"`)
	c2 := mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	if got := getFile(t, c2, "/upload/a.txt"); got != "second" {
		t.Errorf("after SIGHUP: a.txt = %q", got)
	}
	c.Close()
	c2.Close()
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}

	logs := ts.stderr.String()
	for _, want := range []string{
		`msg="atmoz mode" users_file=0 arguments=1 sftp_users=0`,
		"argument 1 (user foo): the password is in plain text",
		"mounts:  /upload -> " + host + " (rw, on_conflict=overwrite, user foo)",
		"connect: sftp -P ",
		" foo@127.0.0.1",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %q in the log:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "uid and gid") {
		t.Error("the spec gives no uid or gid")
	}
	uploads := events(t, ts.stdout.String(), "fs.upload")
	if len(uploads) != 2 || uploads[0]["mount"] != "upload" || uploads[1]["conflict"] != "overwritten" {
		t.Errorf("fs.upload events %v", uploads)
	}
	if strings.Contains(ts.stdout.String()+logs, "atmoz1") {
		t.Errorf("the internal mount name shows:\n%s\n%s", ts.stdout.String(), logs)
	}
	noSecret(t, ts)
}

// TestAtmozImage: the README's other examples in the image, all at once.
// The users file /etc/sftp/users.conf (foo, bar and baz without
// directories, on a fresh volume), keys in /home/foo/.ssh/keys/, an
// existing volume directory (/home/baz/share), and $SFTP_USERS with a
// bcrypt hash (:e) and a plain password; serve finds no configuration
// file and serves them.
func TestAtmozImage(t *testing.T) {
	home := atmozEnv(t, true)
	writeAll(t, atmozUsersFile, "foo:123:1001:100\nbar:abc:1002:100\nbaz:xyz:1003:100\n")
	key := newSigner(t)
	writeAll(t, filepath.Join(home, "foo", ".ssh", "keys", "id_rsa.pub"), authorizedKey(key)+"\n")
	writeAll(t, filepath.Join(home, "baz", "share", "old.txt"), "on the volume")
	t.Setenv(atmoz.EnvUsers, "qux:"+bcryptOf(t, pw)+":e:1004::inbox quux:"+pw)
	ts := startRun(t, "serve", "--allow-root", "--listen", "127.0.0.1:0")

	foo := mustLogin(t, ts.addr, "foo", ssh.Password("123"))
	if got := names(t, foo, "/"); len(got) != 0 {
		t.Errorf("foo: / lists %v", got)
	}
	if err := putFile(foo, "/x", "x"); err == nil {
		t.Error("foo: an upload into the empty root succeeded")
	}
	mustLogin(t, ts.addr, "foo", ssh.PublicKeys(key))
	mustLogin(t, ts.addr, "bar", ssh.Password("abc"))
	baz := mustLogin(t, ts.addr, "baz", ssh.Password("xyz"))
	if got := names(t, baz, "/"); !slices.Equal(got, []string{"share"}) {
		t.Errorf("baz: / lists %v", got)
	}
	if got := getFile(t, baz, "/share/old.txt"); got != "on the volume" {
		t.Errorf("baz: old.txt = %q", got)
	}
	qux := mustLogin(t, ts.addr, "qux", ssh.Password(pw))
	if got := names(t, qux, "/"); !slices.Equal(got, []string{"inbox"}) {
		t.Errorf("qux: / lists %v", got)
	}
	if err := putFile(qux, "/inbox/f", "data"); err != nil {
		t.Error(err)
	}
	if got := readHost(t, filepath.Join(home, "qux", "inbox", "f")); got != "data" {
		t.Errorf("qux's upload: %q", got)
	}
	mustLogin(t, ts.addr, "quux", ssh.Password(pw))

	logs := ts.stderr.String()
	for _, want := range []string{
		`msg="atmoz mode" users_file=3 arguments=0 sftp_users=2`,
		`msg="atmoz mode: the uid and gid of user specs are ignored"`,
		atmozUsersFile + " line 1 (user foo): no directories, so the user logs in to an empty read-only root, as in atmoz; name directories in the spec's last field (user:pass:::upload) or mount them under " + filepath.Join(home, "foo"),
		"SFTP_USERS entry 2 (user quux): the password is in plain text",
		"host key: " + filepath.Join(imageStateDir, hostkey.DefaultFile) + " (generated, 0600)",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("no %q in the log:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "line 2 (user bar): the password is in plain text") {
		t.Error("a plain password of the users file is warned about")
	}
	noSecret(t, ts)
}

// TestAtmozImageHostKeys: in the image, atmoz's /etc/ssh host keys are
// served when they exist, so that clients keep their known_hosts entry;
// --state-dir and --host-key take precedence, and outside the image they
// are never used.
func TestAtmozImageHostKeys(t *testing.T) {
	atmozEnv(t, true)
	signer, err := hostkey.Generate(atmozHostKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::up")
	if logs := ts.stderr.String(); !strings.Contains(logs, "host key: "+atmozHostKeys[0]+"\n  ED25519 "+fp) {
		t.Errorf("not served from %s:\n%s", atmozHostKeys[0], logs)
	}
	ts.stop(t)

	state := t.TempDir()
	ts = startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "--state-dir", state, "foo:"+pw+":::up")
	if logs := ts.stderr.String(); !strings.Contains(logs, "host key: "+filepath.Join(state, hostkey.DefaultFile)+" (generated, 0600)") {
		t.Errorf("--state-dir:\n%s", logs)
	}
	ts.stop(t)

	t.Setenv(envImage, "")
	ts = startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::up")
	if logs := ts.stderr.String(); strings.Contains(logs, atmozHostKeys[0]) || !strings.Contains(logs, "(generated, 0600)") {
		t.Errorf("outside the image:\n%s", logs)
	}
	ts.stop(t)
}

// TestAtmozFlags: --read-only and --on-conflict apply in atmoz mode, as
// they would to a file's mounts; --users-conf adds the users of a file
// outside the image, and a user given twice keeps its first definition.
func TestAtmozFlags(t *testing.T) {
	home := atmozEnv(t, false)
	users := filepath.Join(t.TempDir(), "users.conf")
	writeAll(t, users, "# atmoz users\nfoo:"+pw+":::up\n")
	t.Setenv(atmoz.EnvUsers, "foo:other")
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "--on-conflict", "rename", "--users-conf", users, "bar:"+pw+":::up")
	c := mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	for range 2 {
		if err := putFile(c, "/up/a.txt", "data"); err != nil {
			t.Fatal(err)
		}
	}
	if got := names(t, c, "/up"); !slices.Equal(got, []string{"a (1).txt", "a.txt"}) {
		t.Errorf("--on-conflict rename: /up lists %v", got)
	}
	if _, err := atmozLogin(t, ts.addr, "foo", ssh.Password("other")); err == nil {
		t.Error("the second definition of foo logs in")
	}
	mustLogin(t, ts.addr, "bar", ssh.Password(pw))
	c.Close()
	ts.stop(t)
	for _, want := range []string{
		`msg="atmoz mode" users_file=1 arguments=1 sftp_users=0`,
		"SFTP_USERS entry 1: user foo is already defined by " + users + " line 2; skipped, as atmoz skips it",
	} {
		if !strings.Contains(ts.stderr.String(), want) {
			t.Errorf("no %q in the log:\n%s", want, ts.stderr.String())
		}
	}
	noSecret(t, ts)

	ts = startServe(t, "--listen", "127.0.0.1:0", "--read-only", "--users-conf", users)
	c = mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	if err := putFile(c, "/up/b.txt", "data"); err == nil {
		t.Error("--read-only: the upload succeeded")
	}
	if got := getFile(t, c, "/up/a.txt"); got != "data" {
		t.Errorf("--read-only: a.txt = %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, "foo", "up", "b.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("b.txt: %v", err)
	}
	c.Close()
	ts.stop(t)
}

// TestAtmozUnavailableDirectory: a directory that cannot be created is
// unavailable to its user, logged with the fix; the others work, and the
// audit log names it by its directory.
func TestAtmozUnavailableDirectory(t *testing.T) {
	home := atmozEnv(t, false)
	writeAll(t, filepath.Join(home, "foo", "blocked"), "a file where the directory would be")
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::upload,blocked")
	c := mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	if got := names(t, c, "/"); !slices.Equal(got, []string{"upload"}) {
		t.Errorf("/ lists %v", got)
	}
	c.Close()
	ts.stop(t)
	path := filepath.Join(home, "foo", "blocked")
	if want := "argument 1 (user foo): directory blocked cannot be created (" + path + " is not a directory), so it is unavailable to foo; give it a volume of its own (-v HOST_DIR:" + path + ")"; !strings.Contains(ts.stderr.String(), want) {
		t.Errorf("no %q in the log:\n%s", want, ts.stderr.String())
	}
	denied := events(t, ts.stdout.String(), "fs.denied")
	if len(denied) != 1 || denied[0]["mount"] != "blocked" || denied[0]["reason"] != "mount_unavailable" {
		t.Errorf("fs.denied events %v", denied)
	}
}

// TestAtmozUnopenableDirectory: a directory that exists but cannot be
// opened, such as a volume's host directory of another user with mode
// 0700, is unavailable to its user too, instead of stopping the start
// with the internal name of its mount; the user's other directory works.
func TestAtmozUnopenableDirectory(t *testing.T) {
	home := atmozEnv(t, false)
	up := filepath.Join(home, "foo", "upload")
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(up, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(up, 0o755) })
	if r, err := os.OpenRoot(up); err == nil {
		r.Close()
		t.Skip("a directory with mode 0000 opens: the test runs with CAP_DAC_OVERRIDE, or on Windows")
	}
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::upload,other")
	c := mustLogin(t, ts.addr, "foo", ssh.Password(pw))
	if got := names(t, c, "/"); !slices.Equal(got, []string{"other"}) {
		t.Errorf("/ lists %v", got)
	}
	c.Close()
	if code := ts.stop(t); code != exitOK {
		t.Errorf("exit %d", code)
	}
	logs := ts.stderr.String()
	if want := "argument 1 (user foo): directory upload cannot be opened (open " + up + ": permission denied), so it is unavailable to foo"; !strings.Contains(logs, want) {
		t.Errorf("no %q in the log:\n%s", want, logs)
	}
	if strings.Contains(logs, "atmoz1") {
		t.Errorf("the internal mount name shows:\n%s", logs)
	}
	noSecret(t, ts)
}

// TestAtmozModeSelection: --config and $GOSFTPD_CONFIG stay strict, in the
// image an /etc/gosftpd without config.toml never leads to atmoz mode,
// --users-conf goes only without a configuration file, --dir and
// --ephemeral, and the image's default users file is read only in the
// image. Each of these exits 2.
func TestAtmozModeSelection(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.toml")
	empty := filepath.Join(t.TempDir(), "users.conf")
	writeAll(t, empty, "# nobody\n")
	for _, tt := range []struct {
		name  string
		image bool
		env   map[string]string
		setup func(t *testing.T)
		args  []string
		want  string
	}{
		{
			name: "--config missing", env: map[string]string{atmoz.EnvUsers: "foo:" + pw}, args: []string{"serve", "--config", missing},
			want: "Error: --config: " + missing + " does not exist\n",
		},
		{
			name: "$GOSFTPD_CONFIG missing", env: map[string]string{atmoz.EnvUsers: "foo:" + pw, config.EnvConfig: missing}, args: []string{"serve"},
			want: "Error: $GOSFTPD_CONFIG: " + missing + " does not exist\n",
		},
		{
			name: "$GOSFTPD_CONFIG missing, specs", env: map[string]string{config.EnvConfig: missing}, args: []string{"foo:" + pw},
			want: "Error: $GOSFTPD_CONFIG: " + missing + " does not exist\n",
		},
		{
			name: "empty /etc/gosftpd", image: true, env: map[string]string{atmoz.EnvUsers: "foo:" + pw}, setup: mkImageConfigDir, args: []string{"serve"},
			want: "/etc/gosftpd is mounted but holds no config.toml",
		},
		{
			name: "empty /etc/gosftpd, specs", image: true, setup: mkImageConfigDir, args: []string{"foo:" + pw},
			want: "/etc/gosftpd is mounted but holds no config.toml",
		},
		{
			name: "users file outside the image", setup: writeImageUsers, args: []string{"serve"},
			want: "Error: no configuration file found (",
		},
		{
			name: "--users-conf with a file", setup: writeLocalConfig, args: []string{"serve", "--users-conf", empty},
			want: "Error: --users-conf cannot be used with a configuration file (gosftpd.toml): atmoz mode starts only without one\n",
		},
		{
			name: "--users-conf with --dir", args: []string{"serve", "--users-conf", empty, "--dir", "."},
			want: "Error: --users-conf and --dir cannot be used together",
		},
		{
			name: "--users-conf with --ephemeral", args: []string{"serve", "--users-conf", empty, "--ephemeral"},
			want: "Error: --ephemeral and --users-conf cannot be used together\n",
		},
		{
			name: "--users-conf without users", args: []string{"serve", "--users-conf", empty},
			want: "Error: --users-conf: " + empty + " holds no user specs (lines of user:pass[:e][:uid[:gid[:dir1[,dir2]...]]])\n",
		},
		{
			name: "--users-conf missing", args: []string{"serve", "--users-conf", missing},
			want: "Error: the users file: " + statError(t, missing) + "\n",
		},
		{
			name: "--authorized-keys", env: map[string]string{atmoz.EnvUsers: "foo:" + pw}, args: []string{"serve", "--authorized-keys", empty},
			want: "Error: --authorized-keys cannot be used in atmoz mode: a user's keys are the files in ",
		},
		{
			name: "--user", args: []string{"--user", "foo", "foo:" + pw},
			want: "Error: unknown flag: --user\n",
		},
		{
			name: "a bad spec", env: map[string]string{atmoz.EnvUsers: "Foo:" + pw}, args: []string{"serve"},
			want: "Error: SFTP_USERS entry 1: the user name is not one gosftpd accepts",
		},
		{
			name: "flags without specs", args: []string{"--listen", ":2222"},
			want: "Error: these flags need atmoz user specs as arguments; without specs use 'gosftpd serve'\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			atmozEnv(t, tt.image)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if tt.setup != nil {
				tt.setup(t)
			}
			code, stdout, stderr := execute(t, append(tt.args, "--allow-root")...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) || stdout != "" {
				t.Errorf("exit %d, stdout %q, stderr:\n%s\nwant it to contain %q", code, stdout, stderr, tt.want)
			}
			if strings.Contains(stderr, pw) || strings.Contains(stderr, "atmoz mode\"") {
				t.Errorf("stderr:\n%s", stderr)
			}
		})
	}
}

// TestAtmozUsersFileOnlyInImage: outside the image the default users file,
// on a host perhaps one left over from atmoz with plain passwords, is never
// read, also when an argument or $SFTP_USERS starts atmoz mode, and no
// other mode warns that it is ignored. The case "users file outside the
// image" of TestAtmozModeSelection has no other source, so it cannot tell
// the two checks apart.
func TestAtmozUsersFileOnlyInImage(t *testing.T) {
	atmozEnv(t, false)
	writeImageUsers(t) // foo
	for _, tt := range []struct {
		name, env string
		args      []string
	}{
		{"an argument", "", []string{"--allow-root", "--listen", "127.0.0.1:0", "bar:" + pw + ":::d"}},
		{"SFTP_USERS", "bar:" + pw + ":::d", []string{"serve", "--allow-root", "--listen", "127.0.0.1:0"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(atmoz.EnvUsers, tt.env)
			ts := startRun(t, tt.args...)
			mustLogin(t, ts.addr, "bar", ssh.Password(pw)).Close()
			if c, err := atmozLogin(t, ts.addr, "foo", ssh.Password(pw)); err == nil {
				c.Close()
				t.Error("foo of the default users file logs in outside the image")
			}
			ts.stop(t)
			logs := ts.stderr.String()
			if !strings.Contains(logs, `msg="atmoz mode" users_file=0 `) || strings.Contains(logs, atmozUsersFile) {
				t.Errorf("the default users file is read outside the image:\n%s", logs)
			}
			noSecret(t, ts)
		})
	}

	keys := filepath.Join(t.TempDir(), "keys")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n")
	ts := startServe(t, "--listen", "127.0.0.1:0", "--dir", t.TempDir(), "--authorized-keys", keys, "--state-dir", t.TempDir())
	ts.stop(t)
	if logs := ts.stderr.String(); strings.Contains(logs, atmozUsersFile) {
		t.Errorf("serve --dir outside the image names the default users file:\n%s", logs)
	}
}

// statError is the message of os.Stat for path, which differs between
// platforms.
func statError(t *testing.T, path string) string {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("%s exists", path)
	}
	return err.Error()
}

func mkImageConfigDir(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(imageConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeImageUsers(t *testing.T) {
	t.Helper()
	writeAll(t, atmozUsersFile, "foo:"+pw+":::up\n")
}

// writeLocalConfig writes a ./gosftpd.toml that serve accepts.
func writeLocalConfig(t *testing.T) {
	t.Helper()
	writeFile(t, "gosftpd.toml", `config_version = 1
[server]
host_keys = ["`+filepath.ToSlash(filepath.Join(t.TempDir(), "host_key"))+`"]
host_key_auto_generate = true
[mounts.data]
path = "`+filepath.ToSlash(t.TempDir())+`"
[users.alice]
authorized_keys = ["`+authorizedKey(newSigner(t))+`"]
access = { data = "full" }
`)
}

// TestAtmozIgnoredSources: with specs as arguments a configuration file
// is ignored, with a warning that names it; in the other modes
// $SFTP_USERS and the image's users file are ignored with a warning that
// names the source and never shows its value.
func TestAtmozIgnoredSources(t *testing.T) {
	atmozEnv(t, true)
	writeLocalConfig(t)
	ts := startRun(t, "--allow-root", "--listen", "127.0.0.1:0", "foo:"+pw+":::up")
	mustLogin(t, ts.addr, "foo", ssh.Password(pw)).Close()
	ts.stop(t)
	if want := "the configuration file gosftpd.toml is ignored: atmoz user specs are given as arguments"; !strings.Contains(ts.stderr.String(), want) {
		t.Errorf("no %q in the log:\n%s", want, ts.stderr.String())
	}

	writeImageUsers(t)
	t.Setenv(atmoz.EnvUsers, "bar:"+pw)
	keys := filepath.Join(t.TempDir(), "keys")
	writeFile(t, keys, authorizedKey(newSigner(t))+"\n")
	for _, tt := range []struct {
		args   []string
		reason string
	}{
		{[]string{"serve"}, "serve uses the configuration file gosftpd.toml"},
		{[]string{"serve", "--dir", t.TempDir(), "--authorized-keys", keys, "--state-dir", t.TempDir()}, "--dir serves without users"},
		{[]string{"serve", "--ephemeral"}, "--ephemeral serves its own user, test"},
	} {
		ts := startRun(t, append(tt.args, "--allow-root", "--listen", "127.0.0.1:0")...)
		ts.stop(t)
		logs := ts.stderr.String()
		for _, src := range []string{"$SFTP_USERS", atmozUsersFile} {
			if want := src + " is ignored: " + tt.reason; !strings.Contains(logs, want) {
				t.Errorf("%q: no %q in the log:\n%s", tt.args, want, logs)
			}
		}
		if strings.Contains(logs, "atmoz mode\"") {
			t.Errorf("%q: atmoz mode:\n%s", tt.args, logs)
		}
		noSecret(t, ts)
	}
}

// TestAtmozUsageErrors: no usage error shows an argument with ':', which
// may be an atmoz user spec with its password: a spec after serve or
// another command, a root argument that fails atmoz's test of a spec
// (with a space before it), an unknown flag that is one, and a spec taken
// as a flag's value. After a spec no argument is shown that is not one,
// except a command: it may be a word of a password with a space.
func TestAtmozUsageErrors(t *testing.T) {
	atmozEnv(t, false)
	spec := "u:" + pw + ":::upload"
	const notShown = " (the value is not shown: it contains ':', as an atmoz user spec does)\n"
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"serve", spec}, "Error: unknown command (argument 1, not shown: it looks like an atmoz user spec; give specs directly after the image name, without 'serve')\nRun 'gosftpd --help' for usage.\n"},
		{[]string{"config", "validate", spec}, "Error: unknown command (argument 1, not shown: it looks like an atmoz user spec; give specs directly after the image name, without 'config validate')\n"},
		{[]string{" " + spec}, "Error: unknown command (argument 1, not shown: it looks like an atmoz user spec, but a spec starts with the user name and ':', without white space)\n"},
		{[]string{":" + pw}, "Error: unknown command (argument 1, not shown: it looks like an atmoz user spec, but a spec starts with the user name and ':', without white space)\n"},
		{[]string{"foo:x", " " + spec}, "Error: argument 2 (not shown: it contains ':') is not an atmoz user spec USER:PASS[:e][:UID[:GID[:DIR[,DIR]...]]]; after the first spec every argument must be one\n"},
		{[]string{"foo:x", "serve"}, "Error: argument 2, the command 'serve', is not an atmoz user spec USER:PASS"},
		{[]string{"foo:correct", pw}, "Error: argument 2 (not shown: it may be part of a spec, such as a word of a password with a space, which needs quotes) is not an atmoz user spec USER:PASS"},
		{[]string{"--allow-root", "--on-conflict", spec, "bar:x"}, "Error: --on-conflict: want rename, reject, overwrite or version" + notShown},
		{[]string{"--allow-root", "--log-level", spec, "bar:x"}, "Error: --log-level: want debug, info, warn or error" + notShown},
		{[]string{"--allow-root", "--log-format", spec, "bar:x"}, "Error: --log-format: want text or json" + notShown},
		{[]string{"--allow-root", "--listen", "u:" + pw, "bar:x"}, "Error: --listen: want HOST:PORT or :PORT, with a port number" + notShown},
		{[]string{"serve", "--allow-root", "--listen", spec}, "Error: --listen: want HOST:PORT or :PORT, with a port number" + notShown},
		// HOST:PORT with a port number is shown: only its range is wrong.
		{[]string{"--allow-root", "--listen", "0.0.0.0:99999", "bar:x"}, "Error: configuration: 1 problem:\n  server.listen: \"0.0.0.0:99999\": invalid port\n"},
		{[]string{"--read-only=" + spec, "bar:x"}, "Error: invalid argument for --read-only (not shown: it contains ':', as an atmoz user spec does)\n"},
		{[]string{"--allow-root", "--listen", "127.0.0.1:0", "--users-conf", spec, "bar:x"}, "Error: --users-conf: the path does not exist (not shown: it looks like an atmoz user spec; give --users-conf its own value, before the specs)\n"},
		{[]string{"--allow-root", "--listen", "127.0.0.1:0", "--state-dir", spec, "bar:x"}, "Error: --state-dir: the path does not exist (not shown: it looks like an atmoz user spec; give --state-dir its own value, before the specs)\n"},
		{[]string{"-" + spec}, "Error: unknown flag (not shown: it contains ':', as an atmoz user spec does)\n"},
		{[]string{"--" + spec}, "Error: unknown flag (not shown: it contains ':', as an atmoz user spec does)\n"},
		{[]string{"serve", "-" + spec}, "Error: unknown flag (not shown: it contains ':', as an atmoz user spec does)\n"},
		{[]string{"--allow-root", "U:" + pw}, "Error: argument 1: the user name is not one gosftpd accepts"},
		{[]string{"bogus"}, `Error: unknown command "bogus" for "gosftpd"`},
	} {
		code, stdout, stderr := executeBounded(t, tt.args...)
		if code != exitUsage || stdout != "" || !strings.HasPrefix(stderr, tt.want) {
			t.Errorf("%q: exit %d, stderr:\n%s\nwant it to start with %q", tt.args, code, stderr, tt.want)
		}
		if strings.Contains(stderr, pw) {
			t.Errorf("%q: stderr shows the password:\n%s", tt.args, stderr)
		}
	}
}

// TestAtmozSpecNeverShown: an atmoz user spec in a position where it
// fails is never shown, with three fields or more and with two, which
// net.SplitHostPort takes for HOST:PORT: as the value of every flag of the
// root command, which a flag takes when its own value is missing, as the
// value of the flags of serve whose values are checked, here with a
// configuration file, and after a spec or a word that is not one.
func TestAtmozSpecNeverShown(t *testing.T) {
	atmozEnv(t, false)
	writeLocalConfig(t)
	listen := []string{"--allow-root", "--listen", "127.0.0.1:0"} // in case it starts
	for _, spec := range []string{"u:" + pw + ":::upload", "u:" + pw} {
		var lines [][]string
		value := func(cmd, rest []string, f *pflag.Flag) {
			if f.NoOptDefVal == "" {
				lines = append(lines, slices.Concat(cmd, listen, []string{"--" + f.Name, spec}, rest))
			}
			lines = append(lines, slices.Concat(cmd, listen, []string{"--" + f.Name + "=" + spec}, rest))
		}
		root := NewRootCommand()
		root.Flags().VisitAll(func(f *pflag.Flag) { value(nil, []string{"bar:x"}, f) })
		serve, _, err := root.Find([]string{"serve"})
		if err != nil {
			t.Fatal(err)
		}
		serve.Flags().VisitAll(func(f *pflag.Flag) {
			if f.NoOptDefVal != "" || slices.Contains([]string{"on-conflict", "log-level", "log-format", "listen"}, f.Name) {
				value([]string{"serve"}, nil, f)
			}
		})
		lines = append(lines,
			[]string{"--help=" + spec},
			slices.Concat(listen, []string{"bar:x", spec + ":x"}), // a uid that is no number
			slices.Concat(listen, []string{"bar:x", "word", spec}),
			slices.Concat(listen, []string{"bar:x", " " + spec}),
			slices.Concat(listen, []string{"bar:correct", pw}),
		)
		for _, args := range lines {
			code, stdout, stderr := executeBounded(t, args...)
			if code != exitUsage || strings.Contains(stdout+stderr, pw) {
				t.Errorf("%q: exit %d, stdout:\n%s\nstderr:\n%s", args, code, stdout, stderr)
			}
		}
	}
}

// executeBounded is execute for a usage error: a command line that serves
// after all stops after 10 seconds, so that the test fails, not hangs.
func executeBounded(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var out, errOut bytes.Buffer
	code = run(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestRootHelp: the root command describes atmoz mode and takes only the
// flags that apply in it.
func TestRootHelp(t *testing.T) {
	code, stdout, _ := execute(t, "--help")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"gosftpd [USER:PASS[:e][:UID[:GID[:DIR[,DIR]...]]]...] [flags]", "--users-conf", `--on-conflict string     when an upload targets an existing file: overwrite, rename, reject or version (default "overwrite")`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("no %q in:\n%s", want, stdout)
		}
	}
	flags := regexp.MustCompile(`(?m)^\s+(?:-\w, )?--([a-z-]+)`).FindAllStringSubmatch(stdout, -1)
	var got []string
	for _, f := range flags {
		got = append(got, f[1])
	}
	slices.Sort(got)
	want := append(slices.Clone(atmozFlags), "help")
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("root flags %v, want %v", got, want)
	}
}
