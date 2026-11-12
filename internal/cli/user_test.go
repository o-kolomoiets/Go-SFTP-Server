// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// executeWithStdin runs the command line as execute does, with stdin as
// its standard input.
func executeWithStdin(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.ExecuteContext(t.Context())
	// As run does.
	switch {
	case err == nil:
		code = exitOK
	case errors.As(err, new(usageError)), errors.As(err, new(configError)):
		code = exitUsage
	default:
		code = exitFailure
	}
	if err != nil {
		fmt.Fprintln(&errOut, "Error:", err)
	}
	return code, out.String(), errOut.String()
}

// teamFile defines two users with comments, in users.d/team.toml.
const teamFile = `# Team; keep this comment.
[users.bob]  # bob's own comment
authorized_keys = ["KEY"]
access = { inbox = "upload" } # ticket 7

# carol, keep until 2027
[users.carol]
authorized_keys = ["KEY"]
access = { inbox = "read" }
`

// teamConfig writes the configuration of userConfig with a second mount,
// archive, and auth.methods set to methods; and users.d/team.toml with bob
// and carol. It returns the paths of both files.
func teamConfig(t *testing.T, methods string) (path, team string) {
	t.Helper()
	path = userConfig(t)
	dir := filepath.Dir(path)
	if err := os.Mkdir(filepath.Join(dir, "archive"), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, strings.Replace(string(data), "[mounts.inbox]",
		"[auth]\nmethods = "+methods+"\n[mounts.archive]\npath = \""+filepath.ToSlash(filepath.Join(dir, "archive"))+"\"\n[mounts.inbox]", 1))
	if err := os.Mkdir(filepath.Join(dir, "users.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	team = filepath.Join(dir, "users.d", "team.toml")
	writeFile(t, team, strings.ReplaceAll(teamFile, "KEY", authorizedKey(newSigner(t))))
	return path, team
}

func readString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// validConfig fails unless the configuration at path is valid.
func validConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

// checkPasswordHash fails unless hash is an argon2id hash of password.
func checkPasswordHash(t *testing.T, hash, password string) {
	t.Helper()
	parts := strings.Split(hash, "$") // "", argon2id, v=19, m=...,t=...,p=..., salt, key
	if len(parts) != 6 || parts[1] != "argon2id" {
		t.Fatalf("not an argon2id hash: %q", hash)
	}
	var (
		m, n uint32
		p    uint8
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &n, &p); err != nil {
		t.Fatalf("%q: %v", hash, err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(argon2.IDKey([]byte(password), salt, n, m, p, uint32(len(key))), key) {
		t.Errorf("%q is not the hash of %q", hash, password)
	}
}

// listJSON returns the users of user list --json.
func listJSON(t *testing.T, path string) []map[string]any {
	t.Helper()
	code, out, errOut := execute(t, "user", "list", "--json", "--config", path)
	if code != exitOK {
		t.Fatalf("user list --json: exit %d: %s", code, errOut)
	}
	var users []map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&users); err != nil {
		t.Fatalf("user list --json: %v\n%s", err, out)
	}
	if dec.More() || !strings.HasSuffix(out, "]\n") {
		t.Errorf("user list --json is not one array and a newline:\n%s", out)
	}
	return users
}

func TestUserSet(t *testing.T) {
	t.Parallel()

	path, team := teamConfig(t, `["publickey"]`)
	before := readString(t, team)
	args := []string{"user", "set", "bob", "--access", "inbox=read", "--access", "archive=upload", "--config", path}
	code, out, errOut := execute(t, args...)
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	for _, want := range []string{
		"Set the access of bob in " + team + ". Apply it with: systemctl reload gosftpd",
		"Open connections of the user keep the access they had until they end.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	want := strings.Replace(before, `access = { inbox = "upload" } # ticket 7`, `access = { archive = "upload", inbox = "read" } # ticket 7`, 1)
	if got := readString(t, team); got != want {
		t.Errorf("users.d/team.toml:\n%s\nwant (only the access of bob changed):\n%s", got, want)
	}
	if fi, err := os.Stat(team); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode of the file: %v, %v; want 0600, as before", fi.Mode().Perm(), err)
	}
	if des, _ := os.ReadDir(filepath.Dir(team)); len(des) != 1 {
		t.Errorf("users.d holds %d entries, want 1 (no temporary files)", len(des))
	}
	c := validConfig(t, path)
	if got := c.Users["bob"].Access; !reflect.DeepEqual(got, map[string]string{"inbox": "read", "archive": "upload"}) {
		t.Errorf("access of bob = %v", got)
	}
	if got := c.Users["carol"].Access; !reflect.DeepEqual(got, map[string]string{"inbox": "read"}) {
		t.Errorf("access of carol = %v", got)
	}

	// The same access again changes nothing.
	written := readString(t, team)
	if code, out, _ := execute(t, args...); code != exitOK || out != "bob has this access already.\n" {
		t.Errorf("the same access: exit %d: %s", code, out)
	}
	if readString(t, team) != written {
		t.Error("the same access rewrote the file")
	}

	// --no-access leaves bob none, with the warning of validation.
	code, out, errOut = execute(t, "user", "set", "bob", "--no-access", "--config", path)
	if code != exitOK || !strings.Contains(errOut, "warning: users.bob.access ("+team+"): no mounts: the user can log in but sees nothing") {
		t.Fatalf("--no-access: exit %d: %s%s", code, out, errOut)
	}
	want = strings.Replace(before, `access = { inbox = "upload" } # ticket 7`, `access = {} # ticket 7`, 1)
	if got := readString(t, team); got != want {
		t.Errorf("--no-access:\n%s\nwant:\n%s", got, want)
	}
	for _, u := range listJSON(t, path) {
		if u["name"] == "bob" && !reflect.DeepEqual(u["access"], map[string]any{}) {
			t.Errorf("user list --json after --no-access: %v", u)
		}
	}
	validConfig(t, path)
}

// user set keeps the form of an access table.
func TestUserSetAccessTable(t *testing.T) {
	t.Parallel()

	path, team := teamConfig(t, `["publickey"]`)
	key := authorizedKey(newSigner(t))
	file := filepath.Join(filepath.Dir(team), "dora.toml")
	writeFile(t, file, "[users.dora]\nauthorized_keys = [\""+key+"\"]\n\n[users.dora.access] # granted in ticket 9\ninbox = \"read\"\n")
	if code, out, errOut := execute(t, "user", "set", "dora", "--access", "archive=full", "--config", path); code != exitOK {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	want := "[users.dora]\nauthorized_keys = [\"" + key + "\"]\n\n[users.dora.access] # granted in ticket 9\narchive = \"full\"\n"
	if got := readString(t, file); got != want {
		t.Errorf("dora.toml:\n%s\nwant:\n%s", got, want)
	}
}

func TestUserSetRefuses(t *testing.T) {
	t.Parallel()

	path, team := teamConfig(t, `["publickey"]`)
	hash, err := auth.HashPassword([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	// pat has a password, which auth.methods leaves out: pat cannot log in.
	pat := filepath.Join(filepath.Dir(team), "pat.toml")
	writeFile(t, pat, "[users.pat]\npassword_hash = \""+hash+"\"\naccess = { inbox = \"upload\" }\n")
	files := map[string]string{team: readString(t, team), pat: readString(t, pat), path: readString(t, path)}

	for _, tt := range []struct {
		args  []string
		stdin string
		want  string
	}{
		{[]string{"nobody", "--access", "inbox=read"}, "", `no user "nobody" in ` + path},
		{[]string{"admin", "--access", "inbox=read"}, "", `user "admin" is defined in ` + path + " itself, which gosftpd does not rewrite"},
		{[]string{"bob", "--access", "inbox=read", "--no-access"}, "", "--access and --no-access cannot be used together"},
		{[]string{"bob"}, "", "nothing to change: give --access MOUNT=PERMISSIONS, --no-access or --password-stdin"},
		{[]string{"bob", "--force"}, "", "nothing to change"},
		{[]string{"bob", "--password-stdin"}, "\n", "--password-stdin: empty password"},
		{[]string{"bob", "--password-stdin"}, "", "--password-stdin: empty password"},
		{[]string{"bob", "--password-stdin"}, strings.Repeat("x", auth.MaxPasswordLen+1) + "\n", "--password-stdin: password longer than"},
		{[]string{"bob", "--access", "inbox=bogus"}, "", `--access "inbox=bogus": `},
		{[]string{"bob", "--access", "inbox"}, "", `--access "inbox": want MOUNT=PERMISSIONS`},
		{[]string{"bob", "--access", "inbox=read", "--access", "inbox=full"}, "", `--access: mount "inbox" given twice`},
		{[]string{"bob", "--access", "outbox=read"}, "", `users.bob.access (` + team + `): unknown mount "outbox"`},
		{[]string{"pat", "--access", "inbox=read"}, "", "pat could not log in (see the warnings); pass --force to write it anyway"},
		{[]string{"pat", "--password-stdin"}, "new\n", "pat could not log in"},
		{nil, "", "accepts 1 arg(s), received 0"},
	} {
		args := append([]string{"user", "set"}, tt.args...)
		if tt.args != nil {
			args = append(args, "--config", path)
		}
		code, out, errOut := executeWithStdin(t, tt.stdin, args...)
		if code != exitUsage || !strings.Contains(errOut, tt.want) {
			t.Errorf("%q: exit %d, want %d and %q:\n%s%s", args, code, exitUsage, tt.want, out, errOut)
		}
	}
	for file, data := range files {
		if readString(t, file) != data {
			t.Errorf("a refused user set changed %s", file)
		}
	}
	if des, _ := os.ReadDir(filepath.Dir(team)); len(des) != 2 {
		t.Errorf("users.d holds %d entries, want 2 (no temporary files)", len(des))
	}

	// --force writes a user that cannot log in, with the warnings.
	code, out, errOut := execute(t, "user", "set", "pat", "--access", "inbox=read", "--force", "--config", path)
	if code != exitOK || !strings.Contains(errOut, `warning: users.pat.password_hash (`+pat+`): ignored: auth.methods does not include "password"`) {
		t.Errorf("--force: exit %d: %s%s", code, out, errOut)
	}
	// A disabled user is no reason to refuse: set does not change that.
	if code, _, errOut := execute(t, "user", "disable", "bob", "--config", path); code != exitOK {
		t.Fatalf("disable: %s", errOut)
	}
	if code, out, errOut := execute(t, "user", "set", "bob", "--access", "archive=read", "--config", path); code != exitOK {
		t.Errorf("a disabled user: exit %d: %s%s", code, out, errOut)
	}
}

func TestUserSetPassword(t *testing.T) {
	t.Parallel()

	path, team := teamConfig(t, `["publickey", "password"]`)
	before := readString(t, team)
	const pw = "correct horse battery staple"
	code, out, errOut := executeWithStdin(t, pw+"\r\nsecond line\n", "user", "set", "bob", "--password-stdin", "--config", path)
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	if want := "Set the password of bob in " + team + ". Apply it with: systemctl reload gosftpd (or kill -HUP the server).\n"; out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	c := validConfig(t, path)
	hash := c.Users["bob"].PasswordHash
	checkPasswordHash(t, hash, pw)
	want := strings.Replace(before, "access = { inbox = \"upload\" } # ticket 7", "password_hash = \""+hash+"\"\naccess = { inbox = \"upload\" } # ticket 7", 1)
	if got := readString(t, team); got != want {
		t.Errorf("users.d/team.toml:\n%s\nwant:\n%s", got, want)
	}

	// Access and password at once; the new password replaces the old.
	code, out, errOut = executeWithStdin(t, "s3cret\n", "user", "set", "bob", "--access", "archive=read", "--password-stdin", "--config", path)
	if code != exitOK || !strings.HasPrefix(out, "Set the access and password of bob in ") {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	c = validConfig(t, path)
	checkPasswordHash(t, c.Users["bob"].PasswordHash, "s3cret")
	if got := c.Users["bob"].Access; !reflect.DeepEqual(got, map[string]string{"archive": "read"}) {
		t.Errorf("access of bob = %v", got)
	}
	if strings.Count(readString(t, team), "password_hash") != 1 {
		t.Errorf("two password hashes:\n%s", readString(t, team))
	}
	for _, s := range []string{out, errOut} {
		if strings.Contains(s, "s3cret") || strings.Contains(s, "$argon2id$") {
			t.Errorf("the output shows the password or its hash:\n%s", s)
		}
	}
	if !strings.Contains(readString(t, team), "# bob's own comment") {
		t.Error("a comment was lost")
	}
}

func TestUserAddPasswordStdin(t *testing.T) {
	t.Parallel()

	path, _ := teamConfig(t, `["publickey", "password"]`)
	const pw = "dora's secret"
	code, out, errOut := executeWithStdin(t, pw+"\n", "user", "add", "dora", "--password-stdin", "--access", "inbox=upload", "--write", "--config", path)
	if code != exitOK || errOut != "" {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	if !strings.Contains(out, "Wrote "+filepath.Join(filepath.Dir(path), "users.d", "dora.toml")) {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(out, pw) || strings.Contains(out, "$argon2id$") {
		t.Errorf("the output shows the password or its hash:\n%s", out)
	}
	c := validConfig(t, path)
	checkPasswordHash(t, c.Users["dora"].PasswordHash, pw)
	if !c.CanLogIn("dora") {
		t.Error("dora cannot log in")
	}

	// Without --write the block is printed, with the hash and not the
	// password.
	code, out, errOut = executeWithStdin(t, pw+"\n", "user", "add", "erin", "--password-stdin", "--access", "inbox=read")
	if code != exitOK || strings.Contains(out, pw) {
		t.Fatalf("exit %d: %s%s", code, out, errOut)
	}
	m := regexp.MustCompile(`password_hash = "([^"]+)"`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no password_hash in:\n%s", out)
	}
	checkPasswordHash(t, m[1], pw)

	hash, err := auth.HashPassword([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	only, _ := teamConfig(t, `["publickey"]`)
	for _, tt := range []struct {
		args  []string
		stdin string
		want  string
	}{
		{[]string{"x", "--password-hash", hash, "--password-stdin", "--access", "inbox=read"}, "pw\n", "--password-hash and --password-stdin cannot be used together"},
		{[]string{"x", "--password-stdin", "--access", "inbox=read"}, "", "--password-stdin: empty password"},
		{[]string{"x", "--password-stdin", "--access", "inbox=read"}, "\r\n", "--password-stdin: empty password"},
		{[]string{"x", "--password-stdin", "--access", "inbox=read", "--write", "--config", only}, "pw\n", "x could not log in"},
	} {
		args := append([]string{"user", "add"}, tt.args...)
		code, out, errOut := executeWithStdin(t, tt.stdin, args...)
		if code != exitUsage || !strings.Contains(errOut, tt.want) {
			t.Errorf("%q: exit %d, want %d and %q:\n%s%s", args, code, exitUsage, tt.want, out, errOut)
		}
	}
}

func TestUserListJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	hash, err := auth.HashPassword([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gosftpd.toml")
	base := `config_version = 1
[server]
host_keys = ["/k"]
[mounts.m]
path = "/srv/m"
[mounts."My Docs"]
path = "/srv/d"
[users.alice]
authorized_keys = ["` + authorizedKey(newSigner(t)) + `"]
access = { m = "full", "My Docs" = "read" }
[users.bob]
authorized_keys_file = "missing.pub"
expires = 2001-01-01T00:00:00Z
principals = []
access = { m = "upload" }
[users.carol]
disabled = true
password_hash = "` + hash + `"
principals = ["carol@corp", "c<2>"]
`
	trust := "[auth]\ntrusted_user_ca_keys = [\"" + authorizedKey(newSigner(t)) + "\"]\n"
	writeFile(t, path, base+trust)
	want := `[
	{"name": "alice", "access": {"m": "full", "My Docs": "read"}, "keys": 1, "keys_unreadable": false, "keys_off": false,
	 "principals": ["alice"], "principals_off": false, "password": false, "password_off": false, "expires": null, "status": "active"},
	{"name": "bob", "access": {"m": "upload"}, "keys": 0, "keys_unreadable": true, "keys_off": false,
	 "principals": [], "principals_off": false, "password": false, "password_off": false, "expires": "2001-01-01T00:00:00Z", "status": "expired"},
	{"name": "carol", "access": {}, "keys": 0, "keys_unreadable": false, "keys_off": false,
	 "principals": ["carol@corp", "c<2>"], "principals_off": false, "password": true, "password_off": true, "expires": null, "status": "disabled"}
]`
	var wantUsers []map[string]any
	if err := json.Unmarshal([]byte(want), &wantUsers); err != nil {
		t.Fatal(err)
	}
	if got := listJSON(t, path); !reflect.DeepEqual(got, wantUsers) {
		t.Errorf("user list --json:\n%v\nwant:\n%v", got, wantUsers)
	}
	if _, out, _ := execute(t, "user", "list", "--json", "--config", path); !strings.Contains(out, `"c<2>"`) {
		t.Errorf("principals are escaped:\n%s", out)
	}

	// The table shows the same.
	_, out, _ := execute(t, "user", "list", "--config", path)
	space := regexp.MustCompile(`[ \t]+`)
	for _, row := range []string{
		"alice My Docs=read, m=full 1 alice - - active",
		"bob m=upload 0+? - - 2001-01-01T00:00:00Z expired",
		"carol 0 carol@corp,c<2> off - disabled",
	} {
		if !strings.Contains(space.ReplaceAllString(out, " "), row) {
			t.Errorf("user list lacks %q:\n%s", row, out)
		}
	}

	// With passwords only, keys and principals are off.
	writeFile(t, path, base+trust+"methods = [\"password\"]\n")
	for _, u := range listJSON(t, path) {
		if u["keys_off"] != true || u["principals_off"] != true || !reflect.DeepEqual(u["principals"], []any{}) || u["password_off"] != false {
			t.Errorf("password-only user list --json: %v", u)
		}
	}

	// No users: an empty array.
	writeFile(t, path, "config_version = 1\n[mounts.m]\npath = \"/srv/m\"\n")
	if _, out, _ := execute(t, "user", "list", "--json", "--config", path); out != "[]\n" {
		t.Errorf("user list --json without users: %q", out)
	}
}

// A server applies user set on reload: new logins get the new access and
// password, open connections keep theirs.
func TestUserSetReload(t *testing.T) {
	isolate(t)
	path, _ := teamConfig(t, `["publickey", "password"]`)
	dir := filepath.Dir(path)
	writeFile(t, path, strings.Replace(readString(t, path), "127.0.0.1:2222", "127.0.0.1:0", 1))
	// A user's only mount is "/" (defaults.flatten): a file in each mount
	// tells them apart.
	writeFile(t, filepath.Join(dir, "inbox", "in.txt"), "in")
	writeFile(t, filepath.Join(dir, "archive", "old.txt"), "old")
	if code, out, errOut := executeWithStdin(t, "first\n", "user", "add", "dora", "--password-stdin", "--access", "inbox=readwrite", "--write", "--config", path); code != exitOK {
		t.Fatalf("user add: exit %d: %s%s", code, out, errOut)
	}
	ts := startServe(t, "--config", path)
	held := mustLogin(t, ts.addr, "dora", ssh.Password("first"))
	if got := names(t, held, "/"); !reflect.DeepEqual(got, []string{"in.txt"}) {
		t.Fatalf("dora sees %v, want the inbox", got)
	}

	if code, out, errOut := executeWithStdin(t, "second\n", "user", "set", "dora", "--access", "archive=read", "--password-stdin", "--config", path); code != exitOK {
		t.Fatalf("user set: exit %d: %s%s", code, out, errOut)
	}
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v\n%s", ev, ts.stderr.String())
	}
	if c, err := atmozLogin(t, ts.addr, "dora", ssh.Password("first")); err == nil {
		c.Close()
		t.Error("the old password still logs in")
	}
	c := mustLogin(t, ts.addr, "dora", ssh.Password("second"))
	if got := names(t, c, "/"); !reflect.DeepEqual(got, []string{"old.txt"}) {
		t.Errorf("after user set dora sees %v, want the archive", got)
	}
	if got := names(t, held, "/"); !reflect.DeepEqual(got, []string{"in.txt"}) {
		t.Errorf("the open connection sees %v, want the inbox it had", got)
	}
}
