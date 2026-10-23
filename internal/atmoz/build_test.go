// SPDX-License-Identifier: Apache-2.0

package atmoz

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// pubKey returns a new public key as an authorized_keys line.
func pubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// build runs Build and checks that no warning shows the password.
func build(t *testing.T, o Options) *Mode {
	t.Helper()
	m, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range m.Warnings {
		if strings.Contains(w, secret) {
			t.Errorf("warning shows the password: %s", w)
		}
	}
	return m
}

// validate gives c a host key and checks it as serve does.
func validate(t *testing.T, c *config.Config) []string {
	t.Helper()
	c.Server.HostKeys = []string{filepath.Join(t.TempDir(), "host_key")}
	c.Server.HostKeyAutoGenerate = true
	warns, err := c.Validate()
	if err != nil {
		t.Fatal(err)
	}
	fsWarns, err := c.CheckFS()
	if err != nil {
		t.Fatal(err)
	}
	return append(warns, fsWarns...)
}

// mountsOf returns the users' mounts as "user:/visible=host path".
func mountsOf(c *config.Config) []string {
	var out []string
	for _, user := range slices.Sorted(maps.Keys(c.Users)) {
		for _, name := range slices.Sorted(maps.Keys(c.Users[user].Access)) {
			m := c.Mounts[name]
			out = append(out, user+":/"+m.Display+"="+m.Path)
		}
	}
	slices.Sort(out)
	return out
}

func hasWarning(warns []string, s string) bool {
	return slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, s) })
}

// TestBuildSimplest: the atmoz README's first example, foo:pass:::upload.
func TestBuildSimplest(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	m := build(t, Options{Args: []string{"foo:" + secret + ":::upload"}, Home: home})
	c := m.Config
	if !c.Atmoz || c.Defaults.Flatten || c.Defaults.OnConflict != "overwrite" {
		t.Errorf("Atmoz %v, flatten %v, on_conflict %q", c.Atmoz, c.Defaults.Flatten, c.Defaults.OnConflict)
	}
	up := filepath.Join(home, "foo", "upload")
	if got := mountsOf(c); !slices.Equal(got, []string{"foo:/upload=" + up}) {
		t.Errorf("mounts %q", got)
	}
	mt := c.Mounts["atmoz1"]
	if mt == nil || !mt.Create || mt.ReadOnly || mt.OnConflict != "overwrite" || c.Users["foo"].Access["atmoz1"] != "full" {
		t.Errorf("mount %+v, access %v", mt, c.Users["foo"].Access)
	}
	if fi, err := os.Stat(up); err != nil || !fi.IsDir() {
		t.Errorf("upload not created: %v", err)
	}
	if !slices.Equal(c.Auth.Methods, []string{auth.MethodPublicKey, auth.MethodPassword}) {
		t.Errorf("methods %v", c.Auth.Methods)
	}
	// Hashed at start, with argon2id; the plain password is kept nowhere.
	if h := c.Users["foo"].PasswordHash; !strings.HasPrefix(h, "$argon2id$") || strings.Contains(h, secret) {
		t.Errorf("password hash %q", h)
	} else if _, err := auth.ParsePasswordHash(h); err != nil {
		t.Error(err)
	}
	if m.Users != [3]int{0, 1, 0} || m.IDs {
		t.Errorf("users %v, ids %v", m.Users, m.IDs)
	}
	if !hasWarning(m.Warnings, "argument 1 (user foo): the password is in plain text") {
		t.Errorf("warnings %q", m.Warnings)
	}
	if warns := validate(t, c); len(warns) != 0 {
		t.Errorf("validation warnings %q", warns)
	}
}

// TestBuildUsersFile: the README's users file, three users without
// directories on a fresh volume, read with the order and the duplicates
// of atmoz: the users file, the arguments, then SFTP_USERS.
func TestBuildUsersFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	file := filepath.Join(t.TempDir(), "users.conf")
	write(t, file, "# atmoz users\n\nfoo:123:1001:100\r\n  # indented comment\nbar:abc:1002:100\nbaz:xyz:1003:100\n\t\n")
	m := build(t, Options{UsersFile: file, Args: []string{"foo:" + secret + ":::x", "qux:" + secret}, Env: "bar:" + secret + "\nquux:" + secret + "  baz:" + secret, Home: home, Discover: true})
	c := m.Config
	if got := slices.Sorted(maps.Keys(c.Users)); !slices.Equal(got, []string{"bar", "baz", "foo", "quux", "qux"}) {
		t.Fatalf("users %v", got)
	}
	if m.Users != [3]int{3, 1, 1} || !m.IDs {
		t.Errorf("users per source %v, ids %v", m.Users, m.IDs)
	}
	// The first definition wins: foo from line 3 has no directory.
	if len(c.Mounts) != 0 || len(c.Users["foo"].Access) != 0 {
		t.Errorf("mounts %v", mountsOf(c))
	}
	for _, w := range []string{
		"argument 1: user foo is already defined by " + file + " line 3; skipped, as atmoz skips it",
		"SFTP_USERS entry 1: user bar is already defined by " + file + " line 5; skipped",
		"SFTP_USERS entry 3: user baz is already defined by " + file + " line 6; skipped",
		file + " line 3 (user foo): no directories, so the user logs in to an empty read-only root, as in atmoz; name directories in the spec's last field (user:pass:::upload) or mount them under " + filepath.Join(home, "foo"),
		// A skipped spec's password is visible all the same.
		"argument 1 (user foo): the password is in plain text",
		"SFTP_USERS entry 2 (user quux): the password is in plain text",
	} {
		if !hasWarning(m.Warnings, w) {
			t.Errorf("no warning %q in %q", w, m.Warnings)
		}
	}
	if hasWarning(m.Warnings, file+" line 4") || hasWarning(m.Warnings, "line 3 (user foo): the password is in plain text") {
		t.Errorf("warnings %q", m.Warnings)
	}
	if !slices.ContainsFunc(c.Inlined, func(f config.InlinedFile) bool { return f.Path == file && f.Secret }) {
		t.Errorf("inlined %+v", c.Inlined)
	}
	// No mount at all is not "no mounts configured".
	if warns := validate(t, c); len(warns) != 0 {
		t.Errorf("validation warnings %q", warns)
	}
}

// TestBuildKeys: every file in .ssh/keys/ is read as an authorized_keys
// file and inlined; lines that cannot be used are skipped with a warning.
func TestBuildKeys(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	k1, k2 := pubKey(t), pubKey(t)
	keys := filepath.Join(home, "foo", ".ssh", "keys")
	write(t, filepath.Join(keys, "id_rsa.pub"), k1+"\n\n# comment\nssh-dss AAAAB3NzaC1kc3M= old\n")
	write(t, filepath.Join(keys, "id_other.pub"), "  "+k2+"  \n")
	write(t, filepath.Join(keys, ".hidden"), "not a key\n")
	write(t, filepath.Join(home, "foo", "share", "f"), "data")
	m := build(t, Options{Args: []string{"foo::1001"}, Home: home, Discover: true})
	c := m.Config
	u := c.Users["foo"]
	if !slices.Equal(u.AuthorizedKeys, []string{k2, k1}) || u.PasswordHash != "" {
		t.Errorf("keys %q, hash %q", u.AuthorizedKeys, u.PasswordHash)
	}
	if !slices.Equal(c.Auth.Methods, []string{auth.MethodPublicKey}) {
		t.Errorf("methods %v", c.Auth.Methods)
	}
	if !hasWarning(m.Warnings, filepath.Join(keys, "id_rsa.pub")+":4: ") || len(m.Warnings) != 1 {
		t.Errorf("warnings %q", m.Warnings)
	}
	var inlined []string
	for _, f := range c.Inlined {
		if f.Secret || f.What != "a key file of foo" {
			t.Errorf("inlined %+v", f)
		}
		inlined = append(inlined, f.Path)
	}
	if !slices.Equal(inlined, []string{filepath.Join(keys, "id_other.pub"), filepath.Join(keys, "id_rsa.pub")}) {
		t.Errorf("inlined %q", inlined)
	}
	if got := mountsOf(c); !slices.Equal(got, []string{"foo:/share=" + filepath.Join(home, "foo", "share")}) {
		t.Errorf("mounts %q", got)
	}
	if warns := validate(t, c); len(warns) != 0 {
		t.Errorf("validation warnings %q", warns)
	}

	// Without a password or keys nobody can log in.
	m = build(t, Options{Args: []string{"bar::::up"}, Home: home})
	if !hasWarning(m.Warnings, "argument 1 (user bar): no password and no keys in "+filepath.Join(home, "bar", ".ssh", "keys")+string(filepath.Separator)+", so the user cannot log in") {
		t.Errorf("warnings %q", m.Warnings)
	}
}

// TestBuildDiscovery: in the image, directories under /home/<user> become
// the user's; names that are no mount names are skipped with a warning,
// .ssh without one, and only directories count. Outside the image only
// the spec's directories are served.
func TestBuildDiscovery(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	foo := filepath.Join(home, "foo")
	for _, d := range []string{"upload", "share", "_data", "lost+found", ".cache", ".ssh", "b c"} {
		if err := os.MkdirAll(filepath.Join(foo, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(foo, "file"), "x")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(foo, "share"), filepath.Join(foo, "link")); err != nil {
			t.Fatal(err)
		}
	}
	m := build(t, Options{Args: []string{"foo:" + secret + ":::upload,new"}, Home: home, Discover: true})
	want := []string{"foo:/b c=" + filepath.Join(foo, "b c"), "foo:/new=" + filepath.Join(foo, "new"), "foo:/share=" + filepath.Join(foo, "share"), "foo:/upload=" + filepath.Join(foo, "upload")}
	if got := mountsOf(m.Config); !slices.Equal(got, want) {
		t.Errorf("mounts %q, want %q", got, want)
	}
	// The spec's directories come first, then the discovered ones by name.
	var order []string
	for _, n := range []string{"atmoz1", "atmoz2", "atmoz3", "atmoz4"} {
		order = append(order, m.Config.Mounts[n].Display)
	}
	if !slices.Equal(order, []string{"upload", "new", "b c", "share"}) {
		t.Errorf("order %q", order)
	}
	for _, d := range []string{"_data", "lost+found", ".cache"} {
		if !hasWarning(m.Warnings, `argument 1 (user foo): directory "`+d+`" in `+foo+" is skipped: not a valid name") {
			t.Errorf("no warning for %s in %q", d, m.Warnings)
		}
	}
	if hasWarning(m.Warnings, `".ssh"`) || hasWarning(m.Warnings, `"file"`) || hasWarning(m.Warnings, `"link"`) {
		t.Errorf("warnings %q", m.Warnings)
	}

	m = build(t, Options{Args: []string{"foo:" + secret + ":::upload"}, Home: home})
	if got := mountsOf(m.Config); !slices.Equal(got, []string{"foo:/upload=" + filepath.Join(foo, "upload")}) {
		t.Errorf("outside the image: mounts %q", got)
	}

	// A directory on the disk and one of the spec that differ only in case.
	_, err := Build(Options{Args: []string{"foo:" + secret + ":::Upload"}, Home: home, Discover: true})
	if err == nil || !strings.Contains(err.Error(), `argument 1 (user foo): directories "Upload" and "upload" (in `+foo+`) differ only in case`) {
		t.Errorf("Build: %v", err)
	}
}

// TestBuildUnavailable: a directory that cannot be created is unavailable
// to its user, with a warning that says how to fix it; the others work.
func TestBuildUnavailable(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	write(t, filepath.Join(home, "foo", "blocked"), "a file where the directory would be")
	m := build(t, Options{Args: []string{"foo:" + secret + ":::upload,blocked", "bar:" + secret + ":::blocked"}, Home: home})
	c := m.Config
	if !slices.Equal(c.Unavailable, []string{"atmoz2"}) || c.Mounts["atmoz2"].Display != "blocked" {
		t.Fatalf("unavailable %v", c.Unavailable)
	}
	path := filepath.Join(home, "foo", "blocked")
	if !hasWarning(m.Warnings, "argument 1 (user foo): directory blocked cannot be created ("+path+" is not a directory), so it is unavailable to foo; give it a volume of its own (-v HOST_DIR:"+path+"), or let ") {
		t.Errorf("warnings %q", m.Warnings)
	}
	if fi, err := os.Stat(filepath.Join(home, "bar", "blocked")); err != nil || !fi.IsDir() {
		t.Errorf("bar's directory: %v", err)
	}
	// CheckFS leaves the unavailable mount out.
	validate(t, c)
}

// TestBuildErrors: every bad spec is reported at once, and a source that
// cannot be read is an error.
func TestBuildErrors(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	_, err := Build(Options{Args: []string{"Foo:" + secret, "bar:" + secret + ":x"}, Env: "baz:" + secret + ":::a/b", Home: home})
	for _, want := range []string{"argument 1: the user name", "argument 2 (user bar): the uid is not a number", "SFTP_USERS entry 1 (user baz): directory \"a/b\""} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Build: %v, want %q", err, want)
		}
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("the error shows the password: %v", err)
	}
	if _, err := Build(Options{Home: home}); !errors.Is(err, ErrNoUsers) {
		t.Errorf("no sources: %v", err)
	}
	file := filepath.Join(t.TempDir(), "users.conf")
	write(t, file, "# nobody\n\n")
	if _, err := Build(Options{UsersFile: file, Env: "  ", Home: home}); !errors.Is(err, ErrNoUsers) {
		t.Errorf("only comments: %v", err)
	}
	if _, err := Build(Options{UsersFile: filepath.Join(home, "missing"), Home: home}); err == nil || !strings.Contains(err.Error(), "the users file: ") {
		t.Errorf("missing users file: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "users.conf")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{UsersFile: dir, Home: home}); err == nil || !strings.Contains(err.Error(), "the users file "+dir+" is a directory: Docker creates one when the host file of a bind mount does not exist") {
		t.Errorf("users file is a directory: %v", err)
	}
	big := filepath.Join(t.TempDir(), "big")
	write(t, big, strings.Repeat("#\n", maxFileSize))
	if _, err := Build(Options{UsersFile: big, Home: home}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("large users file: %v", err)
	}
	// A key file that Docker made a directory of.
	if err := os.MkdirAll(filepath.Join(home, "foo", ".ssh", "keys", "id.pub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Args: []string{"foo::"}, Home: home}); err == nil || !strings.Contains(err.Error(), "argument 1 (user foo): a key file "+filepath.Join(home, "foo", ".ssh", "keys", "id.pub")+" is a directory") {
		t.Errorf("key file is a directory: %v", err)
	}
}

// TestBuildMixedHashes: plain and hashed passwords together give the
// warning config validate gives for hashes of different classes.
func TestBuildMixedHashes(t *testing.T) {
	t.Parallel()
	m := build(t, Options{Args: []string{"foo:" + secret, "bar:" + bcryptHash(t, secret, 10) + ":e"}, Home: t.TempDir()})
	if warns := validate(t, m.Config); !hasWarning(warns, "password hashes of 2 different kinds or costs") {
		t.Errorf("warnings %q", warns)
	}
}

// TestBuildTrustedFilesOutsideMounts: the users file and the key files are
// trusted files, which CheckFS refuses inside a mount: a key file that a
// client could change, the users file, with its passwords, even in a
// read-only one. Outside /home/<user>/<dir> they are fine.
func TestBuildTrustedFilesOutsideMounts(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows")
	}
	home := t.TempDir()
	upload := filepath.Join(home, "foo", "upload")
	key := filepath.Join(upload, "id.pub")
	write(t, key, pubKey(t)+"\n")
	keys := filepath.Join(home, "foo", ".ssh", "keys")
	if err := os.MkdirAll(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(keys, "id.pub")); err != nil {
		t.Fatal(err)
	}
	m := build(t, Options{Args: []string{"foo::::upload"}, Home: home})
	c := m.Config
	c.Server.HostKeys, c.Server.HostKeyAutoGenerate = []string{filepath.Join(t.TempDir(), "host_key")}, true
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err := c.CheckFS()
	if want := "atmoz directory " + upload + ": covers a key file of foo (" + filepath.Join(keys, "id.pub") + "): clients could change it"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("CheckFS: %v, want %q", err, want)
	}

	home = t.TempDir()
	file := filepath.Join(home, "bar", "docs", "users.conf")
	write(t, file, "bar:"+secret+":::docs\n")
	m = build(t, Options{UsersFile: file, Home: home})
	c = m.Config
	c.Mounts["atmoz1"].ReadOnly = true // --read-only
	c.Server.HostKeys, c.Server.HostKeyAutoGenerate = []string{filepath.Join(t.TempDir(), "host_key")}, true
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err = c.CheckFS()
	if want := "atmoz directory " + filepath.Join(home, "bar", "docs") + ": covers the atmoz users file (" + file + "): clients could read it"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("CheckFS: %v, want %q", err, want)
	}
}
