// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUsersFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := &Config{File: filepath.Join(dir, "gosftpd.toml")}
	if _, err := c.UsersFile("bob"); err == nil || !strings.Contains(err.Error(), `include = ["users.d/*.toml"]`) {
		t.Errorf("without include: %v", err)
	}
	c.Include = []string{"*/x/*.toml", "keys/*.pub", "users.d/*.toml"}
	if got, err := c.UsersFile("bob"); err != nil || got != filepath.Join(dir, "users.d", "bob.toml") {
		t.Errorf("UsersFile = %q, %v", got, err)
	}
	odd := &Config{File: filepath.Join(dir, "etc[1]", "gosftpd.toml"), Include: []string{"users.d/*.toml"}}
	if got, err := odd.UsersFile("bob"); err != nil || got != filepath.Join(dir, "etc[1]", "users.d", "bob.toml") {
		t.Errorf("UsersFile in a directory with [ = %q, %v", got, err)
	}
	abs := filepath.Join(dir, "partners")
	c.Include = []string{filepath.Join(abs, "p-*.toml"), filepath.Join(abs, "*.toml")}
	if got, err := c.UsersFile("bob"); err != nil || got != filepath.Join(abs, "bob.toml") {
		t.Errorf("UsersFile with absolute patterns = %q, %v", got, err)
	}
}

const usersFile = `# Partners; keep this comment.
[users.alice]  # the first one
authorized_keys = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl a",
]
access = { inbox = "upload" }

[users."bob.smith"]
password_hash = "x"
disabled = false # set by hand

[users."bob.smith".access]
inbox = "read"

[users.carol]
access = { inbox = "read" }
`

func TestEditUser(t *testing.T) {
	t.Parallel()

	data := []byte(usersFile)
	out, changed, err := EditUser("f.toml", data, "alice", DisableUser)
	if err != nil || !changed {
		t.Fatalf("disable alice: %v, %v", changed, err)
	}
	if !strings.Contains(string(out), "[users.alice]  # the first one\ndisabled = true\n") || !strings.Contains(string(out), "# Partners; keep this comment.") {
		t.Errorf("disable alice:\n%s", out)
	}
	if _, changed, err := EditUser("f.toml", out, "alice", DisableUser); err != nil || changed {
		t.Errorf("disabling twice: %v, %v", changed, err)
	}

	out, changed, err = EditUser("f.toml", data, "bob.smith", DisableUser)
	if err != nil || !changed || !strings.Contains(string(out), "disabled = true # set by hand\n") {
		t.Errorf("disable bob.smith (%v, %v):\n%s", changed, err, out)
	}
	out, _, err = EditUser("f.toml", out, "bob.smith", EnableUser)
	if err != nil || string(out) != usersFile {
		t.Errorf("enable after disable did not restore the file (%v):\n%s", err, out)
	}

	out, changed, err = EditUser("f.toml", data, "bob.smith", RemoveUser)
	if err != nil || !changed {
		t.Fatalf("remove bob.smith: %v, %v", changed, err)
	}
	users, err := ParseUsers("f.toml", out)
	if err != nil || len(users) != 2 || users["alice"] == nil || users["carol"] == nil {
		t.Errorf("after removing bob.smith: %v, %v\n%s", users, err, out)
	}
	if strings.Contains(string(out), "bob") {
		t.Errorf("a table of the removed user is left:\n%s", out)
	}

	if _, _, err := EditUser("f.toml", data, "dave", RemoveUser); err == nil {
		t.Error("removing an unknown user succeeded")
	}
	inline := []byte("[users]\nalice = { access = { inbox = \"read\" } }\n")
	if _, _, err := EditUser("f.toml", inline, "alice", DisableUser); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Errorf("an inline table: %v", err)
	}
}

// Removing a user takes its own comment with it and leaves the comment
// of the next user above that user.
func TestRemoveUserKeepsComments(t *testing.T) {
	t.Parallel()

	data := "# Team file\n\n# Partner A, ticket 1\n[users.a]\naccess = { inbox = \"read\" }\n\n# Partner B, keep until 2027\n[users.b]\naccess = { inbox = \"read\" }\n"
	out, changed, err := EditUser("f.toml", []byte(data), "a", RemoveUser)
	want := "# Team file\n\n\n# Partner B, keep until 2027\n[users.b]\naccess = { inbox = \"read\" }\n"
	if err != nil || !changed || string(out) != want {
		t.Errorf("remove a (%v, %v):\n%s\nwant:\n%s", changed, err, out, want)
	}
}

func TestKeyPath(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"users.bob":             "users|bob",
		` users . "bob.smith" `: "users|bob.smith",
		`users.'x'.access`:      "users|x|access",
		`users.`:                "",
		`users..bob`:            "",
		`users."b\"ob"`:         "",
		`users bob`:             "",
	} {
		if got := strings.Join(keyPath(in), "|"); got != want {
			t.Errorf("keyPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseUsersRefusesOtherTables(t *testing.T) {
	t.Parallel()

	if _, err := ParseUsers("f.toml", []byte("[server]\nlisten = [\":1\"]\n")); err == nil {
		t.Error("an included file with [server] accepted")
	}
}
