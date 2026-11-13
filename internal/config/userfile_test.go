// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestSetUser(t *testing.T) {
	t.Parallel()

	const hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI"
	for _, tt := range []struct {
		name, data, user string
		ch               UserChange
		want             string // "" for no change
	}{{
		name: "inline access",
		data: usersFile, user: "alice",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "read", "My Docs": "list,read"}},
		want: strings.Replace(usersFile, `access = { inbox = "upload" }`, `access = { "My Docs" = "list,read", inbox = "read" }`, 1),
	}, {
		name: "inline access with a comment",
		data: "[users.a]\n  access = { inbox = \"upload\" }  # ticket #42\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"outbox": "read"}},
		want: "[users.a]\n  access = { outbox = \"read\" }  # ticket #42\n",
	}, {
		name: "no access, inline",
		data: usersFile, user: "carol",
		ch:   UserChange{SetAccess: true},
		want: strings.Replace(usersFile, "[users.carol]\naccess = { inbox = \"read\" }", "[users.carol]\naccess = {}", 1),
	}, {
		name: "access table",
		data: usersFile, user: "bob.smith",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "upload", "outbox": "read"}},
		want: strings.Replace(usersFile, "[users.\"bob.smith\".access]\ninbox = \"read\"\n", "[users.\"bob.smith\".access]\ninbox = \"upload\"\noutbox = \"read\"\n", 1),
	}, {
		name: "access table keeps its comments",
		data: "[users.a] # A\ndisabled = true\n\n[users.a.access] # grants\n# the inbox\ninbox = \"read\"\nx = \"list\"  # old\n\n# B\n[users.b]\naccess = {}\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"y": "read"}},
		want: "[users.a] # A\ndisabled = true\n\n[users.a.access] # grants\ny = \"read\"\n# the inbox\n\n# B\n[users.b]\naccess = {}\n",
	}, {
		name: "no access, access table",
		data: "[users.a]\n[users.a.access]\ninbox = \"read\"\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{}},
		want: "[users.a]\n[users.a.access]\n",
	}, {
		name: "dotted keys",
		data: "[users.a]\naccess.inbox = \"read\" # one\ndisabled = false\n\"access\".x = \"list\"\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "upload"}},
		want: "[users.a]\naccess = { inbox = \"upload\" }\ndisabled = false\n",
	}, {
		name: "a user without access",
		data: "[users.a]\nauthorized_keys = [\n  \"ssh-ed25519 AAAA a\",\n]\n# the end of a\n\n[users.b]\naccess = {}\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "read"}},
		want: "[users.a]\nauthorized_keys = [\n  \"ssh-ed25519 AAAA a\",\n]\naccess = { inbox = \"read\" }\n# the end of a\n\n[users.b]\naccess = {}\n",
	}, {
		name: "a table without keys at the end of the file",
		data: "[users.b]\naccess = {}\n\n[users.a]",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "read"}},
		want: "[users.b]\naccess = {}\n\n[users.a]\naccess = { inbox = \"read\" }\n",
	}, {
		name: "the same access",
		data: usersFile, user: "alice",
		ch: UserChange{SetAccess: true, Access: map[string]string{"inbox": "upload"}},
	}, {
		name: "no access already",
		data: "[users.a]\ndisabled = true\n",
		user: "a",
		ch:   UserChange{SetAccess: true},
	}, {
		name: "nothing",
		data: usersFile, user: "alice",
	}, {
		name: "a new password",
		data: usersFile, user: "alice",
		ch:   UserChange{PasswordHash: hash},
		want: strings.Replace(usersFile, "access = { inbox = \"upload\" }", "password_hash = \""+hash+"\"\naccess = { inbox = \"upload\" }", 1),
	}, {
		name: "a password replaced",
		data: usersFile, user: "bob.smith",
		ch:   UserChange{PasswordHash: hash},
		want: strings.Replace(usersFile, `password_hash = "x"`, `password_hash = "`+hash+`"`, 1),
	}, {
		name: "a password replaced, with a comment",
		data: "[users.a]\n'password_hash' = 'x#y' # old\r\naccess = {}\r\n",
		user: "a",
		ch:   UserChange{PasswordHash: hash},
		want: "[users.a]\npassword_hash = \"" + hash + "\" # old\r\naccess = {}\r\n",
	}, {
		name: "access and password, CRLF",
		data: "# keep\r\n[users.a]\r\ndisabled = true\r\n[users.a.access]\r\ninbox = \"read\"\r\n",
		user: "a",
		ch:   UserChange{SetAccess: true, Access: map[string]string{"inbox": "upload"}, PasswordHash: hash},
		want: "# keep\r\n[users.a]\r\ndisabled = true\r\npassword_hash = \"" + hash + "\"\r\n[users.a.access]\r\ninbox = \"upload\"\r\n",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, changed, err := SetUser("f.toml", []byte(tt.data), tt.user, tt.ch)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			if want == "" {
				want = tt.data
			}
			if changed != (tt.want != "") || string(out) != want {
				t.Errorf("changed %v:\n%s\nwant:\n%s", changed, out, want)
			}
			users, err := ParseUsers("f.toml", out)
			if err != nil {
				t.Fatal(err)
			}
			u := users[tt.user]
			if tt.ch.SetAccess && len(u.Access) != len(tt.ch.Access) {
				t.Errorf("access = %v, want %v", u.Access, tt.ch.Access)
			}
			for mount, perm := range tt.ch.Access {
				if u.Access[mount] != perm {
					t.Errorf("access = %v, want %v", u.Access, tt.ch.Access)
				}
			}
			if tt.ch.PasswordHash != "" && u.PasswordHash != tt.ch.PasswordHash {
				t.Errorf("password_hash = %q", u.PasswordHash)
			}
		})
	}
}

func TestSetUserRefuses(t *testing.T) {
	t.Parallel()

	access := UserChange{SetAccess: true, Access: map[string]string{"inbox": "read"}}
	for _, tt := range []struct {
		name, data, user, want string
	}{
		{"an unknown user", usersFile, "dave", `does not define user "dave"`},
		{"an inline user table", "[users]\nalice = { access = { inbox = \"upload\" } }\n", "alice", "by hand"},
		{"an access table elsewhere", "[users.a]\ndisabled = true\n[users.b]\naccess = {}\n[users.a.access]\nx = \"read\"\n", "a", "by hand"},
		{"a multi-line value", "[users.a]\naccess = { x = \"read\", y = \"\"\"\nread\"\"\" }\n", "a", "by hand"},
		{"not a file of users", "[server]\nlisten = [\":1\"]\n", "a", "[users.NAME]"},
	} {
		if _, _, err := SetUser("f.toml", []byte(tt.data), tt.user, access); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
}

func TestHasLogin(t *testing.T) {
	t.Parallel()

	past := time.Now().Add(-time.Hour)
	c := &Config{Users: map[string]*User{
		"key":      {AuthorizedKeys: []string{"ssh-ed25519 AAAA"}},
		"disabled": {AuthorizedKeys: []string{"ssh-ed25519 AAAA"}, Disabled: true},
		"expired":  {AuthorizedKeys: []string{"ssh-ed25519 AAAA"}, Expires: &past},
		"password": {PasswordHash: "x"},
	}}
	c.Auth.Methods = []string{"publickey"}
	for name, want := range map[string][2]bool{
		"key": {true, true}, "disabled": {true, false}, "expired": {true, false}, "password": {false, false}, "nobody": {false, false},
	} {
		if got := [2]bool{c.HasLogin(name), c.CanLogIn(name)}; got != want {
			t.Errorf("%s: HasLogin, CanLogIn = %v, want %v", name, got, want)
		}
	}
}

func TestParseUsersRefusesOtherTables(t *testing.T) {
	t.Parallel()

	if _, err := ParseUsers("f.toml", []byte("[server]\nlisten = [\":1\"]\n")); err == nil {
		t.Error("an included file with [server] accepted")
	}
}
