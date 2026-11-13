// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// showObj and showList build JSON values as encoding/json decodes them
// into any.
type showObj = map[string]any

func showList(s ...string) []any {
	l := make([]any, len(s))
	for i, v := range s {
		l[i] = v
	}
	return l
}

func showMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// decodeShowJSON decodes out, which must hold exactly one JSON object.
func decodeShowJSON(t *testing.T, out string) showObj {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	var v showObj
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, out)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("more than one JSON value: %v\n%s", err, out)
	}
	return v
}

// showMountsConfig sets every key of config show --json, as the GUI's
// init --force writes them (ADR 0013), with a mount name that needs
// quotes, a path with '&', '<' and '>', and a user in an included file.
func showMountsConfig(t *testing.T, dir string) string {
	t.Helper()
	showMkdir(t, filepath.Join(dir, "users.d"))
	writeFile(t, filepath.Join(dir, "users.d", "bob.toml"), "[users.bob]\nauthorized_keys = [\""+authorizedKey(newSigner(t))+"\"]\naccess = { inbox = \"upload\" }\n")
	return `config_version = 1
include = ["users.d/*.toml"]
[server]
listen = ["127.0.0.1:2022", "[::1]:2022"]
host_keys = ["keys/ssh_host_ed25519_key"]
host_key_auto_generate = true
[auth]
methods = ["publickey", "password"]
[defaults]
on_conflict = "reject"
[mounts."My Docs"]
path = "` + filepath.ToSlash(filepath.Join(dir, "docs & <more>")) + `"
create = true
read_only = true
[mounts.inbox]
path = "` + filepath.ToSlash(filepath.Join(dir, "inbox")) + `"
on_conflict = "overwrite"
[audit]
output = "audit/audit.jsonl"
[reload]
disconnect_removed_users = true
`
}

// showMountsWant is config show --json for showMountsConfig, with listen.
func showMountsWant(dir, file string, listen []any) showObj {
	return showObj{
		"file":     file,
		"server":   showObj{"listen": listen, "host_keys": showList(filepath.Join(dir, "keys", "ssh_host_ed25519_key"))},
		"auth":     showObj{"methods": showList("publickey", "password")},
		"defaults": showObj{"on_conflict": "reject"},
		"mounts": showObj{
			"My Docs": showObj{"path": filepath.ToSlash(filepath.Join(dir, "docs & <more>")), "read_only": true, "create": true, "on_conflict": "reject"},
			"inbox":   showObj{"path": filepath.ToSlash(filepath.Join(dir, "inbox")), "read_only": false, "create": false, "on_conflict": "overwrite"},
		},
		"audit":  showObj{"output": filepath.Join(dir, "audit", "audit.jsonl")},
		"reload": showObj{"disconnect_removed_users": true},
	}
}

func TestConfigShowJSON(t *testing.T) {
	for _, tt := range []struct {
		name string
		file func(t *testing.T, dir string) string
		env  map[string]string
		// byEnv names the file with $GOSFTPD_CONFIG instead of --config.
		byEnv bool
		want  func(dir, file string) showObj
	}{
		{
			name: "defaults",
			file: func(_ *testing.T, dir string) string {
				return "config_version = 1\n[server]\nhost_keys = [\"k\"]\n[mounts.m]\npath = \"" + filepath.ToSlash(filepath.Join(dir, "m")) + "\"\n"
			},
			want: func(dir, file string) showObj {
				return showObj{
					"file":     file,
					"server":   showObj{"listen": showList(":2022"), "host_keys": showList(filepath.Join(dir, "k"))},
					"auth":     showObj{"methods": showList("publickey")},
					"defaults": showObj{"on_conflict": "rename"},
					"mounts": showObj{
						"m": showObj{"path": filepath.ToSlash(filepath.Join(dir, "m")), "read_only": false, "create": false, "on_conflict": "rename"},
					},
					"audit":  showObj{"output": "stdout"},
					"reload": showObj{"disconnect_removed_users": false},
				}
			},
		},
		{
			name: "set in the file",
			file: showMountsConfig,
			want: func(dir, file string) showObj {
				return showMountsWant(dir, file, showList("127.0.0.1:2022", "[::1]:2022"))
			},
		},
		{
			name: "environment",
			file: showMountsConfig,
			env: map[string]string{
				config.EnvListen:    "127.0.0.1:2222,[::1]:2222",
				config.EnvLogLevel:  "debug",
				config.EnvLogFormat: "json",
			},
			byEnv: true,
			want: func(dir, file string) showObj {
				return showMountsWant(dir, file, showList("127.0.0.1:2222", "[::1]:2222"))
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			writeFile(t, path, tt.file(t, dir))
			args := []string{"config", "show", "--json"}
			if tt.byEnv {
				t.Setenv(config.EnvConfig, path)
			} else {
				args = append(args, "--config", path)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			code, stdout, stderr := execute(t, args...)
			if code != exitOK || stderr != "" {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			// One object, indented as version --json is, with a newline
			// after it.
			if !strings.HasPrefix(stdout, "{\n  \"file\": ") || !strings.HasSuffix(stdout, "\n}\n") {
				t.Errorf("not an indented object with a newline after it:\n%s", stdout)
			}
			if strings.Contains(stdout, `\u0026`) || strings.Contains(stdout, `\u003c`) {
				t.Errorf("'&' or '<' escaped:\n%s", stdout)
			}
			if got, want := decodeShowJSON(t, stdout), tt.want(dir, path); !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")
				t.Errorf("config show --json:\n%s\nwant:\n%s", gotJSON, wantJSON)
			}
		})
	}
}

// TestConfigShowJSONMatchesTOML checks that every value of config show
// --json is the one config show prints for the key of the same name, and
// that file is the file it names.
func TestConfigShowJSONMatchesTOML(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, showMountsConfig(t, dir))
	t.Setenv(config.EnvListen, "127.0.0.1:2222")

	code, tomlOut, stderr := execute(t, "config", "show", "--config", path)
	if code != exitOK {
		t.Fatalf("show: exit %d: %s", code, stderr)
	}
	code, jsonOut, stderr := execute(t, "config", "show", "--config", path, "--json")
	if code != exitOK {
		t.Fatalf("show --json: exit %d: %s", code, stderr)
	}
	var fromTOML map[string]any
	if _, err := toml.Decode(tomlOut, &fromTOML); err != nil {
		t.Fatal(err)
	}
	fromJSON := decodeShowJSON(t, jsonOut)

	first, _, _ := strings.Cut(tomlOut, "\n")
	if want := "# Effective configuration from " + fromJSON["file"].(string); first != want {
		t.Errorf("file = %q, but config show says %q", fromJSON["file"], first)
	}
	delete(fromJSON, "file")
	showSameValues(t, "", fromJSON, fromTOML)
}

// showSameValues checks that each value in j is the one at the same key in
// tm, recursively.
func showSameValues(t *testing.T, key string, j, tm any) {
	t.Helper()
	jm, ok := j.(map[string]any)
	if !ok {
		if !reflect.DeepEqual(j, tm) {
			t.Errorf("%s = %#v, but config show says %#v", key, j, tm)
		}
		return
	}
	tmm, ok := tm.(map[string]any)
	if !ok {
		t.Errorf("%s is an object, but config show has %#v", key, tm)
		return
	}
	for _, k := range slices.Sorted(maps.Keys(jm)) {
		sub := k
		if key != "" {
			sub = key + "." + k
		}
		v, ok := tmm[k]
		if !ok {
			t.Errorf("%s is not a key of config show", sub)
			continue
		}
		showSameValues(t, sub, jm[k], v)
	}
}

// TestConfigShowJSONNoSecrets checks that no password hash, key, address
// restriction or hook setting of the configuration reaches the JSON,
// while config show prints them all.
func TestConfigShowJSONNoSecrets(t *testing.T) {
	isolate(t)
	hash, err := auth.HashPassword([]byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	showMkdir(t, filepath.Join(dir, "users.d"))
	aliceKey := authorizedKey(newSigner(t))
	carolKey := authorizedKey(newSigner(t))
	writeFile(t, filepath.Join(dir, "users.d", "carol.toml"), `[users.carol]
password_hash = "`+hash+`"
authorized_keys = ["`+carolKey+`"]
access = { inbox = "upload" }
`)
	secrets := []string{
		hash,
		aliceKey, carolKey,
		"198.51.100.0/24",
		"https://hooks.example.com/services/T0KEN-IN-THE-URL",
		"hook.secret",
		"--token=EXEC-TOKEN",
	}
	path := filepath.Join(dir, "config.toml")
	writeFile(t, path, `config_version = 1
include = ["users.d/*.toml"]
[server]
host_keys = ["k"]
[auth]
methods = ["publickey", "password"]
[mounts.inbox]
path = "`+filepath.ToSlash(filepath.Join(dir, "inbox"))+`"
[users.alice]
password_hash = "`+hash+`"
authorized_keys = ["`+aliceKey+`"]
allow_from = ["198.51.100.0/24"]
access = { inbox = "full" }
[[hooks]]
name = "notify"
on = ["fs.upload"]
webhook = { url = "https://hooks.example.com/services/T0KEN-IN-THE-URL", secret_file = "hook.secret" }
[[hooks]]
name = "scan"
on = ["fs.upload"]
exec = { argv = ["`+filepath.ToSlash(filepath.Join(dir, "scan"))+`", "--token=EXEC-TOKEN"] }
`)

	code, tomlOut, stderr := execute(t, "config", "show", "--config", path)
	if code != exitOK {
		t.Fatalf("show: exit %d: %s", code, stderr)
	}
	code, jsonOut, stderr := execute(t, "config", "show", "--config", path, "--json")
	if code != exitOK {
		t.Fatalf("show --json: exit %d: %s", code, stderr)
	}
	for _, s := range secrets {
		if !strings.Contains(tomlOut, s) {
			t.Errorf("config show lacks %q: the test does not test it", s)
		}
		if strings.Contains(jsonOut, s) {
			t.Errorf("config show --json shows %q:\n%s", s, jsonOut)
		}
	}
	for _, s := range []string{"alice", "carol", "password_hash", "authorized_keys", "notify", "scan"} {
		if strings.Contains(jsonOut, s) {
			t.Errorf("config show --json names %q:\n%s", s, jsonOut)
		}
	}
	got := slices.Sorted(maps.Keys(decodeShowJSON(t, jsonOut)))
	if want := []string{"audit", "auth", "defaults", "file", "mounts", "reload", "server"}; !slices.Equal(got, want) {
		t.Errorf("keys = %q, want %q", got, want)
	}
}

// TestConfigShowJSONErrors checks that --json changes nothing about
// failures: the same message on stderr, exit code 2 as without it, and
// nothing on stdout.
func TestConfigShowJSONErrors(t *testing.T) {
	for _, tt := range []struct {
		name  string
		file  string // the configuration file, "" for none
		extra []string
		want  string // in stderr
	}{
		{
			name: "invalid value",
			file: "config_version = 1\n[server]\nhost_keys = [\"k\"]\n[defaults]\non_conflict = \"merge\"\n[mounts.m]\npath = \"/m\"\n",
			want: "1 problem:\n  defaults.on_conflict",
		},
		{
			name: "no mounts",
			file: "config_version = 1\n[server]\nhost_keys = [\"k\"]\n",
			want: "mounts: no mounts configured",
		},
		{
			name: "unknown key",
			file: "config_version = 1\n[server]\nlisten_on = [\":2022\"]\n",
			want: "unknown key server.listen_on",
		},
		{
			name:  "missing file",
			extra: []string{"--config", "missing.toml"},
			want:  "missing.toml",
		},
		{
			name: "no file found",
			want: "Error: no configuration file found",
		},
		{
			name:  "argument",
			extra: []string{"extra"},
			want:  "Error: unknown command \"extra\" for \"gosftpd config show\"\nRun 'gosftpd --help' for usage.\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			dir := t.TempDir()
			t.Chdir(dir)
			args := slices.Clone(tt.extra)
			if tt.file != "" {
				path := filepath.Join(dir, "config.toml")
				writeFile(t, path, strings.ReplaceAll(tt.file, `"/m"`, `"`+filepath.ToSlash(filepath.Join(dir, "m"))+`"`))
				args = append(args, "--config", path)
			} else if len(tt.extra) == 0 {
				noSystemConfig(t)
			}

			code, stdout, stderr := execute(t, append([]string{"config", "show"}, args...)...)
			codeJSON, stdoutJSON, stderrJSON := execute(t, append([]string{"config", "show", "--json"}, args...)...)
			if codeJSON != exitUsage || !strings.Contains(stderrJSON, tt.want) {
				t.Errorf("exit %d, want %d; stderr lacks %q:\n%s", codeJSON, exitUsage, tt.want, stderrJSON)
			}
			if stdoutJSON != "" {
				t.Errorf("stdout: %s", stdoutJSON)
			}
			if code != codeJSON || stderr != stderrJSON || stdout != "" {
				t.Errorf("without --json: exit %d, stdout %q, stderr:\n%s\nwith --json: exit %d, stderr:\n%s", code, stdout, stderr, codeJSON, stderrJSON)
			}
		})
	}
}

// TestConfigShowJSONNotUTF8: a path that is not valid UTF-8 would be
// printed with U+FFFD in its place, naming another file; the command fails
// instead, as for an unusable configuration.
func TestConfigShowJSONNotUTF8(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a file system that takes any bytes in a name")
	}
	isolate(t)
	dir := filepath.Join(t.TempDir(), "caf\xe9")
	showMkdir(t, dir)
	path := filepath.Join(dir, "gosftpd.toml")
	writeFile(t, path, "config_version = 1\n[server]\nhost_keys = [\"k\"]\n[mounts.m]\npath = \"/m\"\n")
	code, out, errOut := execute(t, "config", "show", "--json", "--config", path)
	if code != exitUsage || out != "" || !strings.Contains(errOut, "is not valid UTF-8") {
		t.Errorf("exit %d, stdout %q, stderr:\n%s", code, out, errOut)
	}
	// Without --json, config show prints the bytes as they are.
	if code, out, errOut := execute(t, "config", "show", "--config", path); code != exitOK || !strings.Contains(out, "caf\xe9") {
		t.Errorf("config show: exit %d\n%s%s", code, out, errOut)
	}
}
