// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// readFile returns the repository file at the path elem names.
func readFile(t *testing.T, elem ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{root}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestAtmozUsersFileMode checks that docs/migrate-from-atmoz.md keeps the
// users file, which holds plain passwords, from the other users of the
// host, and that test/docker/atmoz.sh runs the guide's form: the image's
// group 65532 and mode 0640, not the 0644 of a key file.
func TestAtmozUsersFileMode(t *testing.T) {
	t.Parallel()
	guide := readFile(t, "docs", "migrate-from-atmoz.md")
	script := readFile(t, "test", "docker", "atmoz.sh")

	chmods := regexp.MustCompile(`chmod (\S+) (?:<host-dir>/)?users\.conf\b`).FindAllStringSubmatch(guide, -1)
	if len(chmods) == 0 {
		t.Fatal("docs/migrate-from-atmoz.md has no chmod of users.conf")
	}
	for _, m := range chmods {
		if mode, err := strconv.ParseUint(m[1], 8, 32); err != nil || mode&0o007 != 0 {
			t.Errorf("docs/migrate-from-atmoz.md: %q leaves the users file readable by others", m[0])
		}
	}

	// The command of "Store users in config", which atmoz.sh follows.
	cmd := regexp.MustCompile(`sudo chown (\S+) <host-dir>/users\.conf && sudo chmod (\S+) <host-dir>/users\.conf`).FindAllStringSubmatch(guide, -1)
	if len(cmd) != 1 {
		t.Fatalf("docs/migrate-from-atmoz.md has %d \"sudo chown OWNER <host-dir>/users.conf && sudo chmod MODE ...\" commands, want 1", len(cmd))
	}
	owner, mode := cmd[0][1], cmd[0][2]
	if owner != "root:65532" || mode != "0640" {
		t.Errorf("docs/migrate-from-atmoz.md: the users file gets %s %s, want root:65532 0640", owner, mode)
	}
	// atmoz.sh names the owner by numbers, and UID alone for UID:UID.
	numeric := func(owner string) string {
		user, group, ok := strings.Cut(owner, ":")
		if !ok {
			group = user
		}
		id := func(name string) string {
			if name == "root" {
				return "0"
			}
			return name
		}
		return id(user) + ":" + id(group)
	}
	ran := map[string]string{} // chmod and own: the argument atmoz.sh gives them
	for _, m := range regexp.MustCompile(`(?m)^(chmod|own) (\S+) "\$WORK/users\.conf"$`).FindAllStringSubmatch(script, -1) {
		ran[m[1]] = m[2]
	}
	if ran["chmod"] != mode || numeric(ran["own"]) != numeric(owner) {
		t.Errorf("test/docker/atmoz.sh gives users.conf the mode %q and the owner %q, want the guide's %s and %s",
			ran["chmod"], ran["own"], mode, owner)
	}
}
