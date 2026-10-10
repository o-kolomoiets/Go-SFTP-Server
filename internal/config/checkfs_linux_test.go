// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A bind mount shows one directory at two paths; the trusted-file check
// compares identities, not only paths.
func TestTrustedFileThroughBindMount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data, etc := filepath.Join(dir, "data"), filepath.Join(dir, "etc")
	for _, d := range []string{filepath.Join(data, "keys"), etc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mount(filepath.Join(data, "keys"), etc, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mounts unavailable: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(etc, 0) })
	if err := os.WriteFile(filepath.Join(etc, "bob.pub"), []byte(pubKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeConfig(t, dir, `
config_version = 1
[server]
host_keys = ["/nonexistent/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "{dir}/data"
[users.bob]
authorized_keys_file = "{dir}/etc/bob.pub"
access = { data = "full" }
`))
	if err != nil {
		t.Fatal(err)
	}
	mustValidate(t, c)
	if _, _, err := c.CheckFSReload(nil); err == nil || !strings.Contains(err.Error(), "covers the authorized_keys file of bob") {
		t.Errorf("a key file bind-mounted from a writable mount: %v", err)
	}
}

func TestMountInfo(t *testing.T) {
	t.Parallel()

	mi := mountInfo{{"8:1", "/", "/"}, {"8:1", "/srv/data/keys", "/etc/keys"}, {"0:5", "/", "/proc"}}
	for path, want := range map[string]string{
		"/etc/keys/bob.pub": "8:1 /srv/data/keys/bob.pub",
		"/etc/keysx":        "8:1 /etc/keysx",
		"/srv/data":         "8:1 /srv/data",
		"/proc/self":        "0:5 /self",
	} {
		if dev, rel, ok := mi.locate(path); !ok || dev+" "+rel != want {
			t.Errorf("locate(%s) = %s %s %v, want %s", path, dev, rel, ok, want)
		}
	}
	if got := unescapeMount(`/mnt/my\040disk\134x\0`); got != `/mnt/my disk\x\0` {
		t.Errorf("unescapeMount = %q", got)
	}
	if len(readMountInfo()) == 0 {
		t.Error("no mounts in /proc/self/mountinfo")
	}
}
