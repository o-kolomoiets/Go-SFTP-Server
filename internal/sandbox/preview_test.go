// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"slices"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// TestPreviewFS: config validate sees the directories that serve creates
// for mounts with create = true before it computes the rules, and warns
// as serve does: gosftpd init's share next to gosftpd.toml makes the
// directory shared.
func TestPreviewFS(t *testing.T) {
	t.Parallel()
	m := newMemFS(t).files("/home/u/proj/gosftpd.toml").dirs("/home/u/proj/users.d", "/mnt/data").symlink("/data", "/mnt/data")
	c := config.Default()
	c.File, c.Files = native("/home/u/proj/gosftpd.toml"), []string{native("/home/u/proj/gosftpd.toml")}
	c.Include = []string{"users.d/*.toml"}
	c.AddMount("share", native("/home/u/proj/share")).Create = true
	c.AddMount("homes", native("/srv/new/homes/{user}")).Create = true
	c.AddMount("linked", native("/data/up/load")).Create = true
	c.AddMount("later", native("/srv/later")) // not created: serve fails
	in := Input{Config: c, FS: m, ProcSelfFD: -1}
	checkPlan(t, compute(t, in), []string{"dir /home/u/proj " + ro})

	pfs := newPreviewFS(m, c)
	in.FS = pfs
	checkPlan(t, compute(t, in), []string{
		"file /home/u/proj/gosftpd.toml " + rfile,
		"dir /home/u/proj/users.d " + ro,
		"dir /home/u/proj/share " + rw,
		"dir /srv/new/homes " + rw,
		"dir /mnt/data/up/load " + rw,
	}, "configuration: Landlock covers only the file gosftpd.toml in /home/u/proj, which holds share"+shared)

	for path, want := range map[string][]string{
		"/home/u/proj": {"gosftpd.toml", "share", "users.d"},
		"/srv":         {"new"},
		"/srv/new":     {"homes"},
		"/data":        {"up"},
		"/data/up":     {"load"},
	} {
		names, err := pfs.ReadDir(native(path))
		slices.Sort(names)
		if err != nil || !slices.Equal(names, want) {
			t.Errorf("ReadDir(%s) = %v, %v; want %v", path, names, err, want)
		}
	}
	if r, err := pfs.EvalSymlinks(native("/data/up")); err != nil || r != native("/mnt/data/up") {
		t.Errorf("EvalSymlinks(/data/up) = %q, %v", r, err)
	}
	if info, err := pfs.Lstat(native("/srv/new/homes")); err != nil || !info.IsDir() {
		t.Errorf("Lstat(/srv/new/homes) = %v, %v", info, err)
	}
	for _, path := range []string{"/srv/later", "/srv/new/homes/alice", "/home/u/proj/share/x"} {
		if _, err := pfs.Stat(native(path)); err == nil {
			t.Errorf("Stat(%s) found a directory that serve does not create", path)
		}
	}
}
