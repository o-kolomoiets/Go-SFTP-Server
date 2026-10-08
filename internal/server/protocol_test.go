// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/o-kolomoiets/go-sftp-server/internal/audit"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// Resume (Cyberduck style: WRITE without CREAT/TRUNC) continues the file;
// a write below its old size is refused (DoD M2).
func TestResumeThroughClient(t *testing.T) {
	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	data := strings.Repeat("0123456789", 5000)
	writeRemote(t, c, "/part.bin", data[:20000])

	f, err := c.OpenFile("/part.bin", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("EVIL"), 0); statusCode(err) != 3 {
		t.Errorf("write at offset 0: %v", err)
	}
	if _, err := f.WriteAt([]byte(data[20000:]), 20000); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(e.share, "part.bin")); got != data {
		t.Errorf("resumed file differs (%d bytes)", len(got))
	}
	waitFor(t, func() bool { return strings.Contains(e.auditLog.String(), `"start_offset":20000`) })
	log := e.auditLog.String()
	if !strings.Contains(log, `"event":"fs.denied","op":"fs.upload","path":"/part.bin","reason":"existing data is immutable"`) {
		t.Errorf("refused write not audited:\n%s", log)
	}
	if !strings.Contains(log, `"start_offset":20000,"duration_ms"`) || !strings.Contains(log, `"result":"denied"`) {
		t.Errorf("upload with a refused write not marked denied:\n%s", log)
	}
}

// paramiko put(confirm=True) stats the target after the upload; with the
// rename policy the copy must answer.
func TestStatRedirectThroughClient(t *testing.T) {
	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	writeRemote(t, c, "/a.txt", "new")
	fi, err := c.Stat("/a.txt")
	if err != nil || fi.Size() != 3 {
		t.Errorf("Stat after a renamed upload = %v, %v; want the copy", fi, err)
	}
	// rclone checks from another connection of the same user.
	if fi, err := e.sftp(t).Stat("/a.txt"); err != nil || fi.Size() != 3 {
		t.Errorf("another connection of the user = %v, %v; want the copy", fi, err)
	}
	if fi, err := e.sftpAs(t, "bob").Stat("/a.txt"); err != nil || fi.Size() != int64(len("original content")) {
		t.Errorf("another user = %v, %v; want the original", fi, err)
	}
}

func TestStatVFSThroughClient(t *testing.T) {
	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	st, err := c.StatVFS("/")
	if !vfs.StatFSSupported {
		if err == nil {
			t.Error("statvfs answered on an unsupported platform")
		}
		return
	}
	if err != nil || st.TotalSpace() == 0 || st.Flag&1 != 0 {
		t.Errorf("StatVFS = %+v, %v", st, err)
	}
	ro := start(t, vfs.ConflictRename, true).sftp(t)
	if st, err := ro.StatVFS("/"); err != nil || st.Flag&1 == 0 {
		t.Errorf("read-only mount: %+v, %v", st, err)
	}
}

func TestVirtualOwners(t *testing.T) {
	e := start(t, vfs.ConflictRename, false)
	c := e.sftp(t)
	fi, err := c.Stat("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := c.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, fi := range append(entries, fi) {
		st, ok := fi.Sys().(*sftp.FileStat)
		if !ok || st.UID != 1000 || st.GID != 1000 {
			t.Errorf("%s: owner %+v, want the virtual uid/gid 1000", fi.Name(), fi.Sys())
		}
	}
}

type auditSchema struct {
	Schema  int      `json:"schema"`
	Common  []string `json:"common"`
	Context []string `json:"context"`
	Events  map[string]struct {
		Required []string `json:"required"`
		Optional []string `json:"optional"`
	} `json:"events"`
}

// TestAuditSchema pins the audit format: every line of a session that uses
// every operation must match testdata/audit.schema.json.
func TestAuditSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "audit.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema auditSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}

	all := []string{
		audit.CategoryConn, audit.CategoryAuth, audit.CategorySession, audit.CategoryTransfer,
		audit.CategoryModify, audit.CategoryDenied, audit.CategoryList, audit.CategoryStat,
	}
	e := startWith(t, startOpts{policy: vfs.ConflictRename, categories: all})
	if _, err := e.dial(t, signer(t)); err == nil {
		t.Fatal("unknown key accepted")
	}
	conn, err := e.dial(t, e.userKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	writeRemote(t, c, "/new.txt", "x")
	writeRemote(t, c, "/a.txt", "copy")
	if _, err := c.Stat("/a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lstat("/new.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := readRemote(t, c, "/new.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadDir("/"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []error{
		c.Mkdir("/d"),
		c.Rename("/new.txt", "/d/new.txt"),
		c.PosixRename("/d/new.txt", "/a.txt"),
		c.Chtimes("/a.txt", time.Now(), time.Now()),
		c.Remove("/a (2).txt"),
		c.RemoveDirectory("/d"),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	f, err := c.OpenFile("/a (1).txt", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("+"), 4); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.Symlink("/a.txt", "/l"); err == nil {
		t.Fatal("symlink created")
	}
	c.Close()
	conn.Close()

	want := []string{
		"conn.accept", "auth.failure", "auth.success", "session.start", "fs.upload", "fs.download",
		"fs.list", "fs.stat", "fs.mkdir", "fs.rename", "fs.setstat", "fs.remove", "fs.rmdir", "fs.denied", "session.end", "conn.close",
	}
	var (
		lines   []map[string]any
		missing string
	)
	waitForMsg(t, func() bool {
		lines = lines[:0]
		seen := map[string]bool{}
		for l := range strings.SplitSeq(strings.TrimSpace(e.auditLog.String()), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("not JSON: %q", l)
			}
			lines = append(lines, m)
			seen[m["event"].(string)] = true
		}
		for _, ev := range want {
			if !seen[ev] {
				missing = ev
				return false
			}
		}
		return true
	}, func() string { return "missing " + missing })

	for _, m := range lines {
		ev, _ := m["event"].(string)
		spec, ok := schema.Events[ev]
		if !ok {
			t.Errorf("event %q is not in the schema", ev)
			continue
		}
		if m["schema"] != float64(schema.Schema) {
			t.Errorf("%s: schema = %v", ev, m["schema"])
		}
		for _, k := range slices.Concat(schema.Common, spec.Required) {
			if _, ok := m[k]; !ok {
				t.Errorf("%s: missing field %q in %v", ev, k, m)
			}
		}
		allowed := slices.Concat(schema.Common, schema.Context, spec.Required, spec.Optional)
		for k := range m {
			if !slices.Contains(allowed, k) {
				t.Errorf("%s: field %q is not in the schema", ev, k)
			}
		}
	}
}

func waitForMsg(t *testing.T, cond func() bool, msg func() string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met in time: %s", msg())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAuditDocCoversSchema keeps docs/audit-log.md in step with the schema.
func TestAuditDocCoversSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "audit.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema auditSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "audit-log.md"))
	if err != nil {
		t.Fatal(err)
	}
	for ev, spec := range schema.Events {
		if !strings.Contains(string(doc), "`"+ev+"`") {
			t.Errorf("docs/audit-log.md does not list `%s`", ev)
		}
		for _, f := range slices.Concat(schema.Common, schema.Context, spec.Required, spec.Optional) {
			if !strings.Contains(string(doc), "`"+f+"`") {
				t.Errorf("docs/audit-log.md does not describe the field `%s` (%s)", f, ev)
			}
		}
	}
}
