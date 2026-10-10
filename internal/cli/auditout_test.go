// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// logrotate (create mode) renames the file; after reopen new lines go to a
// new file at the same path, and no line is lost or torn while writers run.
func TestAuditOutputReopen(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename a file that is open, as logrotate does")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	var stdout bytes.Buffer
	a, err := openAuditOutput(path, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	const writers, lines = 4, 200
	for w := range writers {
		wg.Go(func() {
			for i := range lines {
				if _, err := fmt.Fprintf(a, "{\"w\":%d,\"i\":%d}\n", w, i); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for i := range 5 {
		rotated := filepath.Join(dir, fmt.Sprintf("audit.jsonl.%d", i))
		if err := os.Rename(path, rotated); err != nil {
			t.Fatal(err)
		}
		if err := a.reopen(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "audit.jsonl*"))
	total := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for l := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
			if l == "" {
				continue
			}
			if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
				t.Fatalf("torn line %q in %s", l, f)
			}
			total++
		}
	}
	if total != writers*lines {
		t.Errorf("%d lines in %d files, want %d", total, len(files), writers*lines)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout got %q", stdout.String())
	}

	// A file that cannot be reopened fails every write until it can be
	// opened again; the rotated file gets nothing more.
	a, err = openAuditOutput(path, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil { // logrotate cannot create the file
		t.Fatal(err)
	}
	if err := a.reopen(); err == nil {
		t.Fatal("reopen over a directory succeeded")
	}
	if _, err := a.Write([]byte("lost\n")); err == nil {
		t.Error("write without a file succeeded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("recovered\n")); err != nil {
		t.Errorf("write once the file can be created: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "recovered\n" {
		t.Errorf("new file = %q", b)
	}
	if b, _ := os.ReadFile(path + ".old"); strings.Contains(string(b), "lost") {
		t.Error("a line went to the rotated file")
	}

	// Switching to stdout; after Close lines are dropped.
	f, err := openAuditFile("stdout")
	if err != nil || f != nil {
		t.Fatalf("openAuditFile(stdout) = %v, %v", f, err)
	}
	a.use("stdout", f)
	_, _ = a.Write([]byte("to stdout\n"))
	if err := a.reopen(); err != nil {
		t.Errorf("reopen of stdout: %v", err)
	}
	_ = a.Close()
	if n, err := a.Write([]byte("dropped\n")); n != len("dropped\n") || err != nil {
		t.Errorf("write after Close = %d, %v", n, err)
	}
	if stdout.String() != "to stdout\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
}
