// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// uploadBytesEnv is the size of the upload in TestServeReloadDuringUpload.
const uploadBytesEnv = "GOSFTPD_TEST_UPLOAD_BYTES"

// TestServeReloadDuringUpload (ROADMAP M4 DoD): a reload that adds a user
// during an upload lets the user log in, and the upload completes, whole.
// The second half of the upload is written while the reload is applied and
// the user logs in, and its last chunk once the user has listed the mount.
// The size is $GOSFTPD_TEST_UPLOAD_BYTES, 64 MiB by default; one cell of
// the CI job test uploads the DoD's 1 GiB.
func TestServeReloadDuringUpload(t *testing.T) {
	isolate(t)
	size := int64(64 << 20)
	if s := os.Getenv(uploadBytesEnv); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 2 {
			t.Fatalf("%s=%q: want a number of bytes, at least 2", uploadBytesEnv, s)
		}
		size = n
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	alice, bob := newSigner(t), newSigner(t)
	path := filepath.Join(dir, "gosftpd.toml")
	base := `config_version = 1
[server]
listen = ["127.0.0.1:0"]
host_keys = ["state/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "` + filepath.ToSlash(data) + `"
min_free_space = "0"
[users.alice]
authorized_keys = ["` + authorizedKey(alice) + `"]
access = { data = "full" }
`
	writeFile(t, path, base)
	ts := startServe(t, "--config", path)

	conn, err := ts.login("alice", alice)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	f, err := c.Create("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	// Every MiB starts with its offset, so that a chunk out of place
	// changes the checksum.
	chunk := bytes.Repeat([]byte("gosftpd!"), 128<<10)
	sum := sha256.New()
	var written int64
	write := func(until int64) error {
		for written < until {
			binary.BigEndian.PutUint64(chunk, uint64(written))
			p := chunk[:min(int64(len(chunk)), until-written)]
			if _, err := f.Write(p); err != nil {
				return fmt.Errorf("write at %d: %w", written, err)
			}
			sum.Write(p)
			written += int64(len(p))
		}
		return nil
	}
	if err := write(size / 2); err != nil {
		t.Fatal(err)
	}
	loggedIn := make(chan struct{})
	errc := make(chan error, 1)
	// Until it sends on errc, the goroutine alone uses f, chunk, written
	// and sum. It stops waiting when the test ends: a failure before
	// close(loggedIn) does not leave it blocked.
	go func() {
		err := write(size - int64(len(chunk)))
		if err == nil {
			select {
			case <-loggedIn:
				err = write(size)
			case <-t.Context().Done():
				err = t.Context().Err()
			}
		}
		errc <- err
	}()

	writeFile(t, path, base+`[users.bob]
authorized_keys = ["`+authorizedKey(bob)+`"]
access = { data = "read" }
`)
	if ev := ts.reload(t, ts.stdout.String); ev["result"] != "ok" {
		t.Fatalf("server.reload = %v\n%s", ev, ts.stderr.String())
	}
	bconn, err := ts.login("bob", bob)
	if err != nil {
		t.Fatalf("the added user cannot log in during the upload: %v", err)
	}
	bc, err := sftp.NewClient(bconn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bc.ReadDir("/"); err != nil {
		t.Errorf("bob: %v", err)
	}
	bc.Close()
	bconn.Close()

	close(loggedIn)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("the upload does not complete: %v", err)
	}
	got, err := os.Open(filepath.Join(data, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	gotSum := sha256.New()
	if n, err := io.Copy(gotSum, got); err != nil || n != size || !bytes.Equal(gotSum.Sum(nil), sum.Sum(nil)) {
		t.Errorf("big.bin: %d bytes (%v), want %d; same content: %v", n, err, size, bytes.Equal(gotSum.Sum(nil), sum.Sum(nil)))
	}
	out := ts.stdout.String()
	if reload, upload := strings.Index(out, `"event":"server.reload"`), strings.Index(out, `"event":"fs.upload"`); reload < 0 || upload < reload {
		t.Errorf("fs.upload does not follow server.reload:\n%s", out)
	}
	if ups := events(t, out, "fs.upload"); len(ups) != 1 || ups[0]["result"] != "ok" || ups[0]["bytes"] != float64(size) {
		t.Errorf("fs.upload = %v, want ok with %d bytes", ups, size)
	}
}
