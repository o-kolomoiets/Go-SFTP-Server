// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A pipe, such as that of --authorized-keys <(...), can be read only once:
// a reload keeps the keys it gave instead of blocking on it. Any other file
// that is not a regular file gives no keys, so that pointing a key file at
// /dev/null revokes its keys.
func TestBuildAuthenticatorReloadPipe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := syscall.Mkfifo(keys, 0o600); err != nil {
		t.Fatal(err)
	}
	line := pubKey(t) + "\n"
	go func() {
		f, err := os.OpenFile(keys, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = f.WriteString(line)
		_ = f.Close()
	}()
	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: keys}
	a, files, _, err := zero.BuildAuthenticator(AuthOptions{})
	if err != nil || a.Len() != 1 || len(files[keys]) != 1 {
		t.Fatalf("reading a pipe = %d keys, %v, %v", a.Len(), files, err)
	}
	a, _, warns, err := zero.BuildAuthenticator(AuthOptions{Reload: true, Previous: files})
	if err != nil || a.Len() != 1 || len(warns) == 0 || !strings.Contains(warns[0], "is a pipe") {
		t.Errorf("reload with a pipe = %d keys, %q, %v; want the key read before", a.Len(), warns, err)
	}
	if a, _, _, err := zero.BuildAuthenticator(AuthOptions{Reload: true}); err != nil || a.Len() != 0 {
		t.Errorf("reload with a pipe not read before = %d keys, %v", a.Len(), err)
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte(pubKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zero.AnyUser.AuthorizedKeysFile = regular
	_, files, _, err = zero.BuildAuthenticator(AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(regular); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.DevNull, regular); err != nil {
		t.Fatal(err)
	}
	if a, _, _, err := zero.BuildAuthenticator(AuthOptions{Reload: true, Previous: files}); err != nil || a.Len() != 0 {
		t.Errorf("reload with the key file pointed at /dev/null = %d keys, %v", a.Len(), err)
	}
}
