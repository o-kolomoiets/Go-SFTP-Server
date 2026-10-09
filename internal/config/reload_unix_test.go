// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A key file that is not a regular file, such as the pipe of
// --authorized-keys <(...), can be read only once: a reload keeps the keys
// read before instead of blocking on it.
func TestBuildAuthenticatorReloadPipe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.WriteFile(keys, []byte(pubKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zero := Default()
	zero.AnyUser = &ZeroConfigUser{AuthorizedKeysFile: keys}
	_, files, _, err := zero.BuildAuthenticator(AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(keys, 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, _, err := zero.BuildAuthenticator(AuthOptions{Reload: true, Previous: files})
	if err != nil || a.Len() != 1 {
		t.Errorf("reload with a pipe = %d keys, %v; want the key read before", a.Len(), err)
	}
	a, _, _, err = zero.BuildAuthenticator(AuthOptions{Reload: true})
	if err != nil || a.Len() != 0 {
		t.Errorf("reload with a pipe not read before = %d keys, %v", a.Len(), err)
	}
}
