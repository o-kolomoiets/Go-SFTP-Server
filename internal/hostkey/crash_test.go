// SPDX-License-Identifier: Apache-2.0

package hostkey

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
)

var errCrash = errors.New("simulated crash")

// crashAt makes the file operations of the steps fail from the n-th on, as
// if the process died there (later ones do nothing either), and returns
// how many ran and a function that restores them.
func crashAt(n int) (count func() int, restore func()) {
	ops := 0
	fail := func() bool { ops++; return n > 0 && ops >= n }
	link, rename, remove, create := osLink, osRename, osRemove, osCreateTemp
	osLink = func(a, b string) error {
		if fail() {
			return errCrash
		}
		return link(a, b)
	}
	osRename = func(a, b string) error {
		if fail() {
			return errCrash
		}
		return rename(a, b)
	}
	osRemove = func(a string) error {
		if fail() {
			return errCrash
		}
		return remove(a)
	}
	osCreateTemp = func(dir, pattern string) (*os.File, error) {
		if fail() {
			return nil, errCrash
		}
		return create(dir, pattern)
	}
	return func() int { return ops }, func() { osLink, osRename, osRemove, osCreateTemp = link, rename, remove, create }
}

// files describes the key files of P: which key each holds and which key
// its .pub and certificate describe ("-" for none).
type files map[string]string

func describe(t *testing.T, p string, names map[string]string) files {
	t.Helper()
	got := files{}
	name := func(k ssh.PublicKey) string {
		if n, ok := names[Fingerprint(k)]; ok {
			return n
		}
		return "?"
	}
	for _, f := range []string{p, Next(p), Old(p)} {
		suffix := f[len(p):]
		got["key"+suffix], got["pub"+suffix], got["cert"+suffix] = "-", "-", "-"
		if k, err := Load(f); err == nil {
			got["key"+suffix] = name(k.PublicKey())
		}
		if k, err := readPublic(f + ".pub"); err == nil {
			got["pub"+suffix] = name(k)
		}
		if data, err := os.ReadFile(Cert(f)); err == nil {
			if c, err := parseCert(data); err == nil {
				got["cert"+suffix] = name(c.Key)
			}
		}
	}
	return got
}

// TestRotationCrash interrupts every step at each of its file operations
// and then runs each step. Whatever happens, P holds a key, no certificate
// of a key that still exists is lost, and after a step that succeeds
// every .pub file and certificate is with its key.
func TestRotationCrash(t *testing.T) {
	ca := mustSigner(t)
	type state struct {
		name  string
		setup func(t *testing.T, p string)
	}
	certified := func(t *testing.T, p string) {
		t.Helper()
		if _, err := Generate(p); err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, p)
		if _, _, err := StartRotation(p, "", nil); err != nil {
			t.Fatal(err)
		}
		writeCert(t, ca, Next(p))
	}
	states := []state{
		{"rotating", certified},
		{"finished", func(t *testing.T, p string) {
			t.Helper()
			certified(t, p)
			if _, err := FinishRotation(p, nil); err != nil {
				t.Fatal(err)
			}
		}},
	}
	steps := map[string]func(p string) error{
		"finish":   func(p string) error { _, err := FinishRotation(p, nil); return err },
		"rollback": func(p string) error { _, err := RollbackRotation(p, nil); return err },
		"retire":   func(p string) error { _, err := RetireRotation(p, nil); return err },
		"abort":    func(p string) error { _, err := AbortRotation(p, nil); return err },
	}
	// interrupt sets up st in a new directory and runs step until its n-th
	// file operation; it reports whether the step was interrupted.
	interrupt := func(t *testing.T, st state, step func(string) error, n int) (p string, names map[string]string, initial files, ok bool) {
		t.Helper()
		p = filepath.Join(t.TempDir(), DefaultFile)
		st.setup(t, p)
		names = map[string]string{}
		for _, f := range []string{p, Next(p), Old(p)} {
			if k, err := Load(f); err == nil {
				names[Fingerprint(k.PublicKey())] = filepath.Base(f)
			}
		}
		initial = describe(t, p, names)
		_, restore := crashAt(n)
		err := step(p)
		restore()
		return p, names, initial, errors.Is(err, errCrash)
	}
	for _, st := range states {
		for crashed, step := range steps {
			for n := 1; ; n++ {
				if _, _, _, ok := interrupt(t, st, step, n); !ok {
					break // the step ran to its end before the n-th operation
				}
				for then, again := range steps {
					p, names, initial, _ := interrupt(t, st, step, n)
					before := describe(t, p, names)
					err := again(p)
					after := describe(t, p, names)
					where := st.name + ": " + crashed + " stopped at file operation " + strconv.Itoa(n) + ", then " + then
					if after["key"] == "-" {
						t.Fatalf("%s: P holds no key", where)
					}
					// No certificate of a key that is still there is lost,
					// neither by the interrupted step nor by the next.
					for _, k := range []string{initial["cert"], initial["cert.next"], initial["cert.old"], before["cert"], before["cert.next"], before["cert.old"]} {
						if k == "-" || k == "?" || !holds(after, k) {
							continue
						}
						if after["cert"] != k && after["cert.next"] != k && after["cert.old"] != k {
							t.Errorf("%s: the certificate of %s is lost: %v -> %v (err %v)", where, k, before, after, err)
						}
					}
					if err != nil {
						continue
					}
					for _, s := range []string{"", ".next", ".old"} {
						k := after["key"+s]
						if k == "-" {
							if after["pub"+s] != "-" || after["cert"+s] != "-" {
								t.Errorf("%s: files of the missing key file P%s are left: %v", where, s, after)
							}
							continue
						}
						if after["pub"+s] != k || after["cert"+s] != "-" && after["cert"+s] != k {
							t.Errorf("%s: the files of P%s do not match its key: %v", where, s, after)
						}
					}
				}
			}
		}
	}
}

// holds reports whether one of the key files holds key.
func holds(f files, key string) bool {
	return f["key"] == key || f["key.next"] == key || f["key.old"] == key
}
