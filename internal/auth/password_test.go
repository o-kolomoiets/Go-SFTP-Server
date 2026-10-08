// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()

	h, err := HashPassword([]byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("HashPassword() = %q", h)
	}
	ph, err := ParsePasswordHash(h)
	if err != nil {
		t.Fatal(err)
	}
	if !ph.verify([]byte("correct horse")) || ph.verify([]byte("correct horsE")) {
		t.Error("verify does not tell the password apart")
	}
	if h2, _ := HashPassword([]byte("correct horse")); h2 == h {
		t.Error("two hashes of one password are equal: salt is not random")
	}
	for _, pw := range [][]byte{nil, make([]byte, MaxPasswordLen+1)} {
		if _, err := HashPassword(pw); err == nil {
			t.Errorf("HashPassword(%d bytes) accepted", len(pw))
		}
	}
}

func TestParsePasswordHash(t *testing.T) {
	t.Parallel()

	bc, err := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	cheap, _ := bcrypt.GenerateFromPassword([]byte("pw"), 4)
	const salt, key = "c2FsdHNhbHRzYWx0", "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	for _, tt := range []struct {
		hash string
		ok   bool
	}{
		{string(bc), true},
		{"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + key, true},
		{"$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + key, true},
		{string(cheap), false},
		{"$argon2id$v=19$m=2097152,t=2,p=1$" + salt + "$" + key, false}, // 2 GiB per attempt
		{"$argon2id$v=19$m=19456,t=100,p=1$" + salt + "$" + key, false},
		{"$argon2id$v=19$m=19456,t=2,p=64$" + salt + "$" + key, false},
		{"$argon2id$v=19$t=2,m=19456,p=1$" + salt + "$" + key, false},
		{"$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + key, false},
		{"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$!!!", false},
		{"$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$" + key[:8], false},
		{"$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + key, false},
		{"plaintext", false},
		{"", false},
	} {
		if _, err := ParsePasswordHash(tt.hash); (err == nil) != tt.ok {
			t.Errorf("ParsePasswordHash(%q) error = %v, want ok = %v", tt.hash, err, tt.ok)
		}
	}
}

func TestPassword(t *testing.T) {
	t.Parallel()

	hash := func(pw string) PasswordHash {
		h, err := HashPassword([]byte(pw))
		if err != nil {
			t.Fatal(err)
		}
		ph, err := ParsePasswordHash(h)
		if err != nil {
			t.Fatal(err)
		}
		return ph
	}
	bc, _ := bcrypt.GenerateFromPassword([]byte("imported"), 10)
	imported, err := ParsePasswordHash(string(bc))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	a := NewUsers([]User{
		{Name: "alice", Password: hash("alice pw")},
		{Name: "bob", Password: hash("bob pw"), AllowFrom: mustPrefixes(t, "10.0.0.0/8")},
		{Name: "carol", Password: hash("carol pw"), Expires: now.Add(-time.Minute)},
		{Name: "dave", Password: hash("dave pw"), Disabled: true},
		{Name: "erin", Keys: []Key{{Key: newKey(t)}}},
		{Name: "frank", Password: imported},
	})
	a.now = func() time.Time { return now }

	tcp := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 5000} }
	for _, tt := range []struct {
		name, user, pw string
		addr           net.Addr
		ok             bool
	}{
		{"right password", "alice", "alice pw", nil, true},
		{"wrong password", "alice", "bob pw", nil, false},
		{"another user's password", "bob", "alice pw", tcp("10.0.0.1"), false},
		{"allowed address", "bob", "bob pw", tcp("10.0.0.1"), true},
		{"disallowed address", "bob", "bob pw", tcp("192.0.2.1"), false},
		{"expired", "carol", "carol pw", nil, false},
		{"disabled", "dave", "dave pw", nil, false},
		{"no password set", "erin", "", nil, false},
		{"no password set, dummy", "erin", "gosftpd dummy password", nil, false},
		{"unknown user", "mallory", "alice pw", nil, false},
		{"unknown user, dummy", "mallory", "gosftpd dummy password", nil, false},
		{"bcrypt", "frank", "imported", nil, true},
		{"too long", "alice", strings.Repeat("x", MaxPasswordLen+1), nil, false},
	} {
		perms, err := a.Password(fakeConn{user: tt.user, addr: tt.addr}, []byte(tt.pw))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok = %v", tt.name, err, tt.ok)
			continue
		}
		if tt.ok && (perms.Extensions[ExtUser] != tt.user || perms.Extensions[ExtMethod] != MethodPassword) {
			t.Errorf("%s: extensions = %v", tt.name, perms.Extensions)
		}
	}

	// Zero-config has no passwords.
	z := New("", nil)
	if _, err := z.Password(fakeConn{user: "alice"}, []byte("gosftpd dummy password")); err == nil {
		t.Error("zero-config accepted a password")
	}
}

// TestPasswordTiming checks that a password attempt takes equally long
// whichever user it names: unknown, without a password, or with a hash of
// another kind or cost (M3 DoD: medians within 10%).
func TestPasswordTiming(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing test; TestPasswordConstantWork checks the same without timing")
	}
	argon, err := HashPassword([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	def, _ := ParsePasswordHash(argon)
	bc, _ := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	imported, err := ParsePasswordHash(string(bc))
	if err != nil {
		t.Fatal(err)
	}
	// A costlier argon2id than the default.
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	costly, err := ParsePasswordHash("$argon2id$v=19$m=24576,t=3,p=1$" + salt + "$" + key)
	if err != nil {
		t.Fatal(err)
	}
	a := NewUsers([]User{
		{Name: "default", Password: def},
		{Name: "imported", Password: imported},
		{Name: "costly", Password: costly},
		{Name: "keyonly", Keys: []Key{{Key: newKey(t)}}},
	})

	users := []string{"default", "imported", "costly", "keyonly", "mallory"}
	const rounds = 7
	measure := func(user string) time.Duration {
		start := time.Now()
		if _, err := a.Password(fakeConn{user: user}, []byte("wrong")); err == nil {
			t.Fatal("wrong password accepted")
		}
		return time.Since(start)
	}
	median := func(d []time.Duration) time.Duration {
		slices.Sort(d)
		return d[len(d)/2]
	}
	// Noise from other processes can only make one round fail; a real
	// difference fails every round.
	var report strings.Builder
	for range 3 {
		times := make([][]time.Duration, len(users))
		for range rounds {
			for i, u := range users {
				times[i] = append(times[i], measure(u))
			}
		}
		meds := make([]time.Duration, len(users))
		for i := range users {
			meds[i] = median(times[i])
		}
		lo, hi := slices.Min(meds), slices.Max(meds)
		if float64(hi-lo)/float64(hi) <= 0.1 {
			return
		}
		fmt.Fprintf(&report, "\n  medians %v for %v", meds, users)
	}
	t.Errorf("password attempts take different times depending on the user:%s", report.String())
}

// countingHash records which classes an attempt verifies.
type countingHash struct {
	cls, pw string
	calls   map[string]int
}

func (h countingHash) verify(pw []byte) bool {
	h.calls[h.cls]++
	return h.pw != "" && string(pw) == h.pw
}
func (h countingHash) class() string       { return h.cls }
func (h countingHash) dummy() PasswordHash { return countingHash{cls: h.cls, calls: h.calls} }

// TestPasswordConstantWork checks without timing that every attempt
// verifies one hash of each configured class, whichever user it names.
func TestPasswordConstantWork(t *testing.T) {
	t.Parallel()

	calls := map[string]int{}
	a := NewUsers([]User{
		{Name: "alice", Password: countingHash{cls: "a", pw: "alice pw", calls: calls}},
		{Name: "bob", Password: countingHash{cls: "b", pw: "bob pw", calls: calls}},
		{Name: "carol", Password: countingHash{cls: "a", pw: "carol pw", calls: calls}},
		{Name: "dave", Keys: []Key{{Key: newKey(t)}}},
	})
	for _, tt := range []struct {
		user, pw string
		ok       bool
	}{
		{"alice", "alice pw", true},
		{"alice", "wrong", false},
		{"bob", "bob pw", true},
		{"bob", "alice pw", false},
		{"carol", "alice pw", false},
		{"dave", "x", false},
		{"mallory", "x", false},
	} {
		clear(calls)
		_, err := a.Password(fakeConn{user: tt.user}, []byte(tt.pw))
		if (err == nil) != tt.ok {
			t.Errorf("%s/%s: err = %v", tt.user, tt.pw, err)
		}
		if calls["a"] != 1 || calls["b"] != 1 || len(calls) != 2 {
			t.Errorf("%s: verified %v, want one hash of each class", tt.user, calls)
		}
	}
}

func TestPasswordClasses(t *testing.T) {
	t.Parallel()

	bc, _ := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	imported, _ := ParsePasswordHash(string(bc))
	h, _ := HashPassword([]byte("pw"))
	def, _ := ParsePasswordHash(h)
	classes := passwordClasses([]PasswordHash{def, imported, def})
	if len(classes) != 2 {
		t.Fatalf("%d classes, want 2", len(classes))
	}
	for _, d := range classes {
		if d.verify([]byte("pw")) || d.verify(nil) {
			t.Errorf("dummy %s matches a password", d.class())
		}
	}
	// A dummy is well-formed: bcrypt really hashes instead of failing early.
	bd := imported.dummy().(bcryptHash)
	if _, err := bcrypt.Cost(bd); err != nil {
		t.Errorf("bcrypt dummy %q: %v", bd, err)
	}
	if err := bcrypt.CompareHashAndPassword(bd, []byte("pw")); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Errorf("bcrypt dummy compare = %v, want a mismatch after hashing", err)
	}
}
