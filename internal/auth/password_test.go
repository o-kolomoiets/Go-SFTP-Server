// SPDX-License-Identifier: Apache-2.0

package auth

import (
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

// TestPasswordTiming checks that an unknown user is refused about as slowly
// as a wrong password (M3 DoD: medians within 10%).
func TestPasswordTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	h, err := HashPassword([]byte("alice pw"))
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := ParsePasswordHash(h)
	a := NewUsers([]User{{Name: "alice", Password: ph}})
	a.Password(fakeConn{user: "mallory"}, []byte("warm up")) //nolint:errcheck // warms up the dummy hash

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
	// difference (an unknown user not hashing) fails every round.
	var report strings.Builder
	for range 3 {
		var known, unknown []time.Duration
		for range 15 {
			known = append(known, measure("alice"))
			unknown = append(unknown, measure("mallory"))
		}
		mk, mu := median(known), median(unknown)
		diff := float64(mk-mu) / float64(mk)
		if diff <= 0.1 && diff >= -0.1 {
			return
		}
		fmt.Fprintf(&report, "\n  median wrong password %v, unknown user %v: %+.0f%%", mk, mu, 100*diff)
	}
	t.Errorf("unknown users are refused at a different speed than wrong passwords:%s", report.String())
}
