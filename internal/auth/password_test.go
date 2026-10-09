// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
		// A bad salt fails without hashing.
		{"$2b$12$" + strings.Repeat("*", 53), false},
		{"$2b$12$" + string(bc[7:]) + "x", false},
		// A 75-byte salt.
		{"$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 100) + "$" + key, false},
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

// TestPasswordTiming checks that a failed password attempt takes equally
// long whichever user it names: unknown, without a password, or with a hash
// of another kind or cost (M3 DoD: medians within 10%).
func TestPasswordTiming(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing test; TestPasswordPadding checks the mechanism")
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

// slowHash takes a fixed time to verify and counts its verifications.
type slowHash struct {
	cls, pw string
	took    time.Duration
	calls   *atomic.Int32
}

func (h slowHash) verify(pw []byte) bool {
	h.calls.Add(1)
	time.Sleep(h.took)
	return h.pw != "" && string(pw) == h.pw
}
func (h slowHash) class() string       { return h.cls }
func (h slowHash) lanes() int          { return 1 }
func (h slowHash) dummy() PasswordHash { return slowHash{cls: h.cls, took: h.took, calls: h.calls} }

// TestPasswordPadding checks the mechanism behind TestPasswordTiming with
// hashes that sleep instead of hashing: each attempt verifies one hash,
// unknown users and users without a password verify the costliest kind,
// and every failure lasts at least as long as the costliest kind.
func TestPasswordPadding(t *testing.T) {
	t.Parallel()

	var fastCalls, slowCalls atomic.Int32
	fast := slowHash{cls: "fast", pw: "alice pw", took: 5 * time.Millisecond, calls: &fastCalls}
	slow := slowHash{cls: "slow", pw: "bob pw", took: 60 * time.Millisecond, calls: &slowCalls}
	a := NewUsers([]User{
		{Name: "alice", Password: fast},
		{Name: "bob", Password: slow},
		{Name: "carol", Keys: []Key{{Key: newKey(t)}}},
	})
	a.pad.classes = []PasswordHash{fast.dummy(), slow.dummy()} // without the real argon2id default
	var slept atomic.Int64
	a.pad.sleep = func(d time.Duration) { slept.Store(int64(d)); time.Sleep(d) }
	a.pad.measure(a) // the first attempt would do this
	target := time.Duration(a.pad.target.Load())
	if target < 72*time.Millisecond || target > 500*time.Millisecond {
		t.Fatalf("target %v, want about 1.2 × 60ms", target)
	}

	attempt := func(user, pw string) (ok bool, took time.Duration, fastN, slowN int32) {
		fastCalls.Store(0)
		slowCalls.Store(0)
		slept.Store(0)
		start := time.Now()
		_, err := a.Password(fakeConn{user: user}, []byte(pw))
		return err == nil, time.Since(start), fastCalls.Load(), slowCalls.Load()
	}
	for _, tt := range []struct {
		user, pw     string
		fastN, slowN int32
	}{
		{"alice", "wrong", 1, 0},
		{"alice", "bob pw", 1, 0},
		{"bob", "wrong", 0, 1},
		{"carol", "x", 0, 1},   // no password: the costliest dummy
		{"mallory", "x", 0, 1}, // unknown: the costliest dummy
		{"mallory", "bob pw", 0, 1},
	} {
		ok, took, fastN, slowN := attempt(tt.user, tt.pw)
		if ok {
			t.Fatalf("%s/%s accepted", tt.user, tt.pw)
		}
		if fastN != tt.fastN || slowN != tt.slowN {
			t.Errorf("%s: verified fast %d, slow %d; want %d, %d", tt.user, fastN, slowN, tt.fastN, tt.slowN)
		}
		if took < target {
			t.Errorf("%s: failure took %v, less than the target %v", tt.user, took, target)
		}
	}
	// A success is not padded.
	if ok, _, _, _ := attempt("alice", "alice pw"); !ok || slept.Load() != 0 {
		t.Errorf("success: ok %v, slept %v", ok, time.Duration(slept.Load()))
	}
	// CheckPassword leaves the wait to the caller: the check and the wait
	// together last the target. (The check itself may run long on a busy
	// machine, so only the sum is fixed.)
	start := time.Now()
	_, wait, err := a.CheckPassword(fakeConn{user: "alice"}, []byte("wrong"))
	checked := time.Since(start)
	if target := time.Duration(a.pad.target.Load()); err == nil || wait <= 0 || checked+wait < target {
		t.Errorf("CheckPassword: checked in %v, wait %v, err %v; want the sum to be at least %v", checked, wait, err, target)
	}

	// Under load the target follows slower verifications, up to four
	// times the measured value. (Slow checks above may have raised it
	// already on a busy machine.)
	a.pad.target.Store(int64(target))
	a.pad.observe(target * 3 / 2)
	if got := time.Duration(a.pad.target.Load()); got != target*3/2 {
		t.Errorf("target after a slower verification = %v, want %v", got, target*3/2)
	}
	a.pad.observe(100 * target)
	if got := time.Duration(a.pad.target.Load()); got != 4*target {
		t.Errorf("target after a very slow verification = %v, want the cap %v", got, 4*target)
	}
}

func TestAcquireLanes(t *testing.T) {
	t.Parallel()

	a := NewUsers(nil)
	slots := cap(a.hashing)
	wide := &argon2Hash{threads: uint8(min(slots+3, 255))}
	if n := a.acquire(wide); n != slots || len(a.hashing) != slots {
		t.Errorf("acquire(p=%d) took %d of %d slots", wide.threads, n, slots)
	}
	a.release(slots)
	if n := a.acquire(bcryptHash("")); n != 1 {
		t.Errorf("acquire(bcrypt) took %d slots", n)
	}
	a.release(1)

	// Two multi-lane verifications and single ones do not deadlock.
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			h := PasswordHash(bcryptHash(""))
			if i%3 == 0 {
				h = wide
			}
			n := a.acquire(h)
			time.Sleep(time.Millisecond)
			a.release(n)
		})
	}
	wg.Wait()
	if len(a.hashing) != 0 {
		t.Errorf("%d slots still held", len(a.hashing))
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
