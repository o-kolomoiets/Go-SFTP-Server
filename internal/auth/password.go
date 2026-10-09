// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordLen bounds passwords; longer ones are refused without hashing.
const MaxPasswordLen = 1024

// argon2id parameters for new hashes: the OWASP minimum (19 MiB, 2 passes,
// 1 lane). Verification runs before authentication, so memory is the price
// of every attempt; see the semaphore in Authenticator.
const (
	argonMemory  = 19456
	argonTime    = 2
	argonThreads = 1
	argonSaltLen = 16
	argonKeyLen  = 32
)

// Bounds for imported hashes, so that a configured hash cannot make each
// login attempt cost unbounded memory or time.
const (
	maxArgonMemory  = 64 * 1024 // KiB
	maxArgonTime    = 10
	maxArgonThreads = 8
	minBcryptCost   = 10
	maxBcryptCost   = 14
)

// PasswordHash is a parsed password hash in PHC format: argon2id, or bcrypt
// for imported accounts.
type PasswordHash interface {
	verify(password []byte) bool
	// class names the algorithm and cost; hashes of one class take
	// equally long to verify.
	class() string
	// dummy returns a hash of the same class that matches no password.
	dummy() PasswordHash
	// lanes is the number of threads a verification uses.
	lanes() int
}

// PasswordClass names the kind and cost of a hash. Hashes of one class
// take equally long to verify.
func PasswordClass(h PasswordHash) string { return h.class() }

type argon2Hash struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func (h *argon2Hash) class() string {
	return fmt.Sprintf("argon2id m=%d t=%d p=%d len=%d", h.memory, h.time, h.threads, len(h.key))
}

func (h *argon2Hash) lanes() int { return int(h.threads) }

func (h *argon2Hash) dummy() PasswordHash {
	d := &argon2Hash{memory: h.memory, time: h.time, threads: h.threads, salt: make([]byte, len(h.salt)), key: make([]byte, len(h.key))}
	_, _ = rand.Read(d.salt)
	_, _ = rand.Read(d.key)
	return d
}

func (h *argon2Hash) verify(password []byte) bool {
	k := argon2.IDKey(password, h.salt, h.time, h.memory, h.threads, uint32(len(h.key))) //nolint:gosec // G115: key length is bounded by ParsePasswordHash
	return subtle.ConstantTimeCompare(k, h.key) == 1
}

type bcryptHash []byte

func (h bcryptHash) verify(password []byte) bool {
	return bcrypt.CompareHashAndPassword(h, password) == nil
}

func (h bcryptHash) lanes() int { return 1 }

func (h bcryptHash) class() string {
	cost, _ := bcrypt.Cost(h)
	return "bcrypt cost=" + strconv.Itoa(cost)
}

var bcryptRE = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

// bcryptAlphabet is bcrypt's base64 alphabet.
const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func (h bcryptHash) dummy() PasswordHash {
	cost, _ := bcrypt.Cost(h)
	// A random salt and digest: verifying it costs as much as a real hash.
	b := make([]byte, 53)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = bcryptAlphabet[int(b[i])%len(bcryptAlphabet)]
	}
	return bcryptHash(fmt.Sprintf("$2b$%02d$%s", cost, b))
}

// HashPassword returns an argon2id hash of password in PHC format.
func HashPassword(password []byte) (string, error) {
	if err := checkPassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func checkPassword(password []byte) error {
	switch {
	case len(password) == 0:
		return errors.New("empty password")
	case len(password) > MaxPasswordLen:
		return fmt.Errorf("password longer than %d bytes", MaxPasswordLen)
	}
	return nil
}

// ParsePasswordHash parses an argon2id or bcrypt hash and checks that its
// cost is within the bounds gosftpd accepts.
func ParsePasswordHash(s string) (PasswordHash, error) {
	switch {
	case strings.HasPrefix(s, "$argon2id$"):
		return parseArgon2(s)
	case strings.HasPrefix(s, "$2a$"), strings.HasPrefix(s, "$2b$"), strings.HasPrefix(s, "$2y$"):
		// The exact shape: bcrypt.Cost reads only the prefix, and a hash
		// with a bad salt would fail without hashing, faster than others.
		if !bcryptRE.MatchString(s) {
			return nil, errors.New("invalid bcrypt hash: want $2b$<cost>$ and 53 characters of [./A-Za-z0-9]")
		}
		cost, err := bcrypt.Cost([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("invalid bcrypt hash: %w", err)
		}
		if cost < minBcryptCost || cost > maxBcryptCost {
			return nil, fmt.Errorf("bcrypt cost %d is outside %d..%d", cost, minBcryptCost, maxBcryptCost)
		}
		return bcryptHash(s), nil
	case strings.HasPrefix(s, "$argon2i$"), strings.HasPrefix(s, "$argon2d$"):
		return nil, errors.New("only argon2id is supported, not argon2i or argon2d")
	default:
		return nil, errors.New("not an argon2id or bcrypt hash; create one with 'gosftpd user hash-password'")
	}
}

func parseArgon2(s string) (PasswordHash, error) {
	bad := errors.New("invalid argon2id hash: want $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>")
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return nil, bad
	}
	var m, t, p uint64
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, bad
	}
	for i, dst := range []*uint64{&m, &t, &p} {
		name, val, ok := strings.Cut(params[i], "=")
		if !ok || name != "mtp"[i:i+1] {
			return nil, bad
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, bad
		}
		*dst = n
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	key, err2 := enc.DecodeString(parts[5])
	switch {
	case err1 != nil, err2 != nil:
		return nil, bad
	case p < 1 || p > maxArgonThreads:
		return nil, fmt.Errorf("argon2id p=%d is outside 1..%d", p, maxArgonThreads)
	case t < 1 || t > maxArgonTime:
		return nil, fmt.Errorf("argon2id t=%d is outside 1..%d", t, maxArgonTime)
	case m < 8*p || m > maxArgonMemory:
		return nil, fmt.Errorf("argon2id m=%d is outside %d..%d KiB", m, 8*p, maxArgonMemory)
	case len(salt) < 8, len(salt) > 64, len(key) < 16, len(key) > 64:
		return nil, errors.New("invalid argon2id hash: the salt must be 8 to 64 bytes and the hash 16 to 64 bytes")
	}
	return &argon2Hash{memory: uint32(m), time: uint32(t), threads: uint8(p), salt: salt, key: key}, nil
}

// defaultDummy is a hash with the parameters of HashPassword that matches
// no password.
func defaultDummy() PasswordHash {
	return (&argon2Hash{memory: argonMemory, time: argonTime, threads: argonThreads, salt: make([]byte, argonSaltLen), key: make([]byte, argonKeyLen)}).dummy()
}

// passwordClasses returns one dummy hash per class of the configured
// hashes (at least the default class), sorted by class.
func passwordClasses(hashes []PasswordHash) []PasswordHash {
	byClass := map[string]PasswordHash{}
	d := defaultDummy()
	byClass[d.class()] = d
	for _, h := range hashes {
		if _, ok := byClass[h.class()]; !ok {
			byClass[h.class()] = h.dummy()
		}
	}
	out := make([]PasswordHash, 0, len(byClass))
	for _, c := range slices.Sorted(maps.Keys(byClass)) {
		out = append(out, byClass[c])
	}
	return out
}
