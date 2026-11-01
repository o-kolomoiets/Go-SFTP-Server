// SPDX-License-Identifier: Apache-2.0

// Package atmoz reads the users of atmoz/sftp, the Docker image that
// gosftpd can replace unchanged (ADR 0012): user specs
// user:pass[:e][:uid[:gid[:dir1[,dir2]...]]] from a users file, from the
// arguments and from $SFTP_USERS, and builds the configuration of atmoz
// mode from them.
//
// No message of this package contains a password or a raw spec, which
// atmoz itself logs: stderr reaches docker logs, log shippers and journald.
// Messages name the source and position, the user name once it is valid,
// and the field that is wrong.
package atmoz

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/o-kolomoiets/go-sftp-server/internal/auth"
	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// EnvUsers is atmoz's variable with user specs, separated by spaces.
const EnvUsers = "SFTP_USERS"

// maxPassword is atmoz's limit of a password field, in characters.
const maxPassword = 255

// specTest is atmoz's own test of whether an argument is a user spec (its
// entrypoint's reArgsMaybe, ^[^:[:space:]]+:.*$): a character other than
// ':' and white space, then ':'.
var specTest = regexp.MustCompile(`^[^:[:space:]]+:`)

// LooksLikeSpec reports whether arg passes atmoz's test of a user spec.
func LooksLikeSpec(arg string) bool { return specTest.MatchString(arg) }

// Kind is where a spec comes from. The kinds are in atmoz's order: the
// users file, the arguments, then $SFTP_USERS.
type Kind int

// Kinds of sources.
const (
	File Kind = iota // a line of the users file
	Arg              // an argument
	Env              // an entry of $SFTP_USERS
)

// Source is where a spec comes from.
type Source struct {
	Kind Kind
	Path string // the users file
	Pos  int    // the line, argument or entry, from 1
}

// String names the source as messages do: "argument 2", "SFTP_USERS entry
// 3", "/etc/sftp/users.conf line 4".
func (s Source) String() string {
	switch s.Kind {
	case Arg:
		return "argument " + strconv.Itoa(s.Pos)
	case Env:
		return EnvUsers + " entry " + strconv.Itoa(s.Pos)
	case File:
	}
	return s.Path + " line " + strconv.Itoa(s.Pos)
}

// Spec is a parsed user spec.
type Spec struct {
	Source Source
	User   string
	// Password is a plain password, Hash one marked with :e. At most one
	// is set; with neither the user logs in with keys only.
	Password, Hash string
	// IDs reports that the spec gives a uid or a gid, which gosftpd
	// ignores: its users are virtual.
	IDs bool
	// Dirs are the directories the spec names, in its order.
	Dirs []string
}

// Error is a spec that cannot be used. It never holds the password or the
// raw spec.
type Error struct {
	Source Source
	User   string // once it is valid
	Msg    string
}

func (e *Error) Error() string { return where(e.Source, e.User) + ": " + e.Msg }

// where names a spec in messages: its source, and the user once it is
// valid.
func where(src Source, user string) string {
	if user == "" {
		return src.String()
	}
	return src.String() + " (user " + user + ")"
}

// Parse parses the spec raw from src, split as atmoz's create-sftp-user
// splits it.
func Parse(raw string, src Source) (Spec, error) {
	s := Spec{Source: src}
	fail := func(format string, args ...any) error {
		return &Error{Source: src, User: s.User, Msg: fmt.Sprintf(format, args...)}
	}
	if strings.ContainsAny(raw, "\n\r") {
		return Spec{}, fail("contains a line break")
	}
	f := split(raw)
	field := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	if !auth.ValidUserName(f[0]) {
		// Not shown: a mistyped spec may begin with its password.
		return Spec{}, fail("the user name is not one gosftpd accepts: use lowercase letters, digits, '.', '_' and '-' (at most 32, starting with a letter or digit)")
	}
	s.User = f[0]
	pass := field(1)
	if utf8.RuneCountInString(pass) > maxPassword {
		return Spec{}, fail("the password is longer than %d characters", maxPassword)
	}
	next := 2 // the uid
	hashed := field(2) == "e"
	if hashed {
		next = 3
	}
	if len(f) > next+3 {
		return Spec{}, fail("too many fields: the syntax is user:pass[:e][:uid[:gid[:dir1[,dir2]...]]], with ',' between directories")
	}
	uid, gid := field(next), field(next+1)
	if !digits(uid) {
		return Spec{}, fail("the uid is not a number")
	}
	if !digits(gid) {
		return Spec{}, fail("the gid is not a number")
	}
	s.IDs = uid != "" || gid != ""
	switch {
	case pass == "":
		// Keys only, also with :e, as atmoz disables the password.
	case hashed:
		if err := checkHash(pass); err != nil {
			return Spec{}, fail("the password hash (:e) cannot be used: %v", err)
		}
		s.Hash = pass
	default:
		s.Password = pass
	}
	for d := range strings.SplitSeq(field(next+2), ",") {
		if d == "" {
			continue // a,,b and a trailing comma, which atmoz skips too
		}
		switch {
		case strings.Contains(d, "/"):
			return Spec{}, fail("directory %q: nested directories are not supported; name a directory directly under the user's home", d)
		case d == ".ssh":
			return Spec{}, fail("directory .ssh holds the user's keys; name another directory")
		case !vfs.ValidMountName(d):
			return Spec{}, fail("directory %q is not a valid name: %s", d, nameRule)
		}
		if prev, ok := foldFind(s.Dirs, d); ok {
			if prev == d {
				continue
			}
			return Spec{}, fail("directories %q and %q differ only in case", prev, d)
		}
		s.Dirs = append(s.Dirs, d)
	}
	return s, nil
}

// nameRule says what a directory name may be: a gosftpd mount name (ROADMAP
// §6.1 item 3).
const nameRule = "use letters, digits, '.', '_', '-' and spaces (at most 64, not starting with '.', not a device name such as NUL)"

// split splits a spec at ':' as bash's read -ra with IFS=':' does in
// create-sftp-user: a final empty field is dropped, "a:b:" gives a and b.
func split(raw string) []string {
	f := strings.Split(raw, ":")
	if len(f) > 1 && f[len(f)-1] == "" {
		f = f[:len(f)-1]
	}
	return f
}

// digits reports whether s holds only ASCII digits, as atmoz's uid and gid
// patterns ([[:digit:]]*) do.
func digits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// foldFind returns the name of names that equals name ignoring case.
func foldFind(names []string, name string) (string, bool) {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return n, true
		}
	}
	return "", false
}

// cryptHashes are the hashes of crypt(3) that atmoz's chpasswd -e accepts
// and gosftpd does not verify, by prefix.
var cryptHashes = []struct{ prefix, name string }{
	{"$1$", "an MD5-crypt hash"},
	{"$5$", "a SHA-crypt hash"},
	{"$6$", "a SHA-crypt hash"},
	{"$y$", "a yescrypt hash"},
	{"$gy$", "a yescrypt hash"},
	{"$7$", "a scrypt hash"},
}

// errHashTool says how to make a hash gosftpd verifies.
var errHashTool = errors.New("create a hash with 'gosftpd user hash-password'")

// checkHash checks a hash marked with :e: gosftpd verifies argon2id and
// bcrypt with a cost from 10 to 14. Its errors never contain the hash.
func checkHash(h string) error {
	for _, c := range cryptHashes {
		if strings.HasPrefix(h, c.prefix) {
			return fmt.Errorf("it is %s, which gosftpd does not verify (it verifies argon2id and bcrypt); %w", c.name, errHashTool)
		}
	}
	if _, err := auth.ParsePasswordHash(h); err != nil {
		return err
	}
	return nil
}

// hashPrefixes start the hashes a plain password most likely is meant to
// be: one without :e after it is the password itself.
var hashPrefixes = []string{"$argon2id$", "$2a$", "$2b$", "$2y$", "$1$", "$5$", "$6$", "$y$"}

// Warnings returns what is risky about the spec itself: a plain password
// in an argument or in $SFTP_USERS, which anyone who can run docker
// inspect or read the process's command line or environment can see
// (ROADMAP §6.7 never takes a password as an argument), and a plain
// password that looks like a hash. home is the directory of the users'
// homes, /home.
func (s Spec) Warnings(home string) []string {
	if s.Password == "" {
		return nil
	}
	var warns []string
	w := where(s.Source, s.User)
	if s.Source.Kind != File {
		keys := filepath.Join(home, s.User, ".ssh", "keys") + string(filepath.Separator)
		warns = append(warns, w+": the password is in plain text, which anyone who can run docker inspect or read the process's command line or environment can see; give an argon2id hash with ':e' ('gosftpd user hash-password') or log in with keys from "+keys)
	}
	for _, p := range hashPrefixes {
		if strings.HasPrefix(s.Password, p) {
			warns = append(warns, w+": the password looks like a hash, but without ':e' after it the hash itself is the password; add ':e'")
			break
		}
	}
	return warns
}
