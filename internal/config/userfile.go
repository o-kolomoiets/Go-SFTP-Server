// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Files of users written by gosftpd user add --write and changed by user
// disable, enable and remove (ROADMAP M4) and user set (ADR 0013). The main
// configuration file is never rewritten: its comments would be lost.

// UsersFile returns the file user add --write creates for name: NAME.toml
// in the directory of the first include pattern that matches it, such as
// users.d/*.toml.
func (c *Config) UsersFile(name string) (string, error) {
	dir := filepath.Dir(c.File)
	for _, pattern := range c.Include {
		// Like globInclude: a relative pattern is matched inside dir, which
		// is not a pattern itself even if its name has [ or *.
		base := ""
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Clean(pattern)
			if pattern == ".." || strings.HasPrefix(pattern, ".."+string(filepath.Separator)) {
				continue
			}
			base = dir
		}
		d := filepath.Dir(pattern)
		if strings.ContainsAny(d, "*?[") {
			continue // a directory that is a pattern itself
		}
		file := filepath.Join(d, name+".toml")
		if ok, err := filepath.Match(pattern, file); err == nil && ok {
			return filepath.Join(base, file), nil
		}
	}
	return "", fmt.Errorf("%s includes no directory for user files; add include = [\"users.d/*.toml\"] to it", c.File)
}

// CanLogIn reports whether the user name exists and could log in now: not
// disabled or expired, with a key or password that auth.methods allows.
func (c *Config) CanLogIn(name string) bool {
	u := c.Users[name]
	switch {
	case u == nil, u.Disabled, u.Expires != nil && u.Expires.Before(time.Now()):
		return false
	}
	return c.HasLogin(name)
}

// HasLogin reports whether the user name exists and has a key, password
// or certificate principal that auth.methods allows, whether or not it is
// disabled or expired.
func (c *Config) HasLogin(name string) bool {
	u := c.Users[name]
	return u != nil && (c.usesKeys(u) || c.canUsePassword(u))
}

// ParseUsers decodes the [users.NAME] tables of an included file, as Load
// does.
func ParseUsers(file string, data []byte) (map[string]*User, error) {
	var inc includeFile
	md, err := toml.Decode(string(data), &inc)
	if err != nil {
		return nil, decodeError(file, err)
	}
	if err := errors.Join(unknownKeys(file, md), exactKeys(file, md, reflect.TypeFor[includeFile]())); err != nil {
		return nil, fmt.Errorf("%w (an included file may only define [users.NAME] tables)", err)
	}
	if inc.Users == nil {
		inc.Users = map[string]*User{}
	}
	for name, u := range inc.Users {
		if u == nil {
			inc.Users[name] = &User{}
		}
	}
	return inc.Users, nil
}

// UserEdit is a change EditUser makes.
type UserEdit int

// User edits.
const (
	DisableUser UserEdit = iota
	EnableUser
	RemoveUser
)

// EditUser applies edit to the [users.NAME] table in data, the content of
// file, keeping everything else, comments included. It checks the result by
// decoding it: every other user must be unchanged. changed is false when
// there was nothing to do (the user was disabled already).
func EditUser(file string, data []byte, name string, edit UserEdit) (out []byte, changed bool, err error) {
	before, err := ParseUsers(file, data)
	if err != nil {
		return nil, false, err
	}
	u, ok := before[name]
	switch {
	case !ok:
		return nil, false, fmt.Errorf("%s does not define user %q", file, name)
	case edit == DisableUser && u.Disabled, edit == EnableUser && !u.Disabled:
		return data, false, nil
	}
	lines := strings.SplitAfter(string(data), "\n")
	start, end := userSection(lines, name)
	if start < 0 {
		return nil, false, fmt.Errorf("%s: no [users.%s] table to edit; change the file by hand", file, name)
	}
	switch edit {
	case RemoveUser:
		// The comment lines right above the table go with it; comment and
		// blank lines right before the next table stay with that one.
		for start > 0 && isComment(lines[start-1]) {
			start--
		}
		for end < len(lines) && end > start+1 && (isComment(lines[end-1]) || strings.TrimSpace(lines[end-1]) == "") {
			end--
		}
		lines = append(lines[:start], lines[end:]...)
		delete(before, name)
	case DisableUser, EnableUser:
		set := edit == DisableUser
		lines = setDisabled(lines, start, end, set)
		u.Disabled = set
	}
	out = []byte(strings.Join(lines, ""))
	after, err := ParseUsers(file, out)
	if err != nil || !reflect.DeepEqual(before, after) {
		return nil, false, byHand(file, name)
	}
	return out, true, nil
}

// byHand is the error of an edit that would change more than the user.
func byHand(file, name string) error {
	return fmt.Errorf("%s: cannot change user %q without touching the rest of the file; change it by hand", file, name)
}

// UserChange is what SetUser changes in a user.
type UserChange struct {
	// SetAccess replaces the user's whole access with Access, mount name
	// to permissions; an empty Access leaves the user none.
	SetAccess bool
	Access    map[string]string
	// PasswordHash, unless empty, replaces the user's password_hash.
	PasswordHash string
}

// SetUser applies ch to the [users.NAME] table in data, the content of
// file, keeping everything else, comments included, as EditUser does.
//   - The new access is written where the old one was: as an inline table
//     (access = { ... }, with the mounts sorted), or as the keys of the
//     user's [users.NAME.access] table. A user without access gets the
//     inline table after its last key.
//   - The password hash replaces the value of password_hash, or is added
//     before access.
//
// It checks the result by decoding it: every other user and every other
// field must be unchanged. changed is false when there was nothing to do
// (the same access and no password).
func SetUser(file string, data []byte, name string, ch UserChange) (out []byte, changed bool, err error) {
	before, err := ParseUsers(file, data)
	if err != nil {
		return nil, false, err
	}
	u, ok := before[name]
	if !ok {
		return nil, false, fmt.Errorf("%s does not define user %q", file, name)
	}
	setAccess := ch.SetAccess && !maps.Equal(u.Access, ch.Access)
	if !setAccess && ch.PasswordHash == "" {
		return data, false, nil
	}
	lines := strings.SplitAfter(string(data), "\n")
	start, end := userSection(lines, name)
	if start < 0 {
		return nil, false, fmt.Errorf("%s: no [users.%s] table to edit; change the file by hand", file, name)
	}
	nl := "\n"
	if strings.HasSuffix(lines[start], "\r\n") {
		nl = "\r\n"
	}
	if setAccess {
		lines = replaceAccess(lines, start, end, name, ch.Access, nl)
		u.Access = maps.Clone(ch.Access)
		start, end = userSection(lines, name)
	}
	if ch.PasswordHash != "" {
		lines = setKey(lines, start, end, passwordRE, "password_hash = "+basicString(ch.PasswordHash), nl)
		u.PasswordHash = ch.PasswordHash
	}
	out = []byte(strings.Join(lines, ""))
	after, err := ParseUsers(file, out)
	if err != nil || !reflect.DeepEqual(noNilAccess(before), noNilAccess(after)) {
		return nil, false, byHand(file, name)
	}
	return out, true, nil
}

// replaceAccess writes access into the user's table lines[start:end]:
// into its [users.NAME.access] table if it has one, else as an inline
// table in place of the old access key or its dotted keys (access.MOUNT =
// ...), or after the table's last key.
func replaceAccess(lines []string, start, end int, name string, access map[string]string, nl string) []string {
	mounts := slices.Sorted(maps.Keys(access))
	for i := start + 1; i < end; i++ {
		m := headerRE.FindStringSubmatch(strings.TrimRight(lines[i], "\r\n"))
		if m == nil || arrayRE.MatchString(lines[i]) || !slices.Equal(keyPath(m[1]), []string{"users", name, "access"}) {
			continue
		}
		// The table's keys go; its comments stay, after the new keys.
		body := i + 1
		for body < end && !headerRE.MatchString(strings.TrimRight(lines[body], "\r\n")) && !arrayRE.MatchString(lines[body]) {
			if line := strings.TrimSpace(lines[body]); line != "" && line[0] != '#' {
				lines = slices.Delete(lines, body, body+1)
				end--
				continue
			}
			body++
		}
		keys := make([]string, len(mounts))
		for j, mount := range mounts {
			keys[j] = key(mount) + " = " + basicString(access[mount]) + nl
		}
		if !strings.HasSuffix(lines[i], "\n") {
			lines[i] += nl
		}
		return slices.Insert(lines, i+1, keys...)
	}

	pairs := make([]string, len(mounts))
	for j, mount := range mounts {
		pairs[j] = key(mount) + " = " + basicString(access[mount])
	}
	inline := "access = {}"
	if len(pairs) > 0 {
		inline = "access = { " + strings.Join(pairs, ", ") + " }"
	}
	// Dotted keys go; the inline table takes the place of the first one.
	own := ownKeys(lines, start, end)
	first := -1
	for i := start + 1; i < own; i++ {
		if accessDotRE.MatchString(lines[i]) {
			if first < 0 {
				first = i
			}
			lines = slices.Delete(lines, i, i+1)
			i--
			own--
			end--
		}
	}
	if first >= 0 {
		return slices.Insert(lines, first, inline+nl)
	}
	return setKey(lines, start, end, accessRE, inline, nl)
}

// setKey replaces the line of the key that re matches among the table's
// own keys (before any sub-table) with kv, keeping its indentation and
// comment. Without one, it adds kv before the access key, or after the last
// key.
func setKey(lines []string, start, end int, re *regexp.Regexp, kv, nl string) []string {
	own := ownKeys(lines, start, end)
	for i := start + 1; i < own; i++ {
		if m := re.FindStringSubmatch(lines[i]); m != nil {
			code, comment := splitComment(lines[i])
			eol := lines[i][len(strings.TrimRight(lines[i], "\r\n")):]
			if comment != "" {
				comment = code[len(strings.TrimRight(code, " \t")):] + comment
			}
			lines[i] = m[1] + kv + comment + eol
			return lines
		}
	}
	at := start + 1
	for i := start + 1; i < own; i++ {
		if accessRE.MatchString(lines[i]) {
			at = i
			break
		}
		if line := strings.TrimSpace(lines[i]); line != "" && line[0] != '#' {
			at = i + 1
		}
	}
	if !strings.HasSuffix(lines[at-1], "\n") {
		lines[at-1] += nl
	}
	return slices.Insert(lines, at, kv+nl)
}

// ownKeys returns the end of the lines of a table's own keys: the first
// sub-table header after start, or end.
func ownKeys(lines []string, start, end int) int {
	for i := start + 1; i < end; i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if headerRE.MatchString(line) || arrayRE.MatchString(line) {
			return i
		}
	}
	return end
}

// splitComment splits a line at the # of its comment, outside strings.
func splitComment(line string) (code, comment string) {
	line = strings.TrimRight(line, "\r\n")
	var quote byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return line[:i], line[i:]
		}
	}
	return line, ""
}

// basicString quotes s as a TOML basic string.
func basicString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// noNilAccess gives the users without an access table an empty one, which
// decodes the same.
func noNilAccess(users map[string]*User) map[string]*User {
	for _, u := range users {
		if u.Access == nil {
			u.Access = map[string]string{}
		}
	}
	return users
}

var (
	headerRE    = regexp.MustCompile(`^\s*\[\s*([^\[\]]*?)\s*\]\s*(?:#.*)?$`)
	arrayRE     = regexp.MustCompile(`^\s*\[\[`)
	disabledRE  = regexp.MustCompile(`^(\s*disabled\s*=\s*)(true|false)(\s*(?:#.*)?)$`)
	accessRE    = regexp.MustCompile(`^(\s*)(?:access|"access"|'access')\s*=`)
	accessDotRE = regexp.MustCompile(`^\s*(?:access|"access"|'access')\s*\.`)
	passwordRE  = regexp.MustCompile(`^(\s*)(?:password_hash|"password_hash"|'password_hash')\s*=`)
)

func isComment(line string) bool { return strings.HasPrefix(strings.TrimSpace(line), "#") }

// userSection returns the lines [start, end) of the [users.NAME] table and
// its sub-tables, or start = -1.
func userSection(lines []string, name string) (start, end int) {
	start = -1
	for i, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		if !arrayRE.MatchString(line) && !headerRE.MatchString(line) {
			continue
		}
		var path []string
		if m := headerRE.FindStringSubmatch(line); m != nil && !arrayRE.MatchString(line) {
			path = keyPath(m[1])
		}
		ours := len(path) >= 2 && path[0] == "users" && path[1] == name
		switch {
		case start < 0 && ours && len(path) == 2:
			start = i
		case start >= 0 && !ours:
			return start, i
		}
	}
	return start, len(lines)
}

// setDisabled sets disabled in the table's own keys, before any sub-table.
func setDisabled(lines []string, start, end int, v bool) []string {
	val := "false"
	if v {
		val = "true"
	}
	for i := start + 1; i < end; i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if headerRE.MatchString(line) || arrayRE.MatchString(line) {
			break
		}
		if m := disabledRE.FindStringSubmatch(line); m != nil {
			lines[i] = m[1] + val + m[3] + lines[i][len(line):]
			return lines
		}
	}
	nl := "\n"
	if strings.HasSuffix(lines[start], "\r\n") {
		nl = "\r\n"
	} else if !strings.HasSuffix(lines[start], "\n") {
		lines[start] += nl
	}
	return append(lines[:start+1], append([]string{"disabled = " + val + nl}, lines[start+1:]...)...)
}

// keyPath splits a TOML dotted key of bare and quoted parts; nil if it is
// not one.
func keyPath(s string) []string {
	var path []string
	for s = strings.TrimSpace(s); s != ""; {
		var part string
		switch s[0] {
		case '"', '\'':
			i := strings.IndexByte(s[1:], s[0])
			if i < 0 || s[0] == '"' && strings.Contains(s[1:1+i], `\`) {
				return nil
			}
			part, s = s[1:1+i], s[2+i:]
		default:
			i := strings.IndexFunc(s, func(r rune) bool { return r == '.' || r == ' ' || r == '\t' })
			if i < 0 {
				i = len(s)
			}
			part, s = s[:i], s[i:]
			if part == "" {
				return nil
			}
		}
		path = append(path, part)
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		if s[0] != '.' {
			return nil
		}
		s = strings.TrimSpace(s[1:])
		if s == "" {
			return nil
		}
	}
	return path
}
