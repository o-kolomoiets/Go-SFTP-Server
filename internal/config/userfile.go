// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Files of users written by gosftpd user add --write and changed by user
// disable, enable and remove (ROADMAP M4). The main configuration file is
// never rewritten: its comments would be lost.

// UsersFile returns the file user add --write creates for name: NAME.toml
// in the directory of the first include pattern that matches it, such as
// users.d/*.toml.
func (c *Config) UsersFile(name string) (string, error) {
	dir := filepath.Dir(c.File)
	for _, pattern := range c.Include {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(dir, pattern)
		}
		d := filepath.Dir(pattern)
		if strings.ContainsAny(d, "*?[") {
			continue // a directory that is a pattern itself
		}
		file := filepath.Join(d, name+".toml")
		if ok, err := filepath.Match(pattern, file); err == nil && ok {
			return file, nil
		}
	}
	return "", fmt.Errorf("%s includes no directory for user files; add include = [\"users.d/*.toml\"] to it", c.File)
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
		return nil, false, fmt.Errorf("%s: cannot change user %q without touching the rest of the file; change it by hand", file, name)
	}
	return out, true, nil
}

var (
	headerRE   = regexp.MustCompile(`^\s*\[\s*([^\[\]]*?)\s*\]\s*(?:#.*)?$`)
	arrayRE    = regexp.MustCompile(`^\s*\[\[`)
	disabledRE = regexp.MustCompile(`^(\s*disabled\s*=\s*)(true|false)(\s*(?:#.*)?)$`)
)

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
