// SPDX-License-Identifier: Apache-2.0

package vfs

import (
	"os"
	"time"
)

// What the table remembers per user, across all of the user's connections:
// clients such as rclone spread one transfer over several SSH connections
// (upload on one, rename, set the time and check the size on others).
//
//   - owned: regular files the user created, so that uploaders may rename
//     and set times on them with only the write permission (temporary
//     upload names); an entry holds the file's identity and expires
//     OwnTTL after the user last changed the file. It also holds whether
//     the file's last upload was closed with result ok, for the hooks'
//     "uploaded" mark (ADR 0010).
//   - redirects: stat_redirect, see Session.Stat.
type userState struct {
	owned     map[userKey]ownEntry
	redirects map[userKey]redirect
}

// userKey names a path in a mount directory (shared by the table
// generations that use it); rel is the mount-relative host path.
type userKey struct {
	dir *dir
	rel string
}

type ownEntry struct {
	id      fileID
	until   time.Time
	arrived bool // the last upload was closed with result ok; no rename since
}

// redirect points STAT, LSTAT and SETSTAT of a requested path at the name
// an upload or rename actually used. An upload that OpenWrite opened under
// another name holds its entry while it is open: the entry does not
// expire, and the upload's close starts its RedirectTTL.
type redirect struct {
	final string // mount-relative
	until time.Time
	open  *WriteHandle // the upload holding the entry, or nil
}

const (
	// RedirectTTL is how long a stat redirect lasts after the upload ended
	// or the move.
	RedirectTTL = 60 * time.Second
	// OwnTTL is how long a user's own upload keeps its "own" status after
	// the user last changed it.
	OwnTTL = time.Hour

	maxRedirects  = 1024 // per user
	maxOwned      = 4096 // per user
	maxUserStates = 8192 // users with recorded state
)

// state returns the user's state, creating it; t.umu must be held. It
// returns nil when too many users have state (zero-config accepts any
// name): then nothing is recorded, which only costs convenience.
func (t *Table) state(user string) *userState {
	if st := t.users[user]; st != nil {
		return st
	}
	if len(t.users) >= maxUserStates {
		t.sweep()
		if len(t.users) >= maxUserStates {
			return nil
		}
	}
	st := &userState{owned: map[userKey]ownEntry{}, redirects: map[userKey]redirect{}}
	t.users[user] = st
	return st
}

// lookup returns the user's state without creating it; t.umu must be held.
func (t *Table) lookup(user string) *userState { return t.users[user] }

// tidy drops the user's state once it holds nothing; t.umu must be held.
func (t *Table) tidy(user string) {
	if st := t.users[user]; st != nil && len(st.owned) == 0 && len(st.redirects) == 0 {
		delete(t.users, user)
	}
}

// sweep removes expired entries and empty states; t.umu must be held.
func (t *Table) sweep() {
	now := t.now()
	for user, st := range t.users {
		for k, e := range st.owned {
			if now.After(e.until) {
				delete(st.owned, k)
			}
		}
		for k, r := range st.redirects {
			if r.open == nil && now.After(r.until) {
				delete(st.redirects, k)
			}
		}
		t.tidy(user)
	}
}

// makeRoom keeps a map below max: expired entries go first, then the one
// that expires soonest (the newest entry is the one a client is about to
// use). until returns when an entry expires and whether an open upload
// holds it. A held entry is never dropped, so with every entry held the
// map grows past max, by no more than the uploads the user has open, until
// their entries expire after the uploads ended.
func makeRoom[V ownEntry | redirect](m map[userKey]V, limit int, now time.Time, until func(V) (time.Time, bool)) {
	if len(m) < limit {
		return
	}
	var (
		soonest userKey
		first   time.Time // when soonest expires
		found   bool
	)
	for k, v := range m {
		u, held := until(v)
		switch {
		case held:
		case now.After(u):
			delete(m, k)
		case !found || u.Before(first):
			soonest, first, found = k, u, true
		}
	}
	if len(m) >= limit && found {
		delete(m, soonest)
	}
}

func ownUntil(e ownEntry) (time.Time, bool)   { return e.until, false }
func redirUntil(r redirect) (time.Time, bool) { return r.until, r.open != nil }

// own records that the session's user created the file fi at rel;
// arrived records that its upload was closed with result ok.
func (s *Session) own(v *view, rel string, fi os.FileInfo, arrived bool) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	now := t.now()
	st := t.state(s.user)
	if st == nil {
		return
	}
	k := userKey{v.m.dir, rel}
	if _, ok := st.owned[k]; !ok {
		makeRoom(st.owned, maxOwned, now, ownUntil)
	}
	st.owned[k] = ownEntry{id: identify(fi), until: now.Add(OwnTTL), arrived: arrived}
}

// isCreated reports whether rel is a file this user created and nobody has
// changed since: an upload of the user still open on it, or a recorded file
// whose identity still matches.
func (s *Session) isCreated(v *view, rel string) bool {
	cur, err := v.root.Lstat(rel)
	if err != nil || !cur.Mode().IsRegular() {
		return false
	}
	t := s.t
	t.umu.Lock()
	var (
		e    ownEntry
		live bool
	)
	if st := t.lookup(s.user); st != nil {
		var ok bool
		e, ok = st.owned[userKey{v.m.dir, rel}]
		live = ok && !t.now().After(e.until)
	}
	t.umu.Unlock()
	if live && e.id.matches(cur) {
		return true
	}
	// While an upload is open its inode cannot be reused, so the device
	// and inode are proof enough.
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, h := range t.writing {
		if h.owned && h.s.user == s.user && h.v.m.dir == v.m.dir && os.SameFile(h.ino, cur) {
			return true
		}
	}
	return false
}

// ownedFile reports whether fi, a file open at rel, is a file this user
// created and nobody has changed since.
func (s *Session) ownedFile(v *view, rel string, fi os.FileInfo) bool {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	st := t.lookup(s.user)
	if st == nil {
		return false
	}
	e, ok := st.owned[userKey{v.m.dir, rel}]
	return ok && !t.now().After(e.until) && e.id.matches(fi)
}

// clearArrived ends the arrived mark of the user's file at rel: an upload
// to the name again gives up what is there (ADR 0010).
func (s *Session) clearArrived(v *view, rel string) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	if st := t.lookup(s.user); st != nil {
		k := userKey{v.m.dir, rel}
		if e, ok := st.owned[k]; ok && e.arrived {
			e.arrived = false
			st.owned[k] = e
		}
	}
}

// arrived reports whether cur at rel completes an upload of this user: a
// recorded file whose last upload was closed with result ok, unchanged
// since, not renamed since, and with no upload of it open (ADR 0010).
func (s *Session) arrived(v *view, rel string, cur os.FileInfo) bool {
	t := s.t
	t.umu.Lock()
	var (
		e    ownEntry
		live bool
	)
	if st := t.lookup(s.user); st != nil {
		var ok bool
		e, ok = st.owned[userKey{v.m.dir, rel}]
		live = ok && !t.now().After(e.until)
	}
	t.umu.Unlock()
	if !live || !e.arrived || !e.id.matches(cur) {
		return false
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, h := range t.writing {
		if os.SameFile(h.ino, cur) {
			return false
		}
	}
	return true
}

// moveCreated follows a rename by the user. own is whether the file was the
// user's before (checked by isCreated, with its identity and expiry): only
// then is it the user's under the new name, with its new change time.
// Either way, neither name keeps an earlier entry. A rename clears the
// arrived mark; keep (a change in place, such as setting times) keeps it.
func (s *Session) moveCreated(v *view, from, to string, own, keep bool) {
	t := s.t
	t.umu.Lock()
	var e ownEntry
	if st := t.lookup(s.user); st != nil {
		e = st.owned[userKey{v.m.dir, from}]
		delete(st.owned, userKey{v.m.dir, from})
		delete(st.owned, userKey{v.m.dir, to})
		t.tidy(s.user)
	}
	t.umu.Unlock()
	if !own || e.id.fi == nil {
		return
	}
	if cur, err := v.root.Lstat(to); err == nil && os.SameFile(e.id.fi, cur) {
		s.own(v, to, cur, keep && e.arrived)
	}
}

// refreshCreated re-records rel after a change by its owner.
func (s *Session) refreshCreated(v *view, rel string) { s.moveCreated(v, rel, rel, true, true) }

// closedCreated records the final identity of an upload being closed, and
// whether it was closed with result ok. The handle itself proves that the
// file is the user's (its entry may have been evicted while the upload was
// open).
func (s *Session) closedCreated(h *WriteHandle, st os.FileInfo, ok bool) {
	if h.id == nil || !os.SameFile(h.id, st) {
		return
	}
	if cur, err := h.v.root.Lstat(h.rel); err == nil && os.SameFile(cur, st) {
		s.own(h.v, h.rel, st, ok)
	}
}

func (s *Session) forget(v *view, rel string) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	if st := t.lookup(s.user); st != nil {
		delete(st.owned, userKey{v.m.dir, rel})
		t.tidy(s.user)
	}
}

// redirected returns the path STAT, LSTAT and SETSTAT should use for vp.
func (s *Session) redirected(vp string) string {
	v, rel, err := s.resolve(vp)
	if err != nil || v == nil || rel == "." {
		return vp
	}
	if final, ok := s.redirectFor(v, rel); ok {
		return s.virtual(v, final)
	}
	return vp
}

// redirectFor returns the live redirect target of a requested path.
func (s *Session) redirectFor(v *view, rel string) (string, bool) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	st := t.lookup(s.user)
	if st == nil {
		return "", false
	}
	k := userKey{v.m.dir, rel}
	r, ok := st.redirects[k]
	if !ok {
		return "", false
	}
	if r.open == nil && t.now().After(r.until) {
		delete(st.redirects, k)
		t.tidy(s.user)
		return "", false
	}
	return r.final, true
}

// setRedirect points requested at final. open is the upload OpenWrite
// opened to final, which holds the redirect until it is closed, or nil.
func (s *Session) setRedirect(v *view, requested, final string, open *WriteHandle) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	now := t.now()
	st := t.state(s.user)
	if st == nil {
		return
	}
	k := userKey{v.m.dir, requested}
	if _, ok := st.redirects[k]; !ok {
		makeRoom(st.redirects, maxRedirects, now, redirUntil)
	}
	st.redirects[k] = redirect{final: final, until: now.Add(RedirectTTL), open: open}
}

// closedRedirect starts the RedirectTTL of the redirect h held while it
// was open. If another open, a remove or a rename of the name ended the
// redirect meanwhile, it is left as it is: gone, or another upload's.
func (s *Session) closedRedirect(h *WriteHandle) {
	if h.requested == "" {
		return
	}
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	st := t.lookup(s.user)
	if st == nil {
		return
	}
	k := userKey{h.v.m.dir, h.requested}
	if r, ok := st.redirects[k]; ok && r.open == h {
		st.redirects[k] = redirect{final: r.final, until: t.now().Add(RedirectTTL)}
	}
}

func (s *Session) clearRedirect(v *view, rel string) {
	t := s.t
	t.umu.Lock()
	defer t.umu.Unlock()
	if st := t.lookup(s.user); st != nil {
		delete(st.redirects, userKey{v.m.dir, rel})
		t.tidy(s.user)
	}
}
