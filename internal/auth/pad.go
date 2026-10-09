// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

// padder makes failed password attempts take about equally long whichever
// user they name. Each attempt verifies one hash: the user's own, or, for
// unknown users and users without a password, a dummy of the costliest
// configured kind and cost. A failure then waits, without using the CPU,
// until the time the costliest hash takes. An attempt never costs more than
// one verification.
//
// With one kind and cost of hash (all made by HashPassword) unknown users
// and real users do exactly the same work, under any load. With several,
// padding hides the difference for attempts one at a time; parallel
// attempts can still tell users of cheaper hashes from the rest, because
// they queue differently. config validate warns about such configurations.
type padder struct {
	classes []PasswordHash // one dummy per configured kind and cost
	sleep   func(time.Duration)

	once   sync.Once
	dummy  PasswordHash // the costliest class, set by measure
	target atomic.Int64 // time a failure takes at least, in nanoseconds
	limit  int64        // the target follows slower checks up to this
}

// newPadder returns a padder for the configured hashes.
func newPadder(hashes []PasswordHash) *padder {
	return &padder{classes: passwordClasses(hashes), sleep: time.Sleep}
}

// measure times each class (once to warm up, then once for real) on the
// first attempt and sets the dummy and the target, 20% above the slowest.
func (p *padder) measure(a *Authenticator) {
	p.once.Do(func() {
		var slowest time.Duration
		p.dummy = p.classes[0]
		probe := []byte("gosftpd timing probe")
		for _, d := range p.classes {
			n := a.acquire(d)
			d.verify(probe)
			start := time.Now()
			d.verify(probe)
			took := time.Since(start)
			a.release(n)
			if took > slowest {
				slowest, p.dummy = took, d
			}
		}
		t := int64(slowest) * 6 / 5
		p.limit = 4 * t
		p.target.Store(t)
	})
}

// observe raises the target when a verification took longer than it, as
// under load, up to four times the measured value.
func (p *padder) observe(d time.Duration) {
	for {
		cur := p.target.Load()
		next := min(int64(d), p.limit)
		if next <= cur || p.target.CompareAndSwap(cur, next) {
			return
		}
	}
}

// rest returns how much longer a failure that took took must last.
func (p *padder) rest(took time.Duration) time.Duration {
	return max(0, time.Duration(p.target.Load())-took)
}
