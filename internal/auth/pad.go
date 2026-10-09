// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

// padder makes failed password attempts take equally long whichever user
// they name. Each attempt verifies one hash: the user's own, or a dummy
// with the default parameters for unknown users and users without a
// password. A failure then waits until the time the costliest configured
// hash takes to verify, without using the CPU for it. So the response time
// tells neither whether a user exists nor which kind of hash it has, and
// an attempt never costs more than one verification.
type padder struct {
	classes []PasswordHash // one dummy per configured kind and cost
	sleep   func(time.Duration)

	once   sync.Once
	target atomic.Int64 // time a failure takes at least, in nanoseconds
	limit  int64        // the target grows under load up to this
}

// newPadder returns a padder for the configured hashes.
func newPadder(hashes []PasswordHash) *padder {
	return &padder{classes: passwordClasses(hashes), sleep: time.Sleep}
}

// measure sets the target from one verification of each class, 20% above
// the slowest. It runs on the first attempt, with a hashing slot held for
// each verification so that memory stays bounded.
func (p *padder) measure(hashing chan struct{}) {
	p.once.Do(func() {
		var slowest time.Duration
		for _, d := range p.classes {
			hashing <- struct{}{}
			start := time.Now()
			d.verify([]byte("gosftpd timing probe"))
			slowest = max(slowest, time.Since(start))
			<-hashing
		}
		t := int64(slowest) * 6 / 5
		p.limit = 2 * t
		p.target.Store(t)
	})
}

// observe raises the target when a verification took longer than it, as
// under load, up to twice the measured value.
func (p *padder) observe(d time.Duration) {
	for {
		cur := p.target.Load()
		next := min(int64(d), p.limit)
		if next <= cur || p.target.CompareAndSwap(cur, next) {
			return
		}
	}
}

// pad waits out the rest of the target after a failed verification that
// took took.
func (p *padder) pad(took time.Duration) {
	if rest := time.Duration(p.target.Load()) - took; rest > 0 {
		p.sleep(rest)
	}
}
