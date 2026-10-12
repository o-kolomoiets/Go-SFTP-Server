// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Results of a delivery, the values of the result label.
const (
	resultOK      = "ok"
	resultFailed  = "failed"
	resultSkipped = "skipped"
	resultDropped = "dropped"
)

// item is an event waiting in a hook's queue.
type item struct {
	ev   *Event
	at   time.Time // when it was queued
	size int64
}

// runner is one hook: its queue and workers. A worker keeps an event
// through its delay and every attempt, so with one worker the events of a
// hook are delivered in order.
type runner struct {
	d    *Dispatcher
	name string
	kind string

	spec atomic.Pointer[Spec]

	// startMu: a worker holds it for reading from its last look at
	// removed until its process started; remove takes it for writing.
	startMu sync.RWMutex
	gone    chan struct{} // closed by remove

	mu       sync.Mutex
	cond     *sync.Cond
	queue    []*item
	bytes    int64
	inflight int
	workers  int
	removed  bool
	changed  chan struct{} // closed and replaced when the spec changes

	drops    map[string]int // dropped events per user since the last warning
	lastWarn time.Time
	flush    *time.Timer // warns of the drops held back by the once-a-minute limit
}

func newRunner(d *Dispatcher, s *Spec) *runner {
	r := &runner{d: d, name: s.Name, kind: s.Kind(), changed: make(chan struct{}), gone: make(chan struct{}), drops: map[string]int{}}
	r.cond = sync.NewCond(&r.mu)
	r.spec.Store(s)
	d.track(r)
	r.mu.Lock()
	r.startWorkers(s.Concurrency)
	r.mu.Unlock()
	return r
}

// startWorkers starts workers up to n; r.mu is held.
func (r *runner) startWorkers(n int) {
	for r.workers < n {
		r.workers++
		r.d.wg.Add(1)
		go r.work()
	}
}

func (r *runner) work() {
	defer r.d.wg.Done()
	for {
		it, ok := r.next()
		if !ok {
			return
		}
		r.process(it)
		r.mu.Lock()
		r.inflight--
		r.mu.Unlock()
	}
}

// next waits for an event; false tells the worker to exit.
func (r *runner) next() (*item, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if r.removed || r.d.killed.Load() || r.workers > r.spec.Load().Concurrency {
			r.exitLocked()
			return nil, false
		}
		if len(r.queue) > 0 {
			it := r.queue[0]
			r.queue[0] = nil
			r.queue = r.queue[1:]
			r.bytes -= it.size
			r.inflight++
			return it, true
		}
		if r.d.isClosing.Load() {
			r.exitLocked()
			return nil, false
		}
		r.cond.Wait()
	}
}

// exitLocked ends a worker; r.mu is held.
func (r *runner) exitLocked() {
	r.workers--
	if r.workers == 0 && r.removed {
		r.d.untrack(r)
	}
}

// process delivers one event after its delay.
func (r *runner) process(it *item) {
	switch r.waitDelay(it) {
	case waitKilled:
		r.count(resultDropped)
		r.logDropped(it, "shutdown")
		return
	case waitRemoved:
		r.count(resultDropped)
		return
	}
	// Filtered again: a reload may have narrowed the hook meanwhile, also
	// for an event that raced it.
	s := r.spec.Load()
	if !s.matchesEvent(it.ev) {
		r.count(resultDropped)
		r.d.log.Debug("hook event dropped: the hook no longer matches it", "hook", r.name, "event", it.ev.Name, "user", it.ev.User)
		return
	}
	var result string
	if s.Exec != nil {
		result = r.runExec(s, it)
	} else {
		result = r.runWebhook(s, it)
	}
	r.count(result)
}

// Outcomes of waitDelay.
const (
	waitDue = iota
	waitKilled
	waitRemoved
)

// waitDelay waits until the event is due under the current spec. Close
// skips the remaining delays; a removed hook drops the event at once, so
// a hook left out by a reload never runs again.
func (r *runner) waitDelay(it *item) int {
	for {
		r.mu.Lock()
		removed, changed := r.removed, r.changed
		r.mu.Unlock()
		switch {
		case r.d.killed.Load():
			return waitKilled
		case removed:
			return waitRemoved
		}
		wait := time.Until(it.at.Add(r.spec.Load().Delay))
		if wait <= 0 {
			return waitDue
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-changed:
			t.Stop()
		case <-r.d.closing:
			t.Stop()
			if r.d.killed.Load() {
				return waitKilled
			}
			return waitDue
		case <-r.d.killCtx.Done():
			t.Stop()
			return waitKilled
		}
	}
}

// enqueue adds an event, or drops it when the queue is full.
func (r *runner) enqueue(e *Event) {
	size := int64(len(e.Line) + len(e.HostPath) + len(e.Path) + len(e.FinalPath) + len(e.TargetPath) + 512)
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.spec.Load()
	if r.removed || r.d.isClosing.Load() || len(r.queue) >= s.Queue || r.bytes+size > maxQueueBytes {
		r.dropLocked(e.User, s)
		return
	}
	r.queue = append(r.queue, &item{ev: e, at: time.Now(), size: size})
	r.bytes += size
	r.cond.Signal()
}

// dropLocked counts an event dropped at the door and warns at most once a
// minute with the counts per user: drops within the minute are warned of
// when it ends. r.mu is held.
func (r *runner) dropLocked(user string, s *Spec) {
	r.count(resultDropped)
	r.drops[user]++
	wait := time.Until(r.lastWarn.Add(time.Minute))
	if wait > 0 && !r.removed && !r.d.isClosing.Load() {
		if r.flush == nil {
			r.flush = time.AfterFunc(wait, r.flushDrops)
		}
		return
	}
	r.warnDropsLocked(s)
}

func (r *runner) warnDropsLocked(s *Spec) {
	if r.flush != nil {
		r.flush.Stop()
		r.flush = nil
	}
	if len(r.drops) == 0 {
		return
	}
	users := slices.Sorted(maps.Keys(r.drops))
	parts := make([]string, 0, len(users))
	total := 0
	for _, u := range users {
		parts = append(parts, u+"="+strconv.Itoa(r.drops[u]))
		total += r.drops[u]
	}
	r.d.log.Warn("hook queue full: events dropped", "hook", r.name, "dropped", total, "by_user", strings.Join(parts, " "),
		"queue", s.Queue, "delay", s.Delay.String())
	clear(r.drops)
	r.lastWarn = time.Now()
}

// flushDrops logs the drops not warned about yet.
func (r *runner) flushDrops() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnDropsLocked(r.spec.Load())
}

// update applies a new spec of the same name and kind.
func (r *runner) update(s *Spec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spec.Store(s)
	// A smaller queue refuses new events until it is below its size; it
	// drops none that wait.
	kept := r.queue[:0]
	var bytes int64
	dropped := 0
	for _, it := range r.queue {
		if s.matchesEvent(it.ev) {
			kept = append(kept, it)
			bytes += it.size
			continue
		}
		dropped++
	}
	clear(r.queue[len(kept):])
	r.queue, r.bytes = kept, bytes
	for range dropped {
		r.count(resultDropped)
	}
	if dropped > 0 {
		r.d.log.Warn("hook changed: pending events dropped", "hook", r.name, "dropped", dropped)
	}
	r.startWorkers(s.Concurrency)
	close(r.changed)
	r.changed = make(chan struct{})
	r.cond.Broadcast()
}

// remove stops the hook: it takes no more events and drops those queued
// or held; a process or an attempt already started finishes. Once it
// returns, the hook starts no process.
func (r *runner) remove() {
	r.startMu.Lock()
	defer r.startMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = true
	close(r.gone)
	r.warnDropsLocked(r.spec.Load())
	if n := len(r.queue); n > 0 {
		for range n {
			r.count(resultDropped)
		}
		r.d.log.Warn("hook removed: pending events dropped", "hook", r.name, "dropped", n)
	}
	clear(r.queue)
	r.queue, r.bytes = nil, 0
	close(r.changed)
	r.changed = make(chan struct{})
	r.cond.Broadcast()
	if r.workers == 0 {
		r.d.untrack(r)
	}
}

// dropAll drops what is still queued, after the workers ended, each
// logged so that it can be replayed.
func (r *runner) dropAll(reason string) {
	r.mu.Lock()
	queue := r.queue
	r.queue, r.bytes = nil, 0
	r.mu.Unlock()
	for _, it := range queue {
		r.count(resultDropped)
		r.logDropped(it, reason)
	}
}

func (r *runner) logDropped(it *item, reason string) {
	r.d.log.Warn("hook event dropped", "hook", r.name, "reason", reason, "event", it.ev.Name,
		"user", it.ev.User, "mount", it.ev.Mount, "path", it.ev.file())
}

func (r *runner) isRemoved() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removed
}

// wake makes waiting workers look at the dispatcher's state again.
func (r *runner) wake() {
	r.mu.Lock()
	r.cond.Broadcast()
	r.mu.Unlock()
}

// length returns the events queued or being delivered.
func (r *runner) length() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue) + r.inflight
}

func (r *runner) count(result string) { r.d.metrics.HookDelivery(r.kind, result) }

// track and untrack keep the runners that may still have workers, so that
// QueueLength and Close also see a removed hook that is finishing.
func (d *Dispatcher) track(r *runner) {
	d.allMu.Lock()
	d.all[r] = struct{}{}
	d.allMu.Unlock()
}

func (d *Dispatcher) untrack(r *runner) {
	d.allMu.Lock()
	delete(d.all, r)
	d.allMu.Unlock()
}

func (d *Dispatcher) tracked() []*runner {
	d.allMu.Lock()
	defer d.allMu.Unlock()
	return slices.Collect(maps.Keys(d.all))
}
