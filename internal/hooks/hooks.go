// SPDX-License-Identifier: Apache-2.0

// Package hooks runs programs and sends webhooks for file events (ADR
// 0010). A Dispatcher lives for the whole process: sftpd asks it whether a
// hook wants an event and hands the event over; each hook has its own
// bounded queue and workers, so an SFTP request never waits for a hook.
// Reload replaces the set of hooks in place.
package hooks

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/obs"
)

// Events are the audit events a hook can be fired by.
var Events = []string{"fs.upload", "fs.download", "fs.rename", "fs.remove", "fs.mkdir", "fs.rmdir", "fs.setstat"}

// Limits and defaults of a hook (ADR 0010).
const (
	MaxConcurrency  = 16
	MaxQueue        = 10_000
	DefaultQueue    = 1000
	MaxDelay        = time.Hour
	DefaultExecTime = 30 * time.Second
	MaxExecTime     = time.Hour
	DefaultHookTime = 10 * time.Second
	MaxHookTime     = 60 * time.Second
	MinSecretLen    = 32
)

// maxQueueBytes bounds the events waiting in one hook's queue.
var maxQueueBytes int64 = 64 << 20

// Spec is a hook as configured. Exactly one of Exec and Webhook is set.
type Spec struct {
	Name        string
	On          []string // event names from Events
	Mounts      []string // mount names as configured; empty is every mount
	Glob        []string // the file's base name matches any; empty is all
	Exclude     []string // the file's base name matches none
	Delay       time.Duration
	Concurrency int
	Queue       int
	Exec        *Exec
	Webhook     *Webhook
}

// Exec runs a program.
type Exec struct {
	Argv    []string
	Timeout time.Duration
}

// Webhook posts the event to a URL.
type Webhook struct {
	URL     string
	Secret  []byte // the HMAC key
	Timeout time.Duration
}

// Kinds of hooks, the values of the type label.
const (
	KindExec    = "exec"
	KindWebhook = "webhook"
)

// Kind returns KindExec or KindWebhook.
func (s *Spec) Kind() string {
	if s.Exec != nil {
		return KindExec
	}
	return KindWebhook
}

// Event is a file event that succeeded.
type Event struct {
	Name     string // the audit event, such as "fs.upload"
	Uploaded bool   // an fs.rename that completes an upload
	Mount    string
	User     string
	ConnID   string
	// Virtual paths as in the audit line.
	Path, FinalPath, TargetPath string
	// Line is the audit line, the webhook body and the exec stdin.
	Line []byte

	// For exec hooks: the file on the host and its identity when the
	// event happened. Gone is set for events whose file no longer exists
	// (fs.remove, fs.rmdir); otherwise a nil Info skips the run.
	HostPath string
	Info     os.FileInfo
	Gone     bool
}

// file returns the virtual path that filters are matched against.
func (e *Event) file() string {
	if e.FinalPath != "" && (e.Name == "fs.upload" || e.Name == "fs.rename") {
		return e.FinalPath
	}
	return e.Path
}

// matches reports whether the hook wants an event; name is the base name
// of the event's file.
func (s *Spec) matches(event string, uploaded bool, mount, name string) bool {
	if !slices.Contains(s.On, event) && (!uploaded || event != "fs.rename" || !slices.Contains(s.On, "fs.upload")) {
		return false
	}
	if len(s.Mounts) > 0 && !slices.Contains(s.Mounts, mount) {
		return false
	}
	if len(s.Glob) > 0 && !matchAny(s.Glob, name) {
		return false
	}
	return !matchAny(s.Exclude, name)
}

func (s *Spec) matchesEvent(e *Event) bool {
	return s.matches(e.Name, e.Uploaded, e.Mount, path.Base(e.file()))
}

// matchAny reports whether name matches one of the patterns; the patterns
// were checked when the configuration was loaded.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Options configure a Dispatcher.
type Options struct {
	Log     *slog.Logger
	Metrics *obs.Metrics
	// RootCAs verify webhook receivers; nil loads the system roots now,
	// so that a sandbox applied later cannot hide them.
	RootCAs *x509.CertPool
	// Transport replaces the HTTP transport (tests).
	Transport http.RoundTripper
}

// Dispatcher queues events for the configured hooks. Its methods are safe
// for concurrent use, and Wants and Notify on a nil *Dispatcher do
// nothing.
type Dispatcher struct {
	log     *slog.Logger
	metrics *obs.Metrics
	client  *http.Client

	set atomic.Pointer[[]*runner] // the current hooks, in configuration order

	mu      sync.Mutex // Update and Close
	runners map[string]*runner
	closed  bool

	allMu sync.Mutex
	all   map[*runner]struct{} // runners that may have workers, removed ones included

	closing    chan struct{} // closed by Close: delays end, new events are dropped
	killed     atomic.Bool
	killCtx    context.Context // cancelled when Close gives up waiting
	kill       context.CancelFunc
	wg         sync.WaitGroup // workers
	isClosing  atomic.Bool
	retryDelay func(attempt int) time.Duration
}

// New returns a Dispatcher without hooks.
func New(opts Options) *Dispatcher {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	d := &Dispatcher{
		log:        log,
		metrics:    opts.Metrics,
		runners:    map[string]*runner{},
		all:        map[*runner]struct{}{},
		closing:    make(chan struct{}),
		retryDelay: retryDelay,
	}
	d.killCtx, d.kill = context.WithCancel(context.Background())
	d.client = newClient(opts)
	empty := []*runner{}
	d.set.Store(&empty)
	return d
}

// Wants reports whether any hook wants an event, before it is rendered:
// event is its name, uploaded marks an fs.rename that completes an upload,
// name is the base name of its file.
func (d *Dispatcher) Wants(event string, uploaded bool, mount, name string) bool {
	if d == nil || d.isClosing.Load() {
		return false
	}
	for _, r := range *d.set.Load() {
		if r.spec.Load().matches(event, uploaded, mount, name) {
			return true
		}
	}
	return false
}

// Notify queues an event for every hook that wants it. It never blocks:
// a hook whose queue is full drops the event.
func (d *Dispatcher) Notify(e *Event) {
	if d == nil {
		return
	}
	for _, r := range *d.set.Load() {
		if r.spec.Load().matchesEvent(e) {
			r.enqueue(e)
		}
	}
}

// Update replaces the hooks. A hook whose name and kind stay keeps its
// queue: its pending events are filtered again and use the new spec. A
// hook that is gone drops its pending events. Update after Close does
// nothing.
func (d *Dispatcher) Update(specs []Spec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	next := make(map[string]*runner, len(specs))
	set := make([]*runner, 0, len(specs))
	for i := range specs {
		s := specs[i] // a copy the runner owns
		r, ok := d.runners[s.Name]
		if ok && r.kind == s.Kind() {
			r.update(&s)
		} else {
			r = newRunner(d, &s)
		}
		next[s.Name] = r
		set = append(set, r)
	}
	for name, r := range d.runners {
		if next[name] != r {
			r.remove()
		}
	}
	d.runners = next
	d.set.Store(&set)
}

// Close stops taking events, skips pending delays and lets the hooks
// deliver what they hold until deadline. Then it kills running programs,
// cancels requests and counts what is left as dropped. It waits for every
// worker.
func (d *Dispatcher) Close(deadline time.Time) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.isClosing.Store(true)
	close(d.closing)
	d.mu.Unlock()
	runners := d.tracked()
	for _, r := range runners {
		r.wake()
	}

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(time.Until(deadline))
	select {
	case <-done:
		t.Stop()
	case <-t.C:
		d.killed.Store(true)
		d.kill()
		for _, r := range runners {
			r.wake()
		}
		<-done
	}
	d.kill()
	for _, r := range runners {
		r.dropAll("shutdown")
		r.flushDrops()
	}
}

// QueueLength returns the events queued or being delivered, of all hooks.
func (d *Dispatcher) QueueLength() int {
	if d == nil {
		return 0
	}
	n := 0
	for _, r := range d.tracked() {
		n += r.length()
	}
	return n
}
