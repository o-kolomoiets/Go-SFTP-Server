// SPDX-License-Identifier: Apache-2.0

// Package obs collects the operational metrics of gosftpd and serves them,
// with health checks, on the admin listener (ADR 0009). It writes the
// Prometheus text format 0.0.4 itself and imports no other gosftpd
// package.
package obs

import (
	"cmp"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Metric types of the text format.
const (
	typeCounter   = "counter"
	typeGauge     = "gauge"
	typeHistogram = "histogram"
	typeSummary   = "summary"
)

// family is one metric name with its HELP and TYPE lines.
type family interface {
	meta() *desc
	// write appends the sample lines; nothing when the value cannot be
	// read.
	write(b *buf)
}

type desc struct {
	name, help, typ string
}

func (d *desc) meta() *desc { return d }

// Registry holds metric families and writes them in the text format.
type Registry struct {
	mu       sync.Mutex
	families []family
}

// register adds f; a name registered twice is a programming error.
func (r *Registry) register(f family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, g := range r.families {
		if g.meta().name == f.meta().name {
			panic("obs: metric registered twice: " + f.meta().name)
		}
	}
	r.families = append(r.families, f)
	slices.SortFunc(r.families, func(a, b family) int { return strings.Compare(a.meta().name, b.meta().name) })
}

// WriteTo writes every family, sorted by name: HELP, TYPE, then the
// samples. A family without samples (a value that cannot be read) is
// left out entirely.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	families := slices.Clone(r.families)
	r.mu.Unlock()
	var out, b buf
	for _, f := range families {
		b = b[:0]
		f.write(&b)
		if len(b) == 0 {
			continue
		}
		d := f.meta()
		out.str("# HELP ").str(d.name).byte(' ').str(escapeHelp(d.help)).byte('\n')
		out.str("# TYPE ").str(d.name).byte(' ').str(d.typ).byte('\n')
		out = append(out, b...)
	}
	n, err := w.Write(out)
	return int64(n), err
}

// buf builds exposition lines.
type buf []byte

func (b *buf) str(s string) *buf  { *b = append(*b, s...); return b }
func (b *buf) byte(c byte) *buf   { *b = append(*b, c); return b }
func (b *buf) uint(v uint64) *buf { *b = strconv.AppendUint(*b, v, 10); return b }

// float appends v in Go's shortest form, as client_golang does.
func (b *buf) float(v float64) *buf {
	switch {
	case math.IsInf(v, 1):
		return b.str("+Inf")
	case math.IsInf(v, -1):
		return b.str("-Inf")
	case math.IsNaN(v):
		return b.str("NaN")
	}
	*b = strconv.AppendFloat(*b, v, 'g', -1, 64)
	return b
}

// labels appends {name="value",...}; nothing without labels. extra is one
// more pair, such as le or quantile, after the others.
func (b *buf) labels(names, values []string, extraName, extraValue string) *buf {
	if len(names) == 0 && extraName == "" {
		return b
	}
	b.byte('{')
	for i, n := range names {
		if i > 0 {
			b.byte(',')
		}
		b.str(n).str(`="`).str(escapeLabel(values[i])).byte('"')
	}
	if extraName != "" {
		if len(names) > 0 {
			b.byte(',')
		}
		b.str(extraName).str(`="`).str(extraValue).byte('"')
	}
	return b.byte('}')
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
func escapeLabel(s string) string { return labelEscaper.Replace(s) }

// labelSet is the closed set of label values of a vector: every
// combination exists from the start.
type labelSet struct {
	names  []string         // sorted
	values [][]string       // per name, in the order given
	index  []map[string]int // per name: value -> position
	combos [][]string       // every combination, sorted for output
	order  []int            // series index of combos[i]
}

// newLabelSet takes label names with their allowed values; the names are
// sorted, so that series sort by their values in name order.
func newLabelSet(labels []Label) *labelSet {
	labels = slices.Clone(labels)
	slices.SortFunc(labels, func(a, b Label) int { return strings.Compare(a.Name, b.Name) })
	s := &labelSet{}
	for _, l := range labels {
		if len(l.Values) == 0 {
			panic("obs: label without values: " + l.Name)
		}
		idx := make(map[string]int, len(l.Values))
		for i, v := range l.Values {
			idx[v] = i
		}
		s.names = append(s.names, l.Name)
		s.values = append(s.values, l.Values)
		s.index = append(s.index, idx)
	}
	// Series i has the values of the mixed-radix number i.
	n := s.size()
	for i := range n {
		s.combos = append(s.combos, s.combo(i))
		s.order = append(s.order, i)
	}
	slices.SortFunc(s.order, func(a, b int) int { return slices.Compare(s.combos[a], s.combos[b]) })
	return s
}

func (s *labelSet) size() int {
	n := 1
	for _, v := range s.values {
		n *= len(v)
	}
	return n
}

func (s *labelSet) combo(i int) []string {
	c := make([]string, len(s.values))
	for j := len(s.values) - 1; j >= 0; j-- {
		c[j] = s.values[j][i%len(s.values[j])]
		i /= len(s.values[j])
	}
	return c
}

// pos returns the series index of values given in name order, or -1 for a
// value outside the set.
func (s *labelSet) pos(values []string) int {
	if len(values) != len(s.names) {
		return -1
	}
	i := 0
	for j, v := range values {
		k, ok := s.index[j][v]
		if !ok {
			return -1
		}
		i = i*len(s.values[j]) + k
	}
	return i
}

// Label is a label name with every value it can take.
type Label struct {
	Name   string
	Values []string
}

// CounterVec is a counter per combination of label values.
type CounterVec struct {
	desc
	set    *labelSet
	series []atomic.Uint64
}

func newCounterVec(r *Registry, name, help string, labels ...Label) *CounterVec {
	set := newLabelSet(labels)
	c := &CounterVec{desc: desc{name, help, typeCounter}, set: set, series: make([]atomic.Uint64, set.size())}
	r.register(c)
	return c
}

// Add adds n to the series with these label values, given in the sorted
// order of the label names; a value outside the set is dropped.
func (c *CounterVec) Add(n uint64, values ...string) {
	if i := c.set.pos(values); i >= 0 {
		c.series[i].Add(n)
	}
}

// Value returns the value of a series (tests).
func (c *CounterVec) Value(values ...string) uint64 {
	if i := c.set.pos(values); i >= 0 {
		return c.series[i].Load()
	}
	return 0
}

func (c *CounterVec) write(b *buf) {
	for _, i := range c.set.order {
		b.str(c.name).labels(c.set.names, c.set.combos[i], "", "").byte(' ').uint(c.series[i].Load()).byte('\n')
	}
}

// Gauge is a float64 that can go up and down.
type Gauge struct {
	desc
	bits atomic.Uint64
}

func newGauge(r *Registry, name, help string) *Gauge {
	g := &Gauge{desc: desc{name, help, typeGauge}}
	r.register(g)
	return g
}

// Set sets the gauge.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Add adds d, which may be negative.
func (g *Gauge) Add(d float64) {
	for {
		old := g.bits.Load()
		if g.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// Value returns the value.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

func (g *Gauge) write(b *buf) {
	b.str(g.name).byte(' ').float(g.Value()).byte('\n')
}

// Counter is a counter without labels.
type Counter struct {
	desc
	v atomic.Uint64
}

func newCounter(r *Registry, name, help string) *Counter {
	c := &Counter{desc: desc{name, help, typeCounter}}
	r.register(c)
	return c
}

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Value returns the value.
func (c *Counter) Value() uint64 { return c.v.Load() }

func (c *Counter) write(b *buf) {
	b.str(c.name).byte(' ').uint(c.v.Load()).byte('\n')
}

// funcMetric is a counter or gauge read when it is written; ok false
// leaves it out.
type funcMetric struct {
	desc
	fn func() (v float64, ok bool)
}

func newFunc(r *Registry, typ, name, help string, fn func() (float64, bool)) {
	r.register(&funcMetric{desc: desc{name, help, typ}, fn: fn})
}

func (f *funcMetric) write(b *buf) {
	if v, ok := f.fn(); ok {
		b.str(f.name).byte(' ').float(v).byte('\n')
	}
}

// constGauge is a gauge of 1 with fixed labels, such as build_info.
type constGauge struct {
	desc
	names, values []string
}

func newInfo(r *Registry, name, help string, labels map[string]string) {
	g := &constGauge{desc: desc{name, help, typeGauge}}
	for _, n := range slices.Sorted(maps.Keys(labels)) {
		g.names = append(g.names, n)
		g.values = append(g.values, labels[n])
	}
	r.register(g)
}

func (g *constGauge) write(b *buf) {
	b.str(g.name).labels(g.names, g.values, "", "").str(" 1\n")
}

// HistogramVec is a histogram per combination of label values.
type HistogramVec struct {
	desc
	set    *labelSet
	bounds []float64 // upper bounds, ascending, without +Inf
	series []histogram
}

// histogram takes a lock per observation, so that a scrape sees buckets,
// sum and count of the same moment. Observations are rare: one per
// transfer.
type histogram struct {
	mu     sync.Mutex
	counts []uint64 // per bucket, not cumulative; the last is +Inf
	sum    float64
}

func newHistogramVec(r *Registry, name, help string, bounds []float64, labels ...Label) *HistogramVec {
	if !slices.IsSorted(bounds) || len(slices.Compact(slices.Clone(bounds))) != len(bounds) {
		panic("obs: histogram bounds must ascend: " + name)
	}
	set := newLabelSet(labels)
	h := &HistogramVec{desc: desc{name, help, typeHistogram}, set: set, bounds: bounds, series: make([]histogram, set.size())}
	for i := range h.series {
		h.series[i].counts = make([]uint64, len(bounds)+1)
	}
	r.register(h)
	return h
}

// Observe adds v to the series with these label values; a value outside
// the set is dropped.
func (h *HistogramVec) Observe(v float64, values ...string) {
	i := h.set.pos(values)
	if i < 0 {
		return
	}
	// The first bucket whose upper bound is at least v.
	k, _ := slices.BinarySearch(h.bounds, v)
	s := &h.series[i]
	s.mu.Lock()
	s.counts[k]++
	s.sum += v
	s.mu.Unlock()
}

// Count returns the number of observations of a series (tests).
func (h *HistogramVec) Count(values ...string) uint64 {
	i := h.set.pos(values)
	if i < 0 {
		return 0
	}
	s := &h.series[i]
	s.mu.Lock()
	defer s.mu.Unlock()
	var n uint64
	for _, c := range s.counts {
		n += c
	}
	return n
}

func (h *HistogramVec) write(b *buf) {
	counts := make([]uint64, len(h.bounds)+1)
	for _, i := range h.set.order {
		s := &h.series[i]
		s.mu.Lock()
		copy(counts, s.counts)
		sum := s.sum
		s.mu.Unlock()
		names, values := h.set.names, h.set.combos[i]
		var cum uint64
		for k, c := range counts {
			cum += c
			le := "+Inf"
			if k < len(h.bounds) {
				le = string(strconv.AppendFloat(nil, h.bounds[k], 'g', -1, 64))
			}
			b.str(h.name).str("_bucket").labels(names, values, "le", le).byte(' ').uint(cum).byte('\n')
		}
		b.str(h.name).str("_sum").labels(names, values, "", "").byte(' ').float(sum).byte('\n')
		b.str(h.name).str("_count").labels(names, values, "", "").byte(' ').uint(cum).byte('\n')
	}
}

// summaryFunc is a summary without labels read when it is written.
type summaryFunc struct {
	desc
	fn func() (quantiles []Quantile, sum float64, count uint64)
}

// Quantile is one quantile line of a summary.
type Quantile struct {
	Q, V float64
}

func newSummaryFunc(r *Registry, name, help string, fn func() ([]Quantile, float64, uint64)) {
	r.register(&summaryFunc{desc: desc{name, help, typeSummary}, fn: fn})
}

func (s *summaryFunc) write(b *buf) {
	qs, sum, count := s.fn()
	qs = slices.Clone(qs)
	slices.SortFunc(qs, func(a, b Quantile) int { return cmp.Compare(a.Q, b.Q) })
	for _, q := range qs {
		b.str(s.name).labels(nil, nil, "quantile", string(strconv.AppendFloat(nil, q.Q, 'g', -1, 64))).byte(' ').float(q.V).byte('\n')
	}
	b.str(s.name).str("_sum ").float(sum).byte('\n')
	b.str(s.name).str("_count ").uint(count).byte('\n')
}
