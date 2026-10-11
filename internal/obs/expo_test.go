// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This file holds a parser for the text format 0.0.4, written for the
// tests from the format's documentation, independent of the writer.

// reporter is the part of testing.T the parser uses, so that a test can
// check that it rejects bad input.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// fakeT records failures; Fatalf panics to stop the parser.
type fakeT struct{ failed bool }

func (*fakeT) Helper()                 {}
func (f *fakeT) Errorf(string, ...any) { f.failed = true }
func (f *fakeT) Fatalf(string, ...any) { f.failed = true; panic(f) }

type sample struct {
	name   string
	labels map[string]string
	keys   []string // label names in the order written
	value  float64
}

// series is the sample's name with its labels sorted, for uniqueness.
func (s sample) series() string {
	var b strings.Builder
	b.WriteString(s.name)
	for _, k := range slices.Sorted(maps.Keys(s.labels)) {
		fmt.Fprintf(&b, ",%s=%q", k, s.labels[k])
	}
	return b.String()
}

// without returns the labels without name, as a key.
func (s sample) without(name string) string {
	var parts []string
	for _, k := range s.keys {
		if k != name {
			parts = append(parts, k+"="+strconv.Quote(s.labels[k]))
		}
	}
	return strings.Join(parts, ",")
}

type parsedFamily struct {
	name, help, typ string
	samples         []sample
}

var (
	metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// parseExposition parses text and checks the structure the format and
// ADR 0009 require; it returns the families by name.
func parseExposition(t reporter, text string) map[string]*parsedFamily {
	t.Helper()
	if text != "" && !strings.HasSuffix(text, "\n") {
		t.Fatalf("the output does not end with a line feed")
	}
	families := map[string]*parsedFamily{}
	var order []string
	var cur *parsedFamily
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		where := fmt.Sprintf("line %d %q", i+1, line)
		switch {
		case line == "":
			t.Fatalf("%s: empty line", where)
		case strings.HasPrefix(line, "# HELP "):
			name, help, ok := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			if !ok || !metricName.MatchString(name) {
				t.Fatalf("%s: bad HELP", where)
			}
			if families[name] != nil {
				t.Fatalf("%s: second HELP for %s", where, name)
			}
			cur = &parsedFamily{name: name, help: unescape(t, help, false)}
			families[name] = cur
			order = append(order, name)
		case strings.HasPrefix(line, "# TYPE "):
			name, typ, ok := strings.Cut(strings.TrimPrefix(line, "# TYPE "), " ")
			if !ok || cur == nil || cur.name != name || cur.typ != "" || len(cur.samples) > 0 {
				t.Fatalf("%s: TYPE not right after the HELP of its family", where)
			}
			if !slices.Contains([]string{"counter", "gauge", "histogram", "summary", "untyped"}, typ) {
				t.Fatalf("%s: unknown type", where)
			}
			cur.typ = typ
		case strings.HasPrefix(line, "#"):
			t.Fatalf("%s: unexpected comment", where)
		default:
			s := parseSample(t, where, line)
			if cur == nil || cur.typ == "" || !belongs(cur, s.name) {
				t.Fatalf("%s: sample outside its family", where)
			}
			if seen[s.series()] {
				t.Fatalf("%s: duplicate series", where)
			}
			seen[s.series()] = true
			cur.samples = append(cur.samples, s)
		}
	}
	if !slices.IsSorted(order) {
		t.Errorf("families not sorted by name: %v", order)
	}
	for _, f := range families {
		if len(f.samples) == 0 {
			t.Errorf("%s: a family without samples", f.name)
		}
		checkFamily(t, f)
	}
	return families
}

func belongs(f *parsedFamily, name string) bool {
	switch f.typ {
	case "histogram":
		return name == f.name+"_bucket" || name == f.name+"_sum" || name == f.name+"_count"
	case "summary":
		return name == f.name || name == f.name+"_sum" || name == f.name+"_count"
	}
	return name == f.name
}

func parseSample(t reporter, where, line string) sample {
	t.Helper()
	s := sample{labels: map[string]string{}}
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		t.Fatalf("%s: no value", where)
	}
	s.name, line = line[:i], line[i:]
	if !metricName.MatchString(s.name) {
		t.Fatalf("%s: bad metric name", where)
	}
	if strings.HasPrefix(line, "{") {
		line = line[1:]
		for !strings.HasPrefix(line, "}") {
			eq := strings.Index(line, `="`)
			if eq < 0 {
				t.Fatalf("%s: bad label", where)
			}
			name := line[:eq]
			if !labelName.MatchString(name) || strings.HasPrefix(name, "__") {
				t.Fatalf("%s: bad label name %q", where, name)
			}
			if _, dup := s.labels[name]; dup {
				t.Fatalf("%s: label %s twice", where, name)
			}
			line = line[eq+2:]
			var v strings.Builder
			for {
				if line == "" {
					t.Fatalf("%s: unterminated label value", where)
				}
				c := line[0]
				line = line[1:]
				if c == '"' {
					break
				}
				if c == '\n' {
					t.Fatalf("%s: raw line feed in a label value", where)
				}
				if c == '\\' {
					if line == "" {
						t.Fatalf("%s: bad escape", where)
					}
					switch line[0] {
					case '\\':
						v.WriteByte('\\')
					case '"':
						v.WriteByte('"')
					case 'n':
						v.WriteByte('\n')
					default:
						t.Fatalf("%s: bad escape \\%c", where, line[0])
					}
					line = line[1:]
					continue
				}
				v.WriteByte(c)
			}
			s.labels[name] = v.String()
			s.keys = append(s.keys, name)
			if strings.HasPrefix(line, ",") {
				line = line[1:]
			} else if !strings.HasPrefix(line, "}") {
				t.Fatalf("%s: bad label separator", where)
			}
		}
		line = line[1:]
	}
	v, ok := strings.CutPrefix(line, " ")
	if !ok || strings.Contains(v, " ") {
		t.Fatalf("%s: want one value and no timestamp", where)
	}
	f, err := parseFloat(v)
	if err != nil {
		t.Fatalf("%s: bad value: %v", where, err)
	}
	s.value = f
	return s
}

func parseFloat(v string) (float64, error) {
	switch v {
	case "+Inf":
		return math.Inf(1), nil
	case "-Inf":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	}
	return strconv.ParseFloat(v, 64)
}

// unescape undoes the HELP escapes (\\ and \n) or, with label, also \".
func unescape(t reporter, s string, label bool) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch {
		case i < len(s) && s[i] == '\\':
			b.WriteByte('\\')
		case i < len(s) && s[i] == 'n':
			b.WriteByte('\n')
		case i < len(s) && s[i] == '"' && label:
			b.WriteByte('"')
		default:
			t.Fatalf("bad escape in %q", s)
		}
	}
	return b.String()
}

// checkFamily checks histogram and summary blocks: one block per series,
// buckets in ascending numeric le ending at +Inf, cumulative, then _sum,
// then _count equal to the +Inf bucket; quantiles, _sum, _count.
func checkFamily(t reporter, f *parsedFamily) {
	t.Helper()
	switch f.typ {
	case "counter":
		for _, s := range f.samples {
			if s.value < 0 || math.IsNaN(s.value) {
				t.Errorf("%s: negative counter", s.series())
			}
		}
	case "histogram":
		checkBlocks(t, f, "le", "_bucket")
	case "summary":
		checkBlocks(t, f, "quantile", "")
	}
}

func checkBlocks(t reporter, f *parsedFamily, key, suffix string) {
	t.Helper()
	done := map[string]bool{}
	ss := f.samples
	for len(ss) > 0 {
		id := ss[0].without(key)
		if done[id] {
			t.Errorf("%s{%s}: series split into two blocks", f.name, id)
			return
		}
		done[id] = true
		var bounds []float64
		var counts []float64
		for len(ss) > 0 && ss[0].name == f.name+suffix && ss[0].without(key) == id {
			b, err := parseFloat(ss[0].labels[key])
			if err != nil {
				t.Errorf("%s: bad %s %q", f.name, key, ss[0].labels[key])
				return
			}
			if ss[0].keys[len(ss[0].keys)-1] != key {
				t.Errorf("%s: %s is not the last label", f.name, key)
			}
			bounds = append(bounds, b)
			counts = append(counts, ss[0].value)
			ss = ss[1:]
		}
		if len(bounds) == 0 {
			t.Errorf("%s{%s}: no %s lines", f.name, id, key)
			return
		}
		if !slices.IsSorted(bounds) || len(slices.Compact(slices.Clone(bounds))) != len(bounds) {
			t.Errorf("%s{%s}: %s not in ascending numeric order: %v", f.name, id, key, bounds)
		}
		if len(ss) < 2 || ss[0].name != f.name+"_sum" || ss[1].name != f.name+"_count" || ss[0].without("") != id || ss[1].without("") != id {
			t.Errorf("%s{%s}: _sum and _count do not follow", f.name, id)
			return
		}
		count := ss[1].value
		ss = ss[2:]
		if key != "le" {
			continue
		}
		if !math.IsInf(bounds[len(bounds)-1], 1) {
			t.Errorf("%s{%s}: no +Inf bucket", f.name, id)
		}
		if !slices.IsSorted(counts) {
			t.Errorf("%s{%s}: buckets not cumulative: %v", f.name, id, counts)
		}
		if counts[len(counts)-1] != count {
			t.Errorf("%s{%s}: _count %v differs from the +Inf bucket %v", f.name, id, count, counts[len(counts)-1])
		}
	}
}

func TestParserRejects(t *testing.T) {
	t.Parallel()

	for name, text := range map[string]string{
		"unsorted":    "# HELP b x\n# TYPE b gauge\nb 1\n# HELP a x\n# TYPE a gauge\na 1\n",
		"string le":   "# HELP h x\n# TYPE h histogram\nh_bucket{le=\"10\"} 1\nh_bucket{le=\"5\"} 1\nh_bucket{le=\"+Inf\"} 1\nh_sum 1\nh_count 1\n",
		"split":       "# HELP h x\n# TYPE h histogram\nh_bucket{a=\"1\",le=\"+Inf\"} 1\nh_bucket{a=\"2\",le=\"+Inf\"} 1\nh_sum{a=\"1\"} 1\nh_count{a=\"1\"} 1\n",
		"count":       "# HELP h x\n# TYPE h histogram\nh_bucket{le=\"+Inf\"} 2\nh_sum 1\nh_count 1\n",
		"duplicate":   "# HELP a x\n# TYPE a gauge\na 1\na 2\n",
		"bad escape":  "# HELP a x\n# TYPE a gauge\na{l=\"\\t\"} 1\n",
		"no type":     "# HELP a x\na 1\n",
		"no newline":  "# HELP a x\n# TYPE a gauge\na 1",
		"stray":       "# HELP a x\n# TYPE a gauge\nb 1\n",
		"cumulative":  "# HELP h x\n# TYPE h histogram\nh_bucket{le=\"1\"} 2\nh_bucket{le=\"+Inf\"} 1\nh_sum 1\nh_count 1\n",
		"no samples":  "# HELP a x\n# TYPE a gauge\n",
		"second help": "# HELP a x\n# TYPE a gauge\na 1\n# HELP a x\n",
	} {
		ft := &fakeT{}
		func() {
			defer func() { _ = recover() }()
			parseExposition(ft, text)
		}()
		if !ft.failed {
			t.Errorf("%s: accepted", name)
		}
	}
}
