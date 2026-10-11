// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (rerun with -update to accept):\n%s", path, got)
	}
}

func write(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// testRegistry has a family of every kind, with values that exercise
// sorting and escaping.
func testRegistry() *Registry {
	r := &Registry{}
	c := newCounterVec(r, "t_ops_total", "Operations.", Label{"result", []string{"ok", "error"}}, Label{"op", []string{"b", "a"}})
	c.Add(3, "b", "ok")
	c.Add(1, "a", "error")
	h := newHistogramVec(r, "t_duration_seconds", "Durations.", []float64{0.5, 5, 10, 100}, Label{"dir", []string{"up", "down"}})
	for _, v := range []float64{0.1, 0.5, 7, 7, 1000} {
		h.Observe(v, "up")
	}
	g := newGauge(r, "t_active", "Active things.")
	g.Add(2)
	g.Add(-1)
	newCounter(r, "t_events_total", `Events with a \ backslash and a
line feed in HELP.`).Inc()
	newInfo(r, "t_info", "Info.", map[string]string{"version": "1.0 \"quoted\"\nnext \\ line", "a": "x"})
	newFunc(r, typeGauge, "t_missing", "Cannot be read.", func() (float64, bool) { return 0, false })
	newFunc(r, typeGauge, "t_special", "Special values.", func() (float64, bool) { return math.Inf(1), true })
	newFunc(r, typeGauge, "t_float", "A float.", func() (float64, bool) { return 1.7600000123e9, true })
	newSummaryFunc(r, "t_pause_seconds", "Pauses.", func() ([]Quantile, float64, uint64) {
		return []Quantile{{1, 0.3}, {0, 0.001}, {0.5, 0.01}}, 0.5, 9
	})
	return r
}

func TestExpositionGolden(t *testing.T) {
	t.Parallel()

	out := write(t, testRegistry())
	golden(t, "exposition.golden", out)
	fams := parseExposition(t, out)
	if _, ok := fams["t_missing"]; ok {
		t.Error("a value that cannot be read was written")
	}
	info := fams["t_info"].samples[0]
	if info.labels["version"] != "1.0 \"quoted\"\nnext \\ line" {
		t.Errorf("label value round trip: %q", info.labels["version"])
	}
	if h := fams["t_events_total"].help; h != "Events with a \\ backslash and a\nline feed in HELP." {
		t.Errorf("HELP round trip: %q", h)
	}
	// Every combination exists, with 0 where nothing happened.
	if n := len(fams["t_ops_total"].samples); n != 4 {
		t.Errorf("t_ops_total has %d series, want 4", n)
	}
	if n := len(fams["t_duration_seconds"].samples); n != 2*(4+1+2) {
		t.Errorf("t_duration_seconds has %d lines, want 14", n)
	}
}

func TestLabelSetValuesOutsideTheSet(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	c := newCounterVec(r, "c_total", "C.", Label{"a", []string{"x", "y"}}, Label{"b", []string{"1", "2", "3"}})
	c.Add(1, "y", "3")
	c.Add(1, "z", "3") // dropped
	c.Add(1, "y")      // dropped
	c.Add(1, "y", "3", "x")
	if c.Value("y", "3") != 1 || c.Value("x", "1") != 0 || c.Value("z", "3") != 0 {
		t.Errorf("values: %d %d", c.Value("y", "3"), c.Value("x", "1"))
	}
	h := newHistogramVec(r, "h_seconds", "H.", []float64{1}, Label{"d", []string{"u"}})
	h.Observe(1, "v")
	if h.Count("u") != 0 || h.Count("v") != 0 {
		t.Error("an observation outside the set was recorded")
	}
	parseExposition(t, write(t, r))
}

func TestRegisterTwicePanics(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	newCounter(r, "x_total", "X.")
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	newGauge(r, "x_total", "X.")
}

func TestHistogramBuckets(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	h := newHistogramVec(r, "h_seconds", "H.", []float64{1, 2}, Label{"d", []string{"u"}})
	for _, v := range []float64{0, 1, 1.5, 2, 3} {
		h.Observe(v, "u")
	}
	fams := parseExposition(t, write(t, r))
	got := map[string]float64{}
	for _, s := range fams["h_seconds"].samples {
		got[s.name+s.labels["le"]] = s.value
	}
	// An observation equal to a bound counts in that bucket.
	for k, want := range map[string]float64{"h_seconds_bucket1": 2, "h_seconds_bucket2": 4, "h_seconds_bucket+Inf": 5, "h_seconds_sum": 7.5, "h_seconds_count": 5} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

// Scrapes during observations see consistent histograms (run with -race).
func TestHistogramConcurrent(t *testing.T) {
	t.Parallel()

	r := &Registry{}
	h := newHistogramVec(r, "h_seconds", "H.", TransferBuckets, Label{"d", []string{"u", "v"}})
	c := newCounterVec(r, "c_total", "C.", Label{"d", []string{"u", "v"}})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := range 4 {
		wg.Go(func() {
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				d := []string{"u", "v"}[n%2]
				h.Observe(float64((n*7+i)%9000)/3, d)
				c.Add(1, d)
			}
		})
	}
	for range 200 {
		parseExposition(t, write(t, r))
	}
	close(stop)
	wg.Wait()
}
