// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Summary describes a set of latencies in milliseconds.
type Summary struct {
	Count int     `json:"count"`
	Mean  float64 `json:"mean_ms"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

// recorder collects latency samples from many goroutines.
type recorder struct {
	mu sync.Mutex
	v  []float64
}

func (r *recorder) add(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	r.mu.Lock()
	r.v = append(r.v, ms)
	r.mu.Unlock()
}

func (r *recorder) summary() Summary {
	r.mu.Lock()
	v := slices.Clone(r.v)
	r.mu.Unlock()
	return summarize(v)
}

// summarize returns nearest-rank percentiles.
func summarize(v []float64) Summary {
	if len(v) == 0 {
		return Summary{}
	}
	sort.Float64s(v)
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(v)))) - 1
		return round3(v[max(0, min(i, len(v)-1))])
	}
	return Summary{Count: len(v), Mean: round3(sum / float64(len(v))), P50: q(0.50), P95: q(0.95), P99: q(0.99), Max: round3(v[len(v)-1])}
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

// Histogram is a Prometheus histogram summed over every series of one
// metric that matches a label filter: cumulative counts per finite upper
// bound, the +Inf bucket being Count.
type Histogram struct {
	Bounds []float64 `json:"bounds"`
	Counts []float64 `json:"counts"`
	Count  float64   `json:"count"`
	Sum    float64   `json:"sum"`
}

// sub returns h minus an earlier scrape of the same histogram.
func (h Histogram) sub(o Histogram) Histogram {
	out := Histogram{Bounds: slices.Clone(h.Bounds), Counts: slices.Clone(h.Counts), Count: h.Count - o.Count, Sum: h.Sum - o.Sum}
	for i, b := range out.Bounds {
		if j := slices.Index(o.Bounds, b); j >= 0 {
			out.Counts[i] -= o.Counts[j]
		}
	}
	return out
}

// add sums two histograms with the same bounds (another replica's).
func (h Histogram) add(o Histogram) Histogram {
	if len(h.Bounds) == 0 {
		return Histogram{Bounds: slices.Clone(o.Bounds), Counts: slices.Clone(o.Counts), Count: o.Count, Sum: o.Sum}
	}
	out := Histogram{Bounds: slices.Clone(h.Bounds), Counts: slices.Clone(h.Counts), Count: h.Count + o.Count, Sum: h.Sum + o.Sum}
	for i, b := range out.Bounds {
		if j := slices.Index(o.Bounds, b); j >= 0 {
			out.Counts[i] += o.Counts[j]
		}
	}
	return out
}

// FractionWithin is the share of observations at or below bound, which
// must be one of the bucket bounds; -1 when it is not.
func (h Histogram) FractionWithin(bound float64) float64 {
	if h.Count <= 0 {
		return 1
	}
	for i, b := range h.Bounds {
		if almostEqual(b, bound) {
			return h.Counts[i] / h.Count
		}
	}
	return -1
}

// Quantile estimates a quantile by linear interpolation inside its bucket,
// the way PromQL's histogram_quantile does.
func (h Histogram) Quantile(q float64) float64 {
	if h.Count <= 0 || len(h.Bounds) == 0 {
		return 0
	}
	rank := q * h.Count
	prevBound, prevCount := 0.0, 0.0
	for i, b := range h.Bounds {
		c := h.Counts[i]
		if c >= rank {
			if math.IsInf(b, 1) {
				return prevBound
			}
			if c == prevCount {
				return b
			}
			return prevBound + (b-prevBound)*(rank-prevCount)/(c-prevCount)
		}
		prevBound, prevCount = b, c
	}
	return prevBound
}

func almostEqual(a, b float64) bool { return math.Abs(a-b) <= 1e-12*math.Max(1, math.Abs(b)) }

// promSample is one line of the text exposition format.
type promSample struct {
	name   string
	labels map[string]string
	value  float64
}

// parseProm reads the samples of a Prometheus text page. Only what the
// load test needs: no exemplars, no timestamps kept.
func parseProm(page string) []promSample {
	var out []promSample
	sc := bufio.NewScanner(strings.NewReader(page))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s := promSample{labels: map[string]string{}}
		var rest string
		if i := strings.IndexByte(line, '{'); i >= 0 {
			j := strings.LastIndexByte(line, '}')
			if j < i {
				continue
			}
			s.name = line[:i]
			parseLabels(line[i+1:j], s.labels)
			rest = strings.TrimSpace(line[j+1:])
		} else {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			s.name, rest = f[0], strings.Join(f[1:], " ")
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		s.value = v
		out = append(out, s)
	}
	return out
}

func parseLabels(s string, into map[string]string) {
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq < 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			return
		}
		key := strings.TrimSpace(s[:eq])
		var val strings.Builder
		i := eq + 2
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(s[i])
				}
				continue
			}
			if s[i] == '"' {
				break
			}
			val.WriteByte(s[i])
		}
		into[key] = val.String()
		s = strings.TrimLeft(s[min(i+1, len(s)):], ", ")
	}
}

// histogramOf sums every series of a histogram metric whose labels include
// all of match.
func histogramOf(samples []promSample, name string, match map[string]string) Histogram {
	byBound := map[float64]float64{}
	var h Histogram
	ok := func(l map[string]string) bool {
		for k, v := range match {
			if l[k] != v {
				return false
			}
		}
		return true
	}
	for _, s := range samples {
		if !ok(s.labels) {
			continue
		}
		switch s.name {
		case name + "_bucket":
			// +Inf is left out (JSON has no infinity); Count holds it.
			b, err := strconv.ParseFloat(s.labels["le"], 64)
			if err == nil && !math.IsInf(b, 0) {
				byBound[b] += s.value
			}
		case name + "_count":
			h.Count += s.value
		case name + "_sum":
			h.Sum += s.value
		}
	}
	for b := range byBound {
		h.Bounds = append(h.Bounds, b)
	}
	sort.Float64s(h.Bounds)
	for _, b := range h.Bounds {
		h.Counts = append(h.Counts, byBound[b])
	}
	return h
}

// gaugeOf sums every sample of a metric whose labels include all of match.
func gaugeOf(samples []promSample, name string, match map[string]string) (float64, bool) {
	sum, found := 0.0, false
outer:
	for _, s := range samples {
		if s.name != name {
			continue
		}
		for k, v := range match {
			if s.labels[k] != v {
				continue outer
			}
		}
		sum += s.value
		found = true
	}
	return sum, found
}
