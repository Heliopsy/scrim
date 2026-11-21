// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"sort"
)

// scanner finds any of a fixed set of byte strings in a buffer in one pass
// per distinct needle length (Rabin-Karp), so every request of a 1,000-
// stream run can be checked against every seeded value and its encodings
// without slowing the fake provider down.
type scanner struct {
	lengths []int
	tables  map[int]map[uint64][]int
	// filter has a bit set for every needle hash, so most positions cost
	// a bit test instead of a map lookup.
	filter  []uint64
	needles [][]byte
	owner   []int // needle index -> seed index
}

const (
	rkBase     = 1099511628211
	filterBits = 1 << 22
)

func filterIndex(h uint64) uint64 { return (h ^ h>>29) & (filterBits - 1) }

// leakForms returns the forms of a value the fake provider must never see:
// the raw bytes, standard and URL-safe base64, lower-case hex and the
// URL-encoded form when it differs.
func leakForms(v []byte) [][]byte {
	forms := [][]byte{v,
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
		[]byte(hex.EncodeToString(v)),
	}
	if q := url.QueryEscape(string(v)); q != string(v) {
		forms = append(forms, []byte(q))
	}
	return forms
}

// newScanner indexes the leak forms of the first encoded values and the raw
// bytes of the rest (tokens nobody encodes); find reports the index of the
// value a hit belongs to.
func newScanner(values [][]byte, encoded int) *scanner {
	s := &scanner{tables: map[int]map[uint64][]int{}, filter: make([]uint64, filterBits/64)}
	for i, v := range values {
		forms := [][]byte{v}
		if i < encoded {
			forms = leakForms(v)
		}
		for _, f := range forms {
			if len(f) < 8 {
				continue
			}
			s.needles = append(s.needles, f)
			s.owner = append(s.owner, i)
		}
	}
	for n, f := range s.needles {
		t, ok := s.tables[len(f)]
		if !ok {
			t = map[uint64][]int{}
			s.tables[len(f)] = t
			s.lengths = append(s.lengths, len(f))
		}
		h := hashOf(f)
		t[h] = append(t[h], n)
		i := filterIndex(h)
		s.filter[i/64] |= 1 << (i % 64)
	}
	sort.Ints(s.lengths)
	return s
}

func hashOf(b []byte) uint64 {
	var h uint64
	for _, c := range b {
		h = h*rkBase + uint64(c)
	}
	return h
}

// find returns the indexes of the values with a form in b, each once.
func (s *scanner) find(b []byte) []int {
	var hits []int
	seen := map[int]bool{}
	for _, n := range s.lengths {
		if len(b) < n {
			break
		}
		t := s.tables[n]
		var pow uint64 = 1
		for range n - 1 {
			pow *= rkBase
		}
		h := hashOf(b[:n])
		for i := 0; ; i++ {
			if f := filterIndex(h); s.filter[f/64]&(1<<(f%64)) == 0 {
				// no needle has this hash
			} else if cands, ok := t[h]; ok {
				for _, c := range cands {
					if o := s.owner[c]; !seen[o] && bytes.Equal(b[i:i+n], s.needles[c]) {
						seen[o] = true
						hits = append(hits, o)
					}
				}
			}
			if i+n >= len(b) {
				break
			}
			h = (h-uint64(b[i])*pow)*rkBase + uint64(b[i+n])
		}
	}
	return hits
}
