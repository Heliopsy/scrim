package redact

import (
	"fmt"

	coregx "github.com/coregx/ahocorasick"
	petar "github.com/petar-dambovaliev/aho-corasick"
	pgavlin "github.com/pgavlin/aho-corasick"
)

// Engine finds leftmost-longest, non-overlapping matches.
// Each calls fn(start, end, pattern) in order; fn returns false to stop.
type Engine interface {
	Each(hay []byte, fn func(s, e, p int) bool)
	Name() string
}

// EngineNames lists the engines usable with NewEngine.
var EngineNames = []string{"petar-nfa", "petar-dfa", "pgavlin-nfa", "pgavlin-dfa", "coregx"}

func NewEngine(name string, pats [][]byte) (Engine, error) {
	switch name {
	case "petar-nfa", "petar-dfa":
		b := petar.NewAhoCorasickBuilder(petar.Opts{MatchKind: petar.LeftMostLongestMatch, DFA: name == "petar-dfa"})
		return &petarEng{name, b.BuildByte(pats)}, nil
	case "pgavlin-nfa", "pgavlin-dfa":
		b := pgavlin.NewAhoCorasickBuilder(pgavlin.Opts{MatchKind: pgavlin.LeftMostLongestMatch, DFA: name == "pgavlin-dfa"})
		return &pgavlinEng{name, b.BuildByte(pats)}, nil
	case "coregx":
		// coregx's LeftmostLongest scans to the end of the haystack on every Find;
		// LeftmostFirst stops at the first match state (earliest end). Equivalent to
		// leftmost-longest only when no pattern overlaps another at a match site;
		// the cross-check verifies that on every fixture.
		a, err := coregx.NewBuilder().SetMatchKind(coregx.LeftmostFirst).AddPatterns(pats).Build()
		if err != nil {
			return nil, err
		}
		return &coregxEng{a}, nil
	}
	return nil, fmt.Errorf("unknown engine %q", name)
}

type petarEng struct {
	name string
	ac   petar.AhoCorasick
}

func (e *petarEng) Name() string { return e.name }
func (e *petarEng) Each(hay []byte, fn func(s, e, p int) bool) {
	it := e.ac.IterByte(hay)
	last := 0
	for m := it.Next(); m != nil; m = it.Next() {
		// the iterator resumes at start+1, so it can report overlapping matches; skip them
		if m.Start() < last {
			continue
		}
		last = m.End()
		if !fn(m.Start(), m.End(), m.Pattern()) {
			return
		}
	}
}

type pgavlinEng struct {
	name string
	ac   pgavlin.AhoCorasick
}

func (e *pgavlinEng) Name() string { return e.name }
func (e *pgavlinEng) Each(hay []byte, fn func(s, e, p int) bool) {
	it := e.ac.IterByte(hay)
	last := 0
	for m := it.Next(); m != nil; m = it.Next() {
		if m.Start() < last {
			continue
		}
		last = m.End()
		if !fn(m.Start(), m.End(), m.Pattern()) {
			return
		}
	}
}

type coregxEng struct{ a *coregx.Automaton }

func (e *coregxEng) Name() string { return "coregx" }
func (e *coregxEng) Each(hay []byte, fn func(s, e, p int) bool) {
	pos := 0
	for pos < len(hay) {
		m, ok := e.a.Find(hay, pos)
		if !ok {
			return
		}
		if !fn(m.Start, m.End, m.PatternID) {
			return
		}
		pos = m.End
	}
}
