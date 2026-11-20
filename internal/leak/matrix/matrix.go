// SPDX-License-Identifier: AGPL-3.0-only

// Package matrix is scrim's bypass matrix: a data-driven catalogue of ways a
// secret can leave in a provider request other than verbatim, each with the
// outcome scrim must produce, and a black-box runner that sends every row
// through a proxy to the fake provider and checks what arrived.
//
// Rows are the product of two catalogues: every [Transform] in the primary
// placement (a tool result) of every API, and every [Placement] with a small
// set of transforms. Each row states its expectation:
//
//   - redacted: the request is forwarded and the value is replaced by a
//     placeholder (the redactor's own variants)
//   - guard: the value must not arrive; the redactor, the guard's repair or a
//     refusal are all acceptable
//   - withheld: the request must be refused and nothing forwarded
//   - limitation: a documented limitation; the row runs and its outcome is
//     reported, but it does not gate a release
//
// The matrix is a release gate: any row whose observed outcome its
// expectation does not accept fails the run.
package matrix

import (
	"fmt"
	"sort"
	"strings"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// Expect is a row's required outcome.
type Expect string

// Expectations.
const (
	Redacted   Expect = "redacted"
	Guard      Expect = "guard"
	Withheld   Expect = "withheld"
	Limitation Expect = "limitation"
)

// rank orders expectations from strictest to most lenient, so a row takes
// the most lenient of its transform's and its placement's.
func (e Expect) rank() int {
	switch e {
	case Redacted:
		return 0
	case Guard:
		return 1
	case Withheld:
		return 2
	case Limitation:
		return 3
	}
	return -1
}

// Outcome is what a row was observed to do.
type Outcome string

// Outcomes.
const (
	// OutcomeRedacted: forwarded, value absent, a placeholder present.
	OutcomeRedacted Outcome = "redacted"
	// OutcomeRepaired: forwarded, value absent, no placeholder (the value
	// was removed some other way, or was too short to count).
	OutcomeRepaired Outcome = "repaired"
	// OutcomeWithheld: refused with an error, nothing forwarded.
	OutcomeWithheld Outcome = "withheld"
	// OutcomeLeaked: the value reached the provider in some form.
	OutcomeLeaked Outcome = "leaked"
	// OutcomeError: the run could not reach a verdict (transport failure).
	OutcomeError Outcome = "error"
)

// Accepts reports whether an expectation accepts an outcome.
func (e Expect) Accepts(o Outcome) bool {
	switch e {
	case Redacted:
		return o == OutcomeRedacted
	case Guard:
		return o == OutcomeRedacted || o == OutcomeRepaired || o == OutcomeWithheld
	case Withheld:
		return o == OutcomeWithheld
	case Limitation:
		return o != OutcomeError
	}
	return false
}

// Row is one matrix entry.
type Row struct {
	ID        string
	API       fp.API
	Transform Transform
	Placement Placement
	Expect    Expect
	Note      string
}

// Rows returns the whole matrix in a stable order.
func Rows() []Row {
	var rows []Row
	seen := map[string]bool{}
	add := func(api fp.API, t Transform, p Placement) {
		if p.Build(api, Content{Value: "x"}, EscapeMinimal) == nil {
			return
		}
		id := fmt.Sprintf("%s/%s/%s", api, p.ID, t.ID)
		if seen[id] {
			return
		}
		seen[id] = true
		exp, note := t.Expect, t.Note
		if p.Expect.rank() > exp.rank() {
			exp, note = p.Expect, p.Note
		}
		rows = append(rows, Row{ID: id, API: api, Transform: t, Placement: p, Expect: exp, Note: note})
	}
	primary, _ := PlacementByID("tool-result")
	perPlacement := []string{"raw", "json-html-escaped", "base64-std@1", "reversed", "spaced-letters"}
	for _, api := range fp.APIs {
		for _, t := range Transforms {
			add(api, t, primary)
		}
		for _, p := range Placements {
			for _, id := range perPlacement {
				t, _ := TransformByID(id)
				add(api, t, p)
			}
		}
	}
	return rows
}

// Summary counts rows by expectation.
func Summary(rows []Row) map[Expect]int {
	m := map[Expect]int{}
	for _, r := range rows {
		m[r.Expect]++
	}
	return m
}

// Filter keeps rows whose ID matches any of the given prefixes. No prefixes
// keeps every row.
func Filter(rows []Row, prefixes ...string) []Row {
	if len(prefixes) == 0 {
		return rows
	}
	var out []Row
	for _, r := range rows {
		for _, p := range prefixes {
			if len(r.ID) >= len(p) && r.ID[:len(p)] == p {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// Markdown renders the catalogue as a table for the documentation.
func Markdown() string {
	var b []byte
	b = append(b, "| Transform | Representative command | Expected | Note |\n| --- | --- | --- | --- |\n"...)
	for _, t := range Transforms {
		b = append(b, fmt.Sprintf("| `%s` | `%s` | %s | %s |\n", t.ID, escapePipe(t.Command), t.Expect, escapePipe(t.Note))...)
	}
	b = append(b, "\n| Placement | Where | Expected | Note |\n| --- | --- | --- | --- |\n"...)
	for _, p := range Placements {
		var apis []string
		for _, api := range fp.APIs {
			if p.Build(api, Content{Value: "x"}, EscapeMinimal) != nil {
				apis = append(apis, string(api))
			}
		}
		sort.Strings(apis)
		b = append(b, fmt.Sprintf("| `%s` | %s (%v) | %s | %s |\n", p.ID, escapePipe(p.Desc), apis, p.Expect, escapePipe(p.Note))...)
	}
	// An empty note is one space between the pipes, as markdownlint's compact
	// table style (MD060) wants.
	return strings.ReplaceAll(string(b), "|  |", "| |")
}

func escapePipe(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}
