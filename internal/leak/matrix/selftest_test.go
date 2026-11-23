// SPDX-License-Identifier: AGPL-3.0-only

package matrix_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/leak/stub"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

type harness struct {
	fake   *fp.Server
	runner *matrix.Runner
}

func newHarness(t *testing.T, proxy func(*url.URL) *httptest.Server) *harness {
	t.Helper()
	fake := fp.New(fp.Options{})
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	px := proxy(u)
	t.Cleanup(px.Close)
	return &harness{fake: fake, runner: &matrix.Runner{
		Target:   matrix.Target{BaseURL: px.URL},
		Upstream: matrix.LocalUpstream{Server: fake},
		Checker:  leak.NewChecker(nil),
	}}
}

// runSharded runs the matrix on several independent harnesses at once. Each
// harness has its own fake provider and proxy, so captures never mix.
func runSharded(t *testing.T, proxy func(*url.URL) *httptest.Server, seeds []leak.Seed) []matrix.Result {
	t.Helper()
	rows := matrix.Rows()
	const shards = 8
	out := make([][]matrix.Result, shards)
	var wg sync.WaitGroup
	for i := range shards {
		h := newHarness(t, proxy)
		var part []matrix.Row
		for j := i; j < len(rows); j += shards {
			part = append(part, rows[j])
		}
		wg.Go(func() {
			res, err := h.runner.Run(context.Background(), part, seeds)
			if err != nil {
				t.Error(err)
			}
			out[i] = res
		})
	}
	wg.Wait()
	var all []matrix.Result
	for _, r := range out {
		all = append(all, r...)
	}
	return all
}

func isTruncation(id string) bool {
	return strings.HasPrefix(id, "truncated-") || id == "sql-substring"
}

// fragmentTooShort reports whether a truncation of a seed leaves too little of
// the secret part to count as a leak, which is by design (short values and
// fragments below the minimum are a documented limitation).
func fragmentTooShort(s leak.Seed) bool {
	return s.Kind == leak.KindShort || s.Kind == leak.KindAWSAccessKey
}

// The pass-through proxy forwards everything, so every row must report a leak
// for every seed: this proves the checker sees every transform and placement
// in the catalogue.
func TestPassThroughLeaksEverything(t *testing.T) {
	seeds := leak.GenerateSet()
	results := runSharded(t, func(u *url.URL) *httptest.Server { return httptest.NewServer(stub.PassThrough(u)) }, seeds)
	for _, r := range results {
		if r.Outcome == matrix.OutcomeError {
			t.Errorf("%s", r.Describe())
			continue
		}
		var seed leak.Seed
		for _, s := range seeds {
			if s.Name == r.Seed.Name {
				seed = s
			}
		}
		if isTruncation(r.Transform) && fragmentTooShort(seed) {
			continue
		}
		if r.Outcome != matrix.OutcomeLeaked {
			t.Errorf("pass-through not reported as a leak: %s", r.Describe())
		}
		if r.Outcome == matrix.OutcomeLeaked && r.Expect != matrix.Limitation && r.Pass {
			t.Errorf("a leak passed a gated row: %s", r.Describe())
		}
	}
	tot := matrix.Tally(results)
	if tot.GatedLeaks == 0 || tot.Failed == 0 {
		t.Fatalf("pass-through produced no gate failure: %+v", tot)
	}
	t.Logf("rows=%d cases=%d leaked=%d", tot.Rows, tot.Cases, tot.Leaked)
}

// The naive stub replaces only verbatim and JSON-escaped values in the body.
// The suite must see it redact the verbatim rows and report everything else.
func TestNaiveRedactorPattern(t *testing.T) {
	seeds := leak.GenerateSet()
	results := runSharded(t, func(u *url.URL) *httptest.Server { return httptest.NewServer(stub.Naive(u, seeds)) }, seeds)
	get := func(row, kind string) matrix.Result {
		for _, r := range results {
			if r.Row == row && string(r.Seed.Kind) == kind {
				return r
			}
		}
		t.Fatalf("no result for %s %s", row, kind)
		return matrix.Result{}
	}
	for _, s := range seeds {
		k := string(s.Kind)
		for _, row := range []string{
			"anthropic-messages/tool-result/raw",
			"anthropic-messages/tool-result-streaming/raw",
			"anthropic-messages/system-prompt/raw",
			"anthropic-messages/unknown-field/raw",
			"openai-chat/tool-result/raw",
			"openai-responses/tool-result-blocks/raw",
			"gemini/tool-result/raw",
			"gemini/tool-result-streaming/raw",
			"gemini/system-prompt/raw",
		} {
			if r := get(row, k); r.Outcome != matrix.OutcomeRedacted || !r.Pass {
				t.Errorf("naive stub should redact: %s", r.Describe())
			}
		}
		for _, row := range []string{
			"anthropic-messages/tool-result/base64-std@1",
			"anthropic-messages/tool-result/reversed",
			"openai-chat/tool-result/hex-lower",
			"openai-responses/header/raw",
			"anthropic-messages/tool-result/json-escape-all",
			"gemini/tool-result/reversed",
			"gemini/query/raw",
		} {
			if r := get(row, k); r.Outcome != matrix.OutcomeLeaked || r.Pass {
				t.Errorf("naive stub should leak: %s", r.Describe())
			}
		}
	}
	// A value with a quote or a backslash is escaped twice inside a tool
	// call's JSON arguments string, which a verbatim matcher misses. The
	// exception: when every quote and backslash of the generated password
	// leads it, the once-escaped form is itself a substring of the
	// twice-escaped one (\"abc escapes to \\\"abc), so the naive stub
	// does catch it.
	for _, s := range seeds {
		if s.Kind != leak.KindPassword {
			continue
		}
		once := jsonEscape(s.Value())
		if strings.Contains(jsonEscape(once), once) {
			t.Logf("password seed escapes into itself twice; naive stub catches it")
			break
		}
		if r := get("openai-chat/tool-call-input/raw", string(leak.KindPassword)); r.Outcome != matrix.OutcomeLeaked {
			t.Errorf("double-escaped password should leak through the naive stub: %s", r.Describe())
		}
	}
	tot := matrix.Tally(results)
	t.Logf("naive stub: %+v", tot)
}

func TestRowsAreUniqueAndBuildable(t *testing.T) {
	rows := matrix.Rows()
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.ID] {
			t.Errorf("duplicate row %s", r.ID)
		}
		seen[r.ID] = true
		if r.Expect == matrix.Limitation && r.Note == "" {
			t.Errorf("limitation row %s has no note", r.ID)
		}
		reqs := r.Placement.Build(r.API, matrix.ContentFor(r.Transform, "AKIAABCDEFGHIJKLMNOP"), r.Transform.Body)
		if len(reqs) == 0 {
			t.Errorf("row %s builds no request", r.ID)
		}
	}
	if len(rows) < 250 {
		t.Errorf("matrix shrank to %d rows", len(rows))
	}
	sum := matrix.Summary(rows)
	t.Logf("rows=%d by expectation=%v", len(rows), sum)
}

// docs/leak-assurance.md embeds the catalogue; regenerate it with
// `scrim audit run --list-matrix` when the catalogue changes.
func TestDocsMatchCatalogue(t *testing.T) {
	b, err := os.ReadFile("../../../docs/leak-assurance.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "<!-- matrix:begin -->\n")
	end := strings.Index(doc, "<!-- matrix:end -->")
	if start < 0 || end < start {
		t.Fatal("matrix markers missing from docs/leak-assurance.md")
	}
	if got := doc[start+len("<!-- matrix:begin -->\n") : end]; got != matrix.Markdown() {
		t.Fatal("docs/leak-assurance.md matrix table is stale: replace it with the output of `scrim audit run --list-matrix`")
	}
	if n := len(matrix.Rows()); !strings.Contains(doc, fmt.Sprintf("%d rows", n)) {
		t.Errorf("docs/leak-assurance.md does not state the row count %d", n)
	}
}

// jsonEscape is the body of a JSON string holding v, without HTML escaping,
// the form the naive stub matches.
func jsonEscape(v string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	q := bytes.TrimSpace(b.Bytes())
	return string(q[1 : len(q)-1])
}

func TestJSONEscapeSelfContainment(t *testing.T) {
	// The case the naive self-test allows for, and one it does not.
	if once := jsonEscape(`\"abc`); !strings.Contains(jsonEscape(once), once) {
		t.Errorf("leading escapes: once-escaped form should be inside the twice-escaped one")
	}
	if once := jsonEscape(`ab"c\d`); strings.Contains(jsonEscape(once), once) {
		t.Errorf("inner escapes: once-escaped form should not survive a second escape")
	}
}
