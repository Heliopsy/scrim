// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
)

func TestPassThroughFailsAndReportHoldsNoValue(t *testing.T) {
	dir := t.TempDir()
	seedsPath := filepath.Join(dir, "seeds.json")
	rep, err := Run(context.Background(), Options{
		Proxy:    BuiltinPassThrough,
		SeedsOut: seedsPath,
		Rows:     []string{"anthropic-messages/tool-result/", "openai-chat/header/"},
	})
	if !errors.Is(err, ErrGate) || rep == nil || rep.Pass {
		t.Fatalf("pass-through: err=%v pass=%v", err, rep != nil && rep.Pass)
	}
	if rep.Summary.GatedLeaks == 0 || rep.Summary.ScenarioFailures == 0 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	if fi, err := os.Stat(seedsPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("seed file: %v %v", fi, err)
	}
	seeds, err := leak.ReadSeedFile(seedsPath)
	if err != nil {
		t.Fatal(err)
	}
	var js bytes.Buffer
	if err := rep.WriteJSON("-", &js); err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	rep.WriteText(&text)
	if !json.Valid(js.Bytes()) {
		t.Fatal("report is not JSON")
	}
	for _, s := range seeds {
		esc, _ := json.Marshal(s.Value())
		for _, out := range []string{js.String(), text.String()} {
			if strings.Contains(out, s.Value()) || strings.Contains(out, string(esc[1:len(esc)-1])) {
				t.Fatalf("report contains the value of %s", s.Name)
			}
		}
	}
	if !strings.Contains(text.String(), "FAIL anthropic-messages/tool-result/raw") {
		t.Errorf("text report does not name the failing row:\n%s", text.String())
	}
}

func TestSeedsInAndNaiveRedactsRaw(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "seeds.json")
	if err := leak.WriteSeedFile(p, leak.GenerateSet(leak.KindGitHubToken, leak.KindPassword)); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		Proxy: BuiltinNaive, SeedsIn: p, Suites: []string{SuiteMatrix},
		Rows: []string{"anthropic-messages/tool-result/raw", "openai-responses/user-text/raw"},
	})
	if err != nil {
		t.Fatalf("naive stub on raw rows: %v %+v", err, rep.Summary)
	}
	if !rep.Pass || len(rep.Seeds) != 2 || rep.Matrix.Totals.Cases != 4 {
		t.Fatalf("report %+v", rep.Summary)
	}
}

func TestBadOptions(t *testing.T) {
	for _, o := range []Options{{}, {Proxy: BuiltinNaive, Driver: "codex"}, {Proxy: BuiltinNaive, Suites: []string{"nope"}}} {
		if _, err := Run(context.Background(), o); err == nil || errors.Is(err, ErrGate) {
			t.Errorf("%+v: err %v", o, err)
		}
	}
}
