// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/status"
)

// TestProjectMoveOnlyAfterConfirmation is the fixture of tasks 10a.11: a
// .env key is listed, never printed, and moved into the store and replaced
// by a reference only after the user says yes.
func TestProjectMoveOnlyAfterConfirmation(t *testing.T) {
	ts := cliServer(t)
	dir := t.TempDir()
	key := leak.Generate(leak.KindAPIKey).Value()
	env := filepath.Join(dir, ".env")
	orig := "DEBUG=true\nOPENAI_API_KEY=" + key + "\n"
	if err := os.WriteFile(env, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	const ref = "bao://kv/agents/openai-api-key#value"

	r := runCLI(ts, nil, "project", "scan", "--dir", dir)
	if r.code != 0 || !strings.Contains(r.stdout, ".env:2 OPENAI_API_KEY") {
		t.Fatalf("scan: %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	// No.
	r = runCLI(ts, strings.NewReader("n\n"), "project", "move", "--dir", dir)
	if r.code != 0 || !strings.Contains(r.stdout, "0 moved, 1 left in place") {
		t.Fatalf("move, answered no: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if b, _ := os.ReadFile(env); string(b) != orig {
		t.Fatal("the file changed although the user said no")
	}
	if _, ok := ts.Store.Value(ref); ok {
		t.Fatal("the value was written although the user said no")
	}
	// No answer at all is no.
	if r = runCLI(ts, nil, "project", "move", "--dir", dir); !strings.Contains(r.stdout, "0 moved") {
		t.Fatalf("move without an answer: %s", r.stdout)
	}

	// Yes.
	r = runCLI(ts, strings.NewReader("y\n"), "project", "move", "--dir", dir)
	if r.code != 0 || !strings.Contains(r.stdout, "1 moved") {
		t.Fatalf("move, answered yes: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if v, ok := ts.Store.Value(ref); !ok || string(v) != key {
		t.Fatalf("the store does not hold the moved value at %s", ref)
	}
	if b, _ := os.ReadFile(env); string(b) != "DEBUG=true\nOPENAI_API_KEY={{scrim:"+ref+"}}\n" {
		t.Fatalf("file after the move:\n%s", b)
	}
	for _, out := range []string{r.stdout, r.stderr} {
		if strings.Contains(out, key) {
			t.Fatal("scrim project printed the value")
		}
	}
}

func TestDoctorOffersToMoveProjectValues(t *testing.T) {
	dir := t.TempDir()
	key := leak.Generate(leak.KindAPIKey).Value()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("STRIPE_SECRET_KEY="+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := projectChecks(dir)[0].Run(context.Background())
	if len(fs) != 1 || fs[0].Outcome != status.Warn || !strings.Contains(fs[0].Message, ".env:1 STRIPE_SECRET_KEY") ||
		!strings.Contains(fs[0].Fix, "scrim project move") {
		t.Fatalf("findings = %+v", fs)
	}
	if strings.Contains(fs[0].Message+fs[0].Fix, key) {
		t.Fatal("doctor shows the value")
	}
}
