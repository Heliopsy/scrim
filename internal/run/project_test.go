// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
)

// registry records PUT /v1/sessions/self/values calls.
type registry struct {
	mu    sync.Mutex
	calls []map[string]string // name to value, per call
	fail  error
}

func (r *registry) set(_ context.Context, _ string, values []localapi.NamedValue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := map[string]string{}
	for _, v := range values {
		_ = v.Value.Expose(func(b []byte) error { m[v.Name] = string(b); return nil })
		v.Value.Wipe()
	}
	if r.fail != nil {
		return r.fail
	}
	r.calls = append(r.calls, m)
	return nil
}

func (r *registry) snapshot() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]string(nil), r.calls...)
}

func TestRunRegistersProjectValuesBeforeTheAgentStarts(t *testing.T) {
	h := newHarness(t, true)
	reg := &registry{}
	h.api.API.SessionValues = reg.set
	work := t.TempDir()
	key, later := leak.Generate(leak.KindAPIKey), leak.Generate(leak.KindAPIKey)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("OPENAI_API_KEY="+key.Value()+"\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb syncBuf
	err := Run(context.Background(), Options{
		Command: []string{selfAgent(t)},
		Environ: baseEnv(t, envAgent+"=rewrite", "TEST_LATER_VALUE="+later.Value()),
		Dir:     work, Daemon: h.daemon(), Stdout: &out, Stderr: &errb, RuntimeDir: t.TempDir(),
		ScanProject: true, ScanInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, errb.String())
	}
	calls := reg.snapshot()
	if len(calls) < 2 {
		t.Fatalf("%d registrations, want the start and the change", len(calls))
	}
	if calls[0][".env#OPENAI_API_KEY"] != key.Value() || len(calls[0]) != 1 {
		t.Errorf("first registration has %d values and not the .env key", len(calls[0]))
	}
	last := calls[len(calls)-1]
	if last[".env#LATER_API_TOKEN"] != later.Value() {
		t.Errorf("the rewritten .env value was not registered (last registration: %d values)", len(last))
	}
	if strings.Contains(errb.String(), key.Value()) || strings.Contains(out.String(), key.Value()) {
		t.Error("scrim run printed a project value")
	}
	if !strings.Contains(errb.String(), "1 secret values in project files are redacted") {
		t.Errorf("no notice about the project values:\n%s", errb.String())
	}
}

func TestRunRefusesWhenProjectValuesCannotBeRegistered(t *testing.T) {
	h := newHarness(t, true)
	h.api.API.SessionValues = (&registry{fail: errors.New("data plane down")}).set
	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("STRIPE_SECRET_KEY="+leak.Generate(leak.KindAPIKey).Value()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(work, "started")
	var errb syncBuf
	err := Run(context.Background(), Options{
		Command: []string{"sh", "-c", "touch " + marker},
		Environ: baseEnv(t), Dir: work, Daemon: h.daemon(), Stderr: &errb, RuntimeDir: t.TempDir(), ScanProject: true,
	})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("run: %v, want refused", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the agent started although its project values were not registered")
	}
}
