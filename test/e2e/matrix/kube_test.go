// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/matrix"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// TestMatrixKubernetes is the Kubernetes cell of the matrix, run by
// test/k8s/e2e.sh once the chart is installed: the bypass matrix through the
// central scrim Deployment and through an agent pod's scrim sidecar, with the
// seeds in the cluster's OpenBao (read by scrim with its own service account
// token) and the cluster's fake provider as the upstream. The script reaches
// each with kubectl port-forward and names them here:
//
//	SCRIM_MATRIX_K8S_BAO, SCRIM_MATRIX_K8S_BAO_TOKEN  OpenBao and a token to write the seeds with
//	SCRIM_MATRIX_K8S_FAKE                             the fake provider (its /_fake control endpoints)
//	SCRIM_MATRIX_K8S_TARGETS                          name=url,... of the LLM base URLs to test
//	SCRIM_MATRIX_K8S_APIS                             name=api,... the API each target runs
//
// It skips without them.
func TestMatrixKubernetes(t *testing.T) {
	bao, fake, targets := os.Getenv("SCRIM_MATRIX_K8S_BAO"), os.Getenv("SCRIM_MATRIX_K8S_FAKE"), os.Getenv("SCRIM_MATRIX_K8S_TARGETS")
	if bao == "" || fake == "" || targets == "" {
		t.Skip("run by test/k8s/e2e.sh")
	}
	apis := map[string]fp.API{}
	for _, kv := range strings.Split(os.Getenv("SCRIM_MATRIX_K8S_APIS"), ",") {
		if name, api, ok := strings.Cut(kv, "="); ok {
			apis[name] = fp.API(api)
		}
	}
	ctx := t.Context()
	seeds := leak.GenerateSet()
	a, err := stores.DefaultRegistry.Open(ctx, stores.Instance{Name: "bao", Kind: "openbao",
		Options: map[string]any{"address": bao, "token": "test:token"},
		Resolve: func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
			if ref != "test:token" {
				return secret.Value{}, errors.New("no such reference")
			}
			return secret.FromString(os.Getenv("SCRIM_MATRIX_K8S_BAO_TOKEN")), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	// Under secret/e2e, which the chart's store redacts and scrim's
	// OpenBao role may read (test/k8s/e2e.sh).
	for i, s := range seeds {
		ref := stores.MustParseRef(fmt.Sprintf("bao://secret/e2e/matrix-seed-%d", i))
		if _, err := a.Write(ctx, ref, map[string]secret.Value{"value": secret.FromString(s.Value())}, stores.WriteOptions{}); err != nil {
			t.Fatalf("write %s: %v", ref, err)
		}
	}
	up := matrix.RemoteUpstream{BaseURL: fake, Client: &http.Client{Timeout: 30 * time.Second}}
	checker := leak.NewChecker(seeds)

	for _, kv := range strings.Split(targets, ",") {
		name, base, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("SCRIM_MATRIX_K8S_TARGETS: %q is not name=url", kv)
		}
		api := apis[name]
		if api == "" {
			api = fp.Anthropic
		}
		t.Run(name, func(t *testing.T) {
			prefix := map[fp.API]string{fp.Anthropic: "/anthropic", fp.OpenAIChat: "/openai", fp.OpenAIResponses: "/openai", fp.Gemini: "/gemini"}
			target := matrix.Target{BaseURL: base, Prefix: prefix, Client: &http.Client{Timeout: 60 * time.Second}}
			waitLoaded(t, target, up, checker, seeds, api)
			var rows []matrix.Row
			for _, r := range matrix.Rows() {
				if r.API == api {
					rows = append(rows, r)
				}
			}
			var failed []string
			runner := &matrix.Runner{Target: target, Upstream: up, Checker: checker, Progress: func(r matrix.Result) {
				if !r.Pass {
					failed = append(failed, r.Describe())
				}
			}}
			results, err := runner.Run(ctx, rows, seeds)
			if err != nil {
				t.Fatal(err)
			}
			tot := matrix.Tally(results)
			t.Logf("%s (%s): %d results, %d gated leaks, %d known-limitation leaks (not gated), %d errors",
				name, api, tot.Cases, tot.GatedLeaks, tot.Limitations, tot.Errors)
			if tot.Failed > 0 || tot.Errors > 0 {
				b, _ := json.MarshalIndent(failed, "", "  ")
				t.Errorf("%d results not at their expected outcome:\n%s", tot.Failed, b)
			}
		})
	}
}

// waitLoaded waits until scrim redacts every seed (its store watch picks up
// the new secrets within seconds), so the matrix does not start before the
// values are loaded.
func waitLoaded(t *testing.T, target matrix.Target, up matrix.Upstream, checker *leak.Checker, seeds []leak.Seed, api fp.API) {
	t.Helper()
	var row []matrix.Row
	for _, r := range matrix.Rows() {
		if r.ID == string(api)+"/tool-result/raw" {
			row = append(row, r)
		}
	}
	if len(row) != 1 {
		t.Fatalf("no %s/tool-result/raw row", api)
	}
	deadline := time.Now().Add(90 * time.Second)
	runner := &matrix.Runner{Target: target, Upstream: up, Checker: checker}
	var last matrix.Result
	for {
		ok := true
		for _, s := range seeds {
			if last = runner.RunRow(t.Context(), row[0], s); last.Outcome != matrix.OutcomeRedacted {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scrim did not redact every seed within 90s; last: %s statuses=%v forwarded=%d error=%q",
				last.Describe(), last.Statuses, last.Forwarded, last.Error)
		}
		time.Sleep(2 * time.Second)
	}
}
