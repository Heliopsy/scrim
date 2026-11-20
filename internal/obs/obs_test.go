// SPDX-License-Identifier: AGPL-3.0-only

package obs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
)

func gen(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sk-" + hex.EncodeToString(b)
}

func TestLoggerNeverPrintsValues(t *testing.T) {
	plain := gen(t)
	echoed := gen(t)
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			log := obs.WithComponent(obs.NewLogger(&buf, obs.LogOptions{
				Level: slog.LevelDebug, Format: format, Scrubber: obs.ReplaceAll(echoed),
			}), "proxy")
			v := secret.FromString(plain)
			log.Info("loaded", "value", v, "raw", []byte(plain))
			log.Error("upstream said "+echoed, "err", fmt.Errorf("401: bad key %s", echoed), "detail", echoed)
			log.With("bound", echoed).WithGroup("g").Warn("grouped", "s", struct{ K string }{echoed})
			out := buf.String()
			for _, leak := range []string{plain, echoed} {
				if strings.Contains(out, leak) {
					t.Fatalf("log output contains a value:\n%s", out)
				}
			}
			if !strings.Contains(out, secret.Marker) || !strings.Contains(out, "component") {
				t.Fatalf("missing marker or component:\n%s", out)
			}
		})
	}
}

func TestJSONRecordShape(t *testing.T) {
	var buf bytes.Buffer
	obs.WithComponent(obs.NewLogger(&buf, obs.LogOptions{Format: "json"}), "control").Info("hello")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"time", "level", "msg", "component"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("record lacks %q: %v", k, rec)
		}
	}
}

func TestLoggerFromConfig(t *testing.T) {
	c, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_LOG_LEVEL=warn", "SCRIM_LOG_FORMAT=json"}))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log, err := obs.LoggerFromConfig(&buf, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("dropped")
	log.Warn("kept")
	if strings.Contains(buf.String(), "dropped") || !strings.HasPrefix(buf.String(), "{") {
		t.Fatalf("level or format not applied: %s", buf.String())
	}
}

func TestScrubberSlot(t *testing.T) {
	var slot obs.ScrubberSlot
	if slot.Scrub("x") != "x" {
		t.Fatal("empty slot must pass through")
	}
	slot.Set(obs.ReplaceAll("x"))
	if slot.Scrub("axb") != "a"+secret.Marker+"b" {
		t.Fatal("slot did not scrub")
	}
}

func TestHealth(t *testing.T) {
	leak := gen(t)
	h := obs.NewHealth()
	h.Scrubber = obs.ReplaceAll(leak)
	h.Live("process", func(context.Context) error { return nil })
	h.Ready("store:bao", func(context.Context) error { return errors.New("never loaded, last error echoed " + leak) })

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()
	for path, want := range map[string]int{"/livez": 200, "/readyz": 503} {
		resp, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, resp.StatusCode, want)
		}
		if strings.Contains(string(body), leak) {
			t.Errorf("%s leaks: %s", path, body)
		}
		if path == "/readyz" && !strings.Contains(string(body), "store:bao") {
			t.Errorf("readiness does not name the store: %s", body)
		}
	}
}

func TestMetrics(t *testing.T) {
	m := obs.NewMetrics()
	m.Counter("guard", "refusals_total", "Requests the guard refused.", "provider", "agent").WithLabelValues("anthropic", "a1").Inc()
	m.Histogram("redaction", "added_seconds", "Added latency.", nil, "provider").WithLabelValues("anthropic").Observe(0.001)
	m.Gauge("store", "values_loaded", "Values loaded per store.", "store").WithLabelValues("bao").Set(3)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{`scrim_guard_refusals_total{agent="a1",provider="anthropic"} 1`, "scrim_redaction_added_seconds_bucket", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
}
