// SPDX-License-Identifier: AGPL-3.0-only

package sinks_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/audit/sinks"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// capture is an HTTP endpoint that records every request body, gunzipped.
type capture struct {
	mu     sync.Mutex
	bodies [][]byte
	heads  []http.Header
	status int
}

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rd io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		rd = zr
	}
	b, _ := io.ReadAll(rd)
	c.mu.Lock()
	c.bodies = append(c.bodies, b)
	c.heads = append(c.heads, r.Header.Clone())
	st := c.status
	c.mu.Unlock()
	if st == 0 {
		st = http.StatusNoContent
		if strings.HasSuffix(r.URL.Path, "/v1/logs") {
			st = http.StatusOK
			w.Header().Set("Content-Type", "application/x-protobuf")
		}
	}
	w.WriteHeader(st)
}

func (c *capture) all() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.bodies, []byte("\n"))
}

func entry(subject string) audit.Entry {
	return audit.Entry{ID: 7, Time: time.Now().UTC(), Action: "grant.revoked", Actor: "operator",
		Agent: policy.Agent{ID: "dev"}, Ref: stores.MustParseRef("env://TOKEN"), Effect: policy.Allow,
		Subject: subject, Outcome: audit.OutcomeOK, Attrs: map[string]string{"via": "test"}}
}

func TestLokiPushFormat(t *testing.T) {
	c := &capture{}
	srv := httptest.NewServer(c)
	defer srv.Close()
	pw := secret.FromString("pw-" + randHex(8))
	s, err := sinks.NewLoki(sinks.LokiOptions{URL: srv.URL + "/", Tenant: "team-a", Username: "scrim", Password: pw,
		Labels: map[string]string{"cluster": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(t.Context(), []audit.Entry{entry("s2"), entry("s1")}); err != nil {
		t.Fatal(err)
	}
	var push struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(c.all(), &push); err != nil {
		t.Fatal(err)
	}
	st := push.Streams[0]
	if st.Stream["service_name"] != "scrim" || st.Stream["source"] != "audit" || st.Stream["cluster"] != "test" || len(st.Values) != 2 {
		t.Fatalf("stream %+v", st)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(st.Values[0][1]), &rec); err != nil || rec["action"] != "grant.revoked" || rec["ref"] != "env://TOKEN" {
		t.Fatalf("line %s: %v", st.Values[0][1], err)
	}
	h := c.heads[0]
	if h.Get("X-Scope-OrgID") != "team-a" || !strings.HasPrefix(h.Get("Authorization"), "Basic ") {
		t.Fatalf("headers %v", h)
	}

	c.status = http.StatusBadRequest
	err = s.Write(t.Context(), []audit.Entry{entry("bad")})
	if err == nil || strings.Contains(err.Error(), "bad") && !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("400 = %v", err)
	}
	c.status = http.StatusUnauthorized
	if err := s.Write(t.Context(), []audit.Entry{entry("x")}); err == nil || strings.Contains(err.Error(), "rejected") {
		t.Fatalf("401 must be retried, not rejected: %v", err)
	}
	if _, err := sinks.NewLoki(sinks.LokiOptions{URL: "http://u:p@loki:3100"}); err == nil {
		t.Fatal("credentials in the URL accepted")
	}
}

func TestOTLPExport(t *testing.T) {
	c := &capture{}
	srv := httptest.NewServer(c)
	defer srv.Close()
	tok := secret.FromString("tok-" + randHex(8))
	s, err := sinks.NewOTLP(t.Context(), sinks.OTLPOptions{Endpoint: srv.URL, Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Write(t.Context(), []audit.Entry{entry("o1"), entry("o2")}); err != nil {
		t.Fatal(err)
	}
	var req collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(c.all(), &req); err != nil {
		t.Fatal(err)
	}
	rl := req.GetResourceLogs()[0]
	var svc string
	for _, a := range rl.GetResource().GetAttributes() {
		if a.GetKey() == "service.name" {
			svc = a.GetValue().GetStringValue()
		}
	}
	recs := rl.GetScopeLogs()[0].GetLogRecords()
	if svc != "scrim" || len(recs) != 2 || recs[0].GetEventName() != "scrim.audit" ||
		!strings.Contains(recs[0].GetBody().GetStringValue(), `"subject":"o1"`) {
		t.Fatalf("service %q, records %v", svc, recs)
	}
	if got := c.heads[0].Get("Authorization"); got == "" || !strings.HasPrefix(got, "Bearer ") {
		t.Fatal("bearer token not sent")
	}
	c.status = http.StatusServiceUnavailable
	if err := s.Write(t.Context(), []audit.Entry{entry("o3")}); err == nil {
		t.Fatal("503 accepted")
	}
}

func TestTargetsFromConfig(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{
		"SCRIM_AUDIT_SINKS=db,loki,kafka",
		"SCRIM_AUDIT_LOKI_URL=http://loki:3100", "SCRIM_AUDIT_LOKI_POLICY=block", "SCRIM_AUDIT_LOKI_TIMEOUT=2s",
		"SCRIM_AUDIT_KAFKA_BROKERS=k1:9092", "SCRIM_AUDIT_KAFKA_QUEUE_SIZE=50",
	}))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := sinks.Targets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sinks.CloseAll(ts)
	if len(ts) != 2 || ts[0].Sink.Name() != "loki" || ts[0].Policy != audit.Block || ts[0].Timeout != 2*time.Second ||
		ts[1].Sink.Name() != "kafka" || ts[1].Policy != audit.Drop || ts[1].QueueSize != 50 {
		t.Fatalf("targets %+v", ts)
	}
	for _, env := range [][]string{
		{"SCRIM_AUDIT_SINKS=otlp"},
		{"SCRIM_AUDIT_SINKS=loki", "SCRIM_AUDIT_LOKI_URL=ftp://x"},
		{"SCRIM_AUDIT_SINKS=kafka", "SCRIM_AUDIT_KAFKA_BROKERS=k:1", "SCRIM_AUDIT_KAFKA_SASL_MECHANISM=plain",
			"SCRIM_AUDIT_KAFKA_USERNAME=u", "SCRIM_AUDIT_KAFKA_PASSWORD=env:SCRIMTEST_KPW", "SCRIMTEST_KPW=x"},
	} {
		cfg, err := config.Load(config.Default, config.EnvLayer(env))
		if err != nil {
			t.Fatalf("%v: %v", env, err)
		}
		if ts, err := sinks.Targets(cfg); err == nil {
			sinks.CloseAll(ts)
			t.Fatalf("%v accepted", env)
		}
	}
	if _, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_AUDIT_SINKS=splunk"})); err == nil {
		t.Fatal("unknown sink accepted")
	}
}

// kafkaCapture records every record the client buffers for produce: the
// exact key and value bytes that would go to the broker.
type kafkaCapture struct {
	mu   sync.Mutex
	data [][]byte
}

func (k *kafkaCapture) OnProduceRecordBuffered(r *kgo.Record) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data = append(k.data, append(append([]byte(nil), r.Key...), r.Value...))
}

func (k *kafkaCapture) all() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return bytes.Join(k.data, []byte("\n"))
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func forms(v string) map[string]string {
	return map[string]string{
		"raw": v, "query": url.QueryEscape(v), "hex": hex.EncodeToString([]byte(v)),
		"base64": base64.StdEncoding.EncodeToString([]byte(v)), "b64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
	}
}

// TestSinkPayloadLeak extends the telemetry leak check (internal/obs) to
// what the audit sinks send: generated values are planted, in every
// encoding, in every free-text field of audit entries that go through the
// fanout to the Loki, OTLP and Kafka sinks; the exact bytes each sink puts
// on the wire are captured and searched for every value in every encoding.
func TestSinkPayloadLeak(t *testing.T) {
	seeded := []string{
		"sk-ant-api03-" + randHex(20),
		"ghp_" + randHex(18),
		"p@ss w0rd&with=specials/+\"" + randHex(6) + "\"",
	}
	vals := make([]secret.Value, len(seeded))
	for i, s := range seeded {
		vals[i] = secret.FromString(s)
	}
	slot := &obs.ScrubberSlot{}
	slot.Set(obs.NewValueScrubber(vals...))

	lc, oc := &capture{}, &capture{}
	lsrv, osrv := httptest.NewServer(lc), httptest.NewServer(oc)
	defer lsrv.Close()
	defer osrv.Close()
	loki, err := sinks.NewLoki(sinks.LokiOptions{URL: lsrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	otlp, err := sinks.NewOTLP(t.Context(), sinks.OTLPOptions{Endpoint: osrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = otlp.Close() }()
	kc := &kafkaCapture{}
	kafka, err := sinks.NewKafka(sinks.KafkaOptions{Brokers: []string{"127.0.0.1:1"}, Topic: "audit",
		Options: []kgo.Opt{kgo.WithHooks(kc)}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kafka.Close() }()
	// Kafka has no broker here: its writes fail after the hook saw the
	// bytes, and the fanout keeps retrying; the capture is what counts.
	f := audit.NewFanout(audit.FanoutOptions{Scrub: slot.Scrub},
		audit.Target{Sink: loki, Policy: audit.Drop}, audit.Target{Sink: otlp, Policy: audit.Drop},
		audit.Target{Sink: kafka, Policy: audit.Drop, WriteTimeout: 300 * time.Millisecond})
	f.Start(t.Context())
	var batch []audit.Entry
	for _, v := range seeded {
		for name, fv := range forms(v) {
			e := audit.Entry{Time: time.Now(), Action: "store.write " + fv, Actor: fv, Rule: "rule-" + fv, Target: "https://" + fv,
				Subject: fv, RequestID: fv, Outcome: audit.OutcomeFailed, Reason: "upstream said: " + fv + " (" + name + ")",
				Agent: policy.Agent{ID: fv, Session: fv, Labels: map[string]string{"pod": fv, fv: "x"}},
				Ref:   stores.Ref{Scheme: "env", Path: fv, Field: fv},
				Attrs: map[string]string{"detail": fv, fv: "key"}}
			batch = append(batch, e)
		}
	}
	if err := f.Write(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(lc.all()) == 0 || len(oc.all()) == 0 || len(kc.all()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("not every sink sent: loki %d, otlp %d, kafka %d bytes", len(lc.all()), len(oc.all()), len(kc.all()))
		}
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_ = f.Close(ctx)
	for sink, payload := range map[string][]byte{"loki": lc.all(), "otlp": oc.all(), "kafka": kc.all()} {
		if !bytes.Contains(payload, []byte(secret.Marker)) {
			t.Errorf("%s payload has no marker: the test did not exercise the scrubber", sink)
		}
		// JSON escapes some characters; search the unescaped form too.
		unescaped := strings.NewReplacer(`\"`, `"`, `&`, "&", `<`, "<", `>`, ">", `\/`, "/").Replace(string(payload))
		for i, v := range seeded {
			for name, fv := range forms(v) {
				if bytes.Contains(payload, []byte(fv)) || strings.Contains(unescaped, fv) {
					t.Errorf("seeded value %d reached the %s sink as %s", i, sink, name)
				}
			}
		}
	}
}
