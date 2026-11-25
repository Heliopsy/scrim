// SPDX-License-Identifier: AGPL-3.0-only

package sinks_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/testing/testpodman"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/audit/sinks"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

var (
	lokiSvc      = podtest.Loki()
	collectorSvc = podtest.Collector()
	redpandaSvc  = podtest.Redpanda()
)

func TestMain(m *testing.M) {
	code := m.Run()
	lokiSvc.Stop()
	collectorSvc.Stop()
	redpandaSvc.Stop()
	os.Exit(code)
}

// counting observes one fanout for the invariant the scenario checks.
type counting struct {
	mu                          sync.Mutex
	delivered, dropped, refused int
}

func (c *counting) AuditSinkDelivered(_ string, n int, _ time.Duration) {
	c.mu.Lock()
	c.delivered += n
	c.mu.Unlock()
}
func (c *counting) AuditSinkWriteFailed(string, time.Duration) {}
func (c *counting) AuditSinkDropped(_, _ string, n int)        { c.mu.Lock(); c.dropped += n; c.mu.Unlock() }
func (c *counting) AuditSinkRefused(_ string, n int)           { c.mu.Lock(); c.refused += n; c.mu.Unlock() }
func (c *counting) AuditSinkQueue(string, int, int)            {}
func (c *counting) AuditSinkUp(string, bool)                   {}
func (c *counting) get() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delivered, c.dropped, c.refused
}

// backend is one real sink under test.
type backend struct {
	svc *podtest.Service
	// newSink builds a fresh sink; run tags what this test writes.
	newSink func(t *testing.T, run string) audit.Sink
	// subjects returns the subjects of entries of run the backend holds.
	subjects func(t *testing.T, run string) map[string]int
}

func waitUntil(t *testing.T, what string, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting until %s", d, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func writeOne(t *testing.T, f *audit.Fanout, run string, i int) error {
	t.Helper()
	e := entry(fmt.Sprintf("%s-%d", run, i))
	e.ID = int64(i)
	return f.Write(t.Context(), []audit.Entry{e})
}

// pausedScenario is the 14.2 check against a real backend: entries reach
// it; then the container is frozen, so the sink stops answering without
// closing its connections. Under drop no write waits and every entry that
// does not fit the queue is counted; under block writes wait for room up
// to the timeout and are then refused, counted. Once the container runs
// again both queues drain, and the backend holds exactly the entries that
// were neither dropped nor refused: delivered + dropped + refused equals
// what was written, so no entry is lost silently.
func pausedScenario(t *testing.T, b backend) {
	b.svc.Addr(t)
	run := "run-" + podtest.RandHex(4)
	dropObs, blockObs := &counting{}, &counting{}
	opts := audit.FanoutOptions{MinBackoff: 100 * time.Millisecond, MaxBackoff: 500 * time.Millisecond}
	dopts, bopts := opts, opts
	dopts.Observer, bopts.Observer = dropObs, blockObs
	dropSink, blockSink := b.newSink(t, run), b.newSink(t, run)
	drop := audit.NewFanout(dopts, audit.Target{Sink: dropSink, Policy: audit.Drop, QueueSize: 20, BatchSize: 5, WriteTimeout: time.Second})
	block := audit.NewFanout(bopts, audit.Target{Sink: blockSink, Policy: audit.Block, QueueSize: 5, BatchSize: 5,
		Timeout: 400 * time.Millisecond, WriteTimeout: time.Second})
	drop.Start(t.Context())
	block.Start(t.Context())
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = drop.Close(ctx)
		_ = block.Close(ctx)
		sinks.CloseAll([]audit.Target{{Sink: dropSink}, {Sink: blockSink}})
	}()

	// Healthy: everything arrives.
	n := 0
	for range 10 {
		if err := writeOne(t, drop, run, n); err != nil {
			t.Fatal(err)
		}
		n++
	}
	waitUntil(t, "the first 10 entries delivered", 60*time.Second, func() bool { d, _, _ := dropObs.get(); return d == 10 })

	resume := b.svc.Pause(t)
	// Drop: 50 writes, none waits, the queue keeps 20, 30 are counted.
	start := time.Now()
	for range 50 {
		if err := writeOne(t, drop, run, n); err != nil {
			t.Fatalf("drop policy refused a write: %v", err)
		}
		n++
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("50 writes under drop took %s with the sink paused", d)
	}
	if _, dropped, _ := dropObs.get(); dropped != 30 {
		t.Fatalf("drop policy counted %d dropped entries, want 30", dropped)
	}
	st := drop.Status()[0]
	waitUntil(t, "the paused sink reported down", 10*time.Second, func() bool { return !drop.Status()[0].Up })
	if st.Queued != 20 || st.Dropped != 30 {
		t.Fatalf("drop status %+v", st)
	}

	// Block: the queue takes 5, the sixth write waits for the timeout and
	// is refused.
	bn := 0
	for range 5 {
		if err := writeOne(t, block, run+"-b", bn); err != nil {
			t.Fatalf("block write within the queue: %v", err)
		}
		bn++
	}
	start = time.Now()
	err := writeOne(t, block, run+"-b", 99)
	if !errors.Is(err, audit.ErrNotAudited) {
		t.Fatalf("block policy with the sink paused and its queue full = %v", err)
	}
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Fatalf("refused after %s, before the 400ms timeout", d)
	}
	if _, _, refused := blockObs.get(); refused != 1 {
		t.Fatalf("refused counter %d", refused)
	}

	resume()
	waitUntil(t, "both queues drained", 90*time.Second, func() bool {
		return drop.Status()[0].Queued == 0 && block.Status()[0].Queued == 0
	})
	dd, dropped, _ := dropObs.get()
	bd, _, refused := blockObs.get()
	if dd+dropped != 60 || bd+refused != 6 {
		t.Fatalf("drop: delivered %d + dropped %d != 60 written; block: delivered %d + refused %d != 6 written", dd, dropped, bd, refused)
	}
	// The backend holds every delivered entry (at least once) and none of
	// the refused one.
	var got map[string]int
	waitUntil(t, "the backend shows every delivered entry", 60*time.Second, func() bool {
		got = b.subjects(t, run)
		return len(got) >= dd+bd
	})
	if len(got) != dd+bd {
		t.Fatalf("backend holds %d distinct entries, %d were delivered", len(got), dd+bd)
	}
	if got[run+"-b-99"] > 0 {
		t.Fatal("the refused entry reached the backend")
	}
	for i := range 5 {
		if got[fmt.Sprintf("%s-b-%d", run, i)] == 0 {
			t.Fatalf("queued block entry %d never arrived", i)
		}
	}
	t.Logf("%s: drop delivered %d, dropped %d; block delivered %d, refused %d", b.svc.Name, dd, dropped, bd, refused)
}

var subjectRE = regexp.MustCompile(`subject\\?":\\?"(run-[0-9a-f]+(?:-b)?-[0-9]+)`)

func TestLokiPausedSink(t *testing.T) {
	pausedScenario(t, backend{
		svc: lokiSvc,
		newSink: func(t *testing.T, run string) audit.Sink {
			s, err := sinks.NewLoki(sinks.LokiOptions{URL: "http://" + lokiSvc.Addr(t), Labels: map[string]string{"run": run}})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		subjects: func(t *testing.T, run string) map[string]int {
			q := url.Values{"query": {`{source="audit",run="` + run + `"}`}, "limit": {"5000"},
				"start": {strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10)}, "end": {strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10)}}
			resp, err := http.Get("http://" + lokiSvc.Addr(t) + "/loki/api/v1/query_range?" + q.Encode())
			if err != nil {
				return nil
			}
			defer func() { _ = resp.Body.Close() }()
			var r struct {
				Data struct {
					Result []struct {
						Values [][2]string `json:"values"`
					} `json:"result"`
				} `json:"data"`
			}
			if json.NewDecoder(resp.Body).Decode(&r) != nil {
				return nil
			}
			out := map[string]int{}
			for _, s := range r.Data.Result {
				for _, v := range s.Values {
					for _, m := range subjectRE.FindAllStringSubmatch(v[1], -1) {
						out[m[1]]++
					}
				}
			}
			return out
		},
	})
}

func TestOTLPCollectorPausedSink(t *testing.T) {
	pausedScenario(t, backend{
		svc: collectorSvc,
		newSink: func(t *testing.T, _ string) audit.Sink {
			s, err := sinks.NewOTLP(t.Context(), sinks.OTLPOptions{Endpoint: "http://" + collectorSvc.Addr(t)})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		subjects: func(t *testing.T, run string) map[string]int {
			if collectorSvc.Container() == "" {
				t.Skip("reading what the collector received needs the container this test started")
			}
			out, err := testpodman.Command("logs", collectorSvc.Container()).CombinedOutput()
			if err != nil {
				return nil
			}
			got := map[string]int{}
			for _, m := range subjectRE.FindAllStringSubmatch(string(out), -1) {
				if strings.HasPrefix(m[1], run) {
					got[m[1]]++
				}
			}
			return got
		},
	})
}

func TestKafkaPausedSink(t *testing.T) {
	topic := "scrim-audit-" + podtest.RandHex(3)
	pausedScenario(t, backend{
		svc: redpandaSvc,
		newSink: func(t *testing.T, _ string) audit.Sink {
			s, err := sinks.NewKafka(sinks.KafkaOptions{Brokers: []string{redpandaSvc.Addr(t)}, Topic: topic,
				Options: []kgo.Opt{kgo.AllowAutoTopicCreation()}})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		subjects: func(t *testing.T, run string) map[string]int {
			cl, err := kgo.NewClient(kgo.SeedBrokers(redpandaSvc.Addr(t)), kgo.ConsumeTopics(topic),
				kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			got := map[string]int{}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			for {
				fs := cl.PollFetches(ctx)
				if ctx.Err() != nil {
					return got
				}
				fs.EachRecord(func(r *kgo.Record) {
					for _, m := range subjectRE.FindAllStringSubmatch(string(r.Value), -1) {
						if strings.HasPrefix(m[1], run) {
							got[m[1]]++
						}
					}
				})
			}
		},
	})
}
