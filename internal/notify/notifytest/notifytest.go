// SPDX-License-Identifier: AGPL-3.0-only

// Package notifytest is the notifier contract suite (specs/policy-approvals
// "Notifiers"). A notifier's tests call [Run] with a harness that can see
// what reached the far end:
//
//	notifytest.Run(t, func(t notifytest.TB) notifytest.Harness {
//		return notifytest.Harness{Notifier: n, Delivered: readInbox}
//	})
//
// The cases check that a request arrives with what a human needs to decide
// it (approval ID, agent, action, secret, rule, reason, expiry, both
// decision links), that success means delivered, that a failing channel
// returns an error and the error carries no decision link (whoever holds one
// decides the request), and that concurrent deliveries all arrive.
//
// The suite proves itself: notifytest_test.go runs it against deliberately
// broken notifiers and requires each to fail the case aimed at it.
package notifytest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

// TB is the subset of testing.TB the cases use.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
	Context() context.Context
}

// Delivery is what reached the far end for one request, as the harness
// reads it back.
type Delivery struct {
	ApprovalID string
	Agent      string
	Action     string
	Reference  string
	Rule       string
	Reason     string
	ExpiresAt  time.Time
	ApproveURL string
	DenyURL    string
}

// Harness is one fresh notifier under test.
type Harness struct {
	Notifier notify.Notifier
	// Delivered returns every request that has reached the far end so far.
	Delivered func(t TB) []Delivery
	// Fail, if set, makes delivery fail until restore is called.
	Fail func(t TB) (restore func())
	// Close, if set, is called when the case ends.
	Close func()
}

// Factory returns a fresh harness for each case.
type Factory func(t TB) Harness

// Case is one contract check.
type Case struct {
	Name string
	Run  func(t TB, h *Harness)
}

// Run runs every case as a subtest.
func Run(t *testing.T, f Factory) {
	t.Helper()
	for _, c := range Cases() {
		t.Run(c.Name, func(t *testing.T) { Check(t, f, c) })
	}
}

// Check prepares a harness and runs one case.
func Check(t TB, f Factory, c Case) {
	t.Helper()
	h := f(t)
	if h.Notifier == nil || h.Delivered == nil {
		t.Fatalf("notifytest: harness needs Notifier and Delivered")
	}
	if h.Close != nil {
		t.Cleanup(h.Close)
	}
	c.Run(t, &h)
}

// Cases returns the cases in order.
func Cases() []Case {
	return []Case{
		{"Name", name},
		{"Delivers", delivers},
		{"SuccessMeansDelivered", successMeansDelivered},
		{"FailureIsAnError", failureIsAnError},
		{"Concurrent", concurrent},
	}
}

func randHex(t TB, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// request builds a request whose every field is unique to this call.
func request(t TB) notify.Request {
	id := randHex(t, 8)
	return notify.Request{
		ApprovalID: "ap-" + id,
		Agent:      policy.Agent{ID: "uid:1000/agent-" + id},
		Summary: policy.Request{
			Action: policy.ActionInject, Ref: stores.Ref{Scheme: "bao", Path: "kv/app-" + id, Field: "token"},
			Host: "api.example.test", Method: "POST", Path: "/v1/items",
		},
		Rule:       "rule-" + id,
		Reason:     "reason " + id,
		ExpiresAt:  time.Now().Add(2 * time.Minute).Truncate(time.Second),
		ApproveURL: "https://scrim.example.test/decide/" + id + "/approve?t=tok-a-" + randHex(t, 12),
		DenyURL:    "https://scrim.example.test/decide/" + id + "/deny?t=tok-d-" + randHex(t, 12),
	}
}

func find(ds []Delivery, id string) (Delivery, bool) {
	i := slices.IndexFunc(ds, func(d Delivery) bool { return d.ApprovalID == id })
	if i < 0 {
		return Delivery{}, false
	}
	return ds[i], true
}

// waitFor polls Delivered until id arrives or a few seconds pass.
func waitFor(t TB, h *Harness, id string) (Delivery, bool) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if d, ok := find(h.Delivered(t), id); ok {
			return d, true
		}
		if time.Now().After(deadline) {
			return Delivery{}, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func name(t TB, h *Harness) {
	if strings.TrimSpace(h.Notifier.Name()) == "" {
		t.Errorf("notifier has no name; rules and errors refer to it by name")
	}
}

func delivers(t TB, h *Harness) {
	r := request(t)
	if err := h.Notifier.Notify(t.Context(), r); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	d, ok := waitFor(t, h, r.ApprovalID)
	if !ok {
		t.Fatalf("request %s was reported delivered but never arrived", r.ApprovalID)
	}
	check := func(what, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("delivered %s = %q, want %q", what, got, want)
		}
	}
	check("agent", d.Agent, r.Agent.ID)
	check("action", d.Action, string(r.Summary.Action))
	check("reference", d.Reference, r.Summary.Ref.String())
	check("rule", d.Rule, r.Rule)
	check("reason", d.Reason, r.Reason)
	check("approve link", d.ApproveURL, r.ApproveURL)
	check("deny link", d.DenyURL, r.DenyURL)
	if !d.ExpiresAt.Equal(r.ExpiresAt) {
		t.Errorf("delivered expiry %s, want %s", d.ExpiresAt, r.ExpiresAt)
	}
}

func successMeansDelivered(t TB, h *Harness) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := request(t)
	start := time.Now()
	err := h.Notifier.Notify(ctx, r)
	if time.Since(start) > 5*time.Second {
		t.Errorf("Notify with a cancelled context took %s", time.Since(start))
	}
	if err == nil {
		if _, ok := waitFor(t, h, r.ApprovalID); !ok {
			t.Errorf("Notify reported success for %s without delivering it", r.ApprovalID)
		}
	}
}

func failureIsAnError(t TB, h *Harness) {
	if h.Fail == nil {
		return
	}
	restore := h.Fail(t)
	r := request(t)
	err := h.Notifier.Notify(t.Context(), r)
	restore()
	if err == nil {
		t.Fatalf("Notify succeeded while delivery was failing; a notifier failure must be visible")
	}
	text := fmt.Sprintf("%v %+v %#v", err, err, err)
	for _, link := range []string{r.ApproveURL, r.DenyURL} {
		_, tok, _ := strings.Cut(link, "?t=")
		if strings.Contains(text, link) || strings.Contains(text, tok) {
			t.Errorf("delivery error carries a decision link: %v", err)
		}
	}
	if !strings.Contains(err.Error(), h.Notifier.Name()) {
		t.Errorf("delivery error %q does not name the notifier %s", err, h.Notifier.Name())
	}
	// Delivery works again once the channel is back.
	r2 := request(t)
	if err := h.Notifier.Notify(t.Context(), r2); err != nil {
		t.Fatalf("Notify after the failure ended: %v", err)
	}
	if _, ok := waitFor(t, h, r2.ApprovalID); !ok {
		t.Errorf("request after the failure ended never arrived")
	}
}

func concurrent(t TB, h *Harness) {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  []string
		errs []error
	)
	for range 8 {
		wg.Go(func() {
			r := request(t)
			err := h.Notifier.Notify(t.Context(), r)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids = append(ids, r.ApprovalID)
		})
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("concurrent Notify: %v", err)
	}
	for _, id := range ids {
		if _, ok := waitFor(t, h, id); !ok {
			t.Errorf("concurrent request %s never arrived", id)
		}
	}
}

// FromRequest is the Delivery a request should produce, for harnesses whose
// far end keeps notify.Request values.
func FromRequest(r notify.Request) Delivery {
	d := Delivery{
		ApprovalID: r.ApprovalID, Agent: r.Agent.ID, Action: string(r.Summary.Action),
		Rule: r.Rule, Reason: r.Reason, ExpiresAt: r.ExpiresAt, ApproveURL: r.ApproveURL, DenyURL: r.DenyURL,
	}
	if !r.Summary.Ref.IsZero() {
		d.Reference = r.Summary.Ref.String()
	}
	return d
}
