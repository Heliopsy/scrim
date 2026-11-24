// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// ActionDataPlane prefixes the audit action of every data plane event:
// "dataplane.redaction", "dataplane.guard_refusal", ...
const ActionDataPlane = "dataplane."

// ActionCapture is the audit action of a capture the control plane stored.
const ActionCapture = "capture.stored"

// eventSink records data plane events: metadata into the audit log in one
// transaction per batch, and counters into metrics. Events never carry a
// value (the boundary contract), so nothing here can leak one.
type eventSink struct {
	state state.Store
	inst  *obs.Instruments
	log   *slog.Logger
}

func eventAction(k pb.EventKind) string {
	name := strings.TrimPrefix(k.String(), "EVENT_KIND_")
	return ActionDataPlane + strings.ToLower(name)
}

func (s *eventSink) record(batch *pb.EventBatch) {
	if d := batch.GetDropped(); d > 0 && s.inst != nil {
		s.inst.AuditDropped("dataplane", int(min(d, 1<<31))) //nolint:gosec // bounded above
	}
	events := batch.GetEvents()
	if len(events) == 0 {
		return
	}
	entries := make([]audit.Entry, 0, len(events))
	for _, e := range events {
		s.metrics(e)
		entries = append(entries, auditEntry(e))
	}
	if s.state == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.state.Update(ctx, func(tx state.Tx) error {
		for i := range entries {
			if err := tx.AppendAudit(ctx, &entries[i]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("data plane events could not be audited", "count", len(entries), "err", err)
		if s.inst != nil {
			s.inst.AuditDropped("state", len(entries))
		}
		return
	}
	if s.inst != nil {
		s.inst.AuditDelivered("state", len(entries))
	}
}

func (s *eventSink) metrics(e *pb.Event) {
	if s.inst == nil {
		return
	}
	switch e.GetKind() {
	case pb.EventKind_EVENT_KIND_REDACTION:
		s.inst.Redaction(e.GetProvider(), e.GetRule(), e.GetAgentId(), int(max(e.GetCount(), 1)))
	case pb.EventKind_EVENT_KIND_GUARD_REPAIR:
		s.inst.GuardRepair(e.GetProvider(), e.GetRule(), e.GetAgentId())
	case pb.EventKind_EVENT_KIND_GUARD_REFUSAL:
		s.inst.GuardRefusal(e.GetProvider(), e.GetAgentId())
	case pb.EventKind_EVENT_KIND_DETECTOR_HIT:
		s.inst.FallbackHit(e.GetProvider(), e.GetRule(), e.GetAgentId())
	default:
	}
}

func auditEntry(e *pb.Event) audit.Entry {
	out := audit.Entry{
		Time:      time.Unix(0, e.GetTimeUnixNano()).UTC(),
		Action:    eventAction(e.GetKind()),
		Actor:     "dataplane",
		Agent:     policy.Agent{ID: e.GetAgentId()},
		Rule:      e.GetRule(),
		Target:    e.GetTarget(),
		RequestID: e.GetRequestId(),
		Reason:    e.GetReason(),
		Attrs:     maps.Clone(e.GetAttrs()),
	}
	if e.GetTimeUnixNano() == 0 {
		out.Time = time.Now().UTC()
	}
	if out.Attrs == nil {
		out.Attrs = map[string]string{}
	}
	out.Attrs["seq"] = strconv.FormatUint(e.GetSeq(), 10)
	out.Attrs["snapshot"] = strconv.FormatUint(e.GetSnapshotVersion(), 10)
	if p := e.GetProvider(); p != "" {
		out.Attrs["provider"] = p
	}
	if c := e.GetCount(); c > 0 {
		out.Attrs["count"] = strconv.FormatUint(uint64(c), 10)
	}
	if r, err := stores.ParseRef(e.GetRef()); err == nil {
		out.Ref = r
	} else if e.GetRef() != "" {
		out.Attrs["ref"] = e.GetRef()
	}
	if e.GetEffect() != pb.Effect_EFFECT_UNSPECIFIED {
		out.Effect = policy.EffectFromPB(e.GetEffect())
	}
	switch e.GetKind() {
	case pb.EventKind_EVENT_KIND_GUARD_REFUSAL, pb.EventKind_EVENT_KIND_ERROR, pb.EventKind_EVENT_KIND_INTERCEPTION_REFUSED,
		pb.EventKind_EVENT_KIND_CLIENT_CERTIFICATE_REFUSED:
		out.Outcome = audit.OutcomeRefused
	default:
		out.Outcome = audit.OutcomeOK
	}
	return out
}

// captureWriter stores a value a tool-proxy capture rule took from a
// response: through the gate (break-glass and store.write rules apply), into
// the store through its refresher, so the value is in the redaction set
// before the write is reported, and returns the placeholder of the stored
// value.
type captureWriter struct {
	gate        *gate.Gate
	refreshers  func(stores.Ref) (*refresh.Refresher, error)
	placeholder func(stores.Ref, secret.Value) (string, error)
	state       state.Store
	log         *slog.Logger
}

// valueField is the field a reference without #field is written to, as the
// agent tools do.
const valueField = "value"

func (c *captureWriter) capture(ctx context.Context, req *pb.CaptureRequest) (string, error) {
	ref, err := stores.ParseRef(req.GetRef())
	if err != nil {
		return "", errors.New("capture rule names an invalid store reference")
	}
	field := ref.Field
	if field == "" {
		field = valueField
	}
	host := req.GetDestination()
	if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	preq := policy.Request{Agent: policy.Agent{ID: "dataplane", Kind: policy.IdentityUnknown}, Action: policy.ActionWrite,
		Ref: ref, Store: ref.Scheme, Host: host, Tool: "capture:" + req.GetRule(), Time: time.Now()}
	if c.gate != nil {
		v := c.gate.Check(ctx, preq, gate.Options{RequestID: "capture-" + strconv.FormatUint(req.GetId(), 10)})
		if !v.Allowed() {
			return "", fmt.Errorf("capture into %s refused by policy (%s)", ref, v.Rule)
		}
	}
	r, err := c.refreshers(ref)
	if err != nil {
		return "", err
	}
	// The data plane wipes req.Value when this returns; the store and the
	// redaction set keep their own copies.
	val := secret.New(req.GetValue())
	defer val.Wipe()
	if val.Len() == 0 {
		return "", errors.New("captured field is empty")
	}
	if _, err := r.Write(ctx, ref.Secret(), map[string]secret.Value{field: val}, stores.WriteOptions{}); err != nil {
		return "", fmt.Errorf("capture into %s: %w", ref, err)
	}
	out := ref.Secret().WithField(field)
	ph, err := c.placeholder(out, val)
	if err != nil {
		return "", fmt.Errorf("capture into %s: %w", ref, err)
	}
	if c.state != nil {
		e := audit.Entry{Time: time.Now().UTC(), Action: ActionCapture, Actor: "dataplane", Ref: out, Target: host,
			Outcome: audit.OutcomeOK, Attrs: map[string]string{"rule": req.GetRule()}}
		if err := state.Apply(ctx, c.state, func(state.Tx) (state.Change, error) { return state.Change{Audit: e}, nil }); err != nil {
			c.log.Error("capture stored but not audited", "ref", out.String(), "err", err)
		}
	}
	return ph, nil
}
