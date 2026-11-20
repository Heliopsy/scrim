// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"strconv"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
)

// How an ask's caller was identified, in the decision's audit attribute
// "caller".
const (
	CallerNone     = "none"     // the transport carried nothing: unknown
	CallerSession  = "session"  // a verified session
	CallerPeer     = "peer"     // a Unix peer mapped by identity.peers
	CallerUnmapped = "unmapped" // a Unix peer no session or mapping covers
	CallerRefused  = "refused"  // a named session that could not be verified
	CallerError    = "error"    // resolving the caller failed
)

// Answer handles one ask from the data plane: the data plane sends a request
// here when a rule asks, when a residual rule could decide, or when an allow
// rule has side effects. The control plane resolves the caller from what the
// transport said (`AskRequest.caller`), re-evaluates the full rule set with
// that identity, so the data plane's reason for asking never widens
// anything. The answer is allow or deny; there is no "ask" answer. An
// expired deadline or any error denies.
func (g *Gate) Answer(ctx context.Context, a *pb.AskRequest) *pb.AskAnswer {
	ans := &pb.AskAnswer{Protocol: uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT), Id: a.GetId(), Effect: pb.Effect_EFFECT_DENY}
	if a.GetProtocol() != uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT) {
		ans.Reason = "protocol version mismatch"
		return ans
	}
	if d := a.GetDeadlineUnixNano(); d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(0, d))
		defer cancel()
	}
	req, err := policy.RequestFromProto(a.GetRequest())
	if err != nil {
		ans.Reason = "invalid request"
		return ans
	}
	agent, attrs := g.caller(ctx, a)
	req.Agent = agent
	v := g.Check(ctx, req, Options{Wait: true, RequestID: "dp-" + strconv.FormatUint(a.GetId(), 10), Attrs: attrs})
	ans.Reason = v.Reason
	if v.Allowed() {
		ans.Effect = pb.Effect_EFFECT_ALLOW
		ans.GrantId = v.GrantID
		if !v.GrantExpires.IsZero() {
			ans.GrantExpiresUnixNano = v.GrantExpires.UnixNano()
		}
	}
	return ans
}

// caller resolves who sent an ask's request. The data plane maps no
// identities, so whatever agent fields the request carries are ignored: the
// caller is what the transport said, verified here, or unknown. A caller
// that names a session it cannot prove is unknown (deny-leaning), never its
// peer mapping, and the refusal is recorded in the decision's audit entry.
func (g *Gate) caller(ctx context.Context, a *pb.AskRequest) (policy.Agent, map[string]string) {
	c := a.GetCaller()
	if c == nil {
		return identity.Unknown(identity.Peer{}).PolicyAgent(), map[string]string{"caller": CallerNone}
	}
	claim := identity.TransportClaim{
		SessionID: c.GetSessionId(), Proof: c.GetSessionProof(), AskID: a.GetId(), Deadline: a.GetDeadlineUnixNano(),
		UnixPeer: c.GetUnixPeer(), Peer: identity.Peer{UID: c.GetPeerUid(), GID: c.GetPeerGid(), PID: c.GetPeerPid()},
	}
	attrs := map[string]string{}
	if claim.SessionID != "" {
		attrs["session"] = claim.SessionID
	}
	if claim.UnixPeer {
		attrs["peer_uid"] = strconv.FormatUint(uint64(claim.Peer.UID), 10)
	}
	if g.Callers == nil {
		attrs["caller"] = CallerError
		attrs["caller_reason"] = "no identity resolver"
		return identity.Unknown(claim.Peer).PolicyAgent(), attrs
	}
	id, err := g.Callers.ResolveClaim(ctx, claim)
	if err != nil {
		if re, ok := identity.IsRefused(err); ok {
			attrs["caller"], attrs["caller_reason"] = CallerRefused, string(re.Reason)
		} else {
			attrs["caller"], attrs["caller_reason"] = CallerError, "identity could not be resolved"
			g.logErr("resolving an ask's caller failed; evaluating it as unknown", err)
		}
		return identity.Unknown(claim.Peer).PolicyAgent(), attrs
	}
	switch {
	case !id.Known():
		attrs["caller"] = CallerUnmapped
	case id.Source == identity.SourceSession:
		attrs["caller"] = CallerSession
	default:
		attrs["caller"] = CallerPeer
	}
	return id.PolicyAgent(), attrs
}
