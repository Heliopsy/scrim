// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"strconv"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/policy"
)

// Answer handles one ask from the data plane: the data plane sends a request
// here when a rule asks, when a residual rule could decide, or when an allow
// rule has side effects. The control plane re-evaluates the full rule set,
// so the data plane's reason for asking never widens anything. The answer is
// allow or deny; there is no "ask" answer. An expired deadline or any error
// denies.
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
	v := g.Check(ctx, req, Options{Wait: true, RequestID: "dp-" + strconv.FormatUint(a.GetId(), 10)})
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
