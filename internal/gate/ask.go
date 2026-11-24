// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// How an ask's caller was identified, in the decision's audit attribute
// "caller".
const (
	CallerNone     = "none"        // the transport carried nothing: unknown
	CallerSession  = "session"     // a verified session
	CallerKube     = "kubernetes"  // a verified Kubernetes service account token
	CallerCert     = "certificate" // a verified client certificate
	CallerPeer     = "peer"        // a Unix peer mapped by identity.peers
	CallerUnmapped = "unmapped"    // a Unix peer no session or mapping covers
	CallerRefused  = "refused"     // a named session that could not be verified
	CallerError    = "error"       // resolving the caller failed
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
	// The service account token is a secret field: it is used to verify the
	// caller and, for passthrough, to log in to a store as that caller, and
	// wiped when the ask is answered.
	kubeToken := a.GetCaller().GetKubernetesToken()
	defer secret.WipeBytes(kubeToken)
	who, attrs := g.caller(ctx, a)
	req.Agent = who.PolicyAgent()
	if g.Labels != nil {
		// Like the caller, the secret's labels are the control plane's own
		// view, not what the request says.
		req.SecretLabels = nil
	}
	o := Options{Wait: true, RequestID: "dp-" + strconv.FormatUint(a.GetId(), 10), Attrs: attrs}
	if g.StoreAccess != nil && usesValue(req.Action) && req.Ref.Scheme != "" {
		o.Confirm = func(ctx context.Context) error {
			src, err := g.StoreAccess.Check(ctx, who, kubeToken, stores.OpRead, req.Ref)
			attrs["store_identity"] = src
			return err
		}
	}
	v := g.Check(ctx, req, o)
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
func (g *Gate) caller(ctx context.Context, a *pb.AskRequest) (identity.Identity, map[string]string) {
	c := a.GetCaller()
	if c == nil {
		return identity.Unknown(identity.Peer{}), map[string]string{"caller": CallerNone}
	}
	claim := identity.TransportClaim{
		SessionID: c.GetSessionId(), Proof: c.GetSessionProof(), AskID: a.GetId(), Deadline: a.GetDeadlineUnixNano(),
		UnixPeer: c.GetUnixPeer(), Peer: identity.Peer{UID: c.GetPeerUid(), GID: c.GetPeerGid(), PID: c.GetPeerPid()},
		KubernetesToken: c.GetKubernetesToken(), ClientCertificateChain: c.GetClientCertificateChain(),
	}
	attrs := map[string]string{}
	if chain := claim.ClientCertificateChain; len(chain) > 0 {
		// Public: lets an operator find the certificate a refusal was about.
		sum := sha256.Sum256(chain[0])
		attrs["cert_sha256"] = hex.EncodeToString(sum[:])
	}
	if claim.SessionID != "" {
		attrs["session"] = claim.SessionID
	}
	if claim.UnixPeer {
		attrs["peer_uid"] = strconv.FormatUint(uint64(claim.Peer.UID), 10)
	}
	if g.Callers == nil {
		attrs["caller"] = CallerError
		attrs["caller_reason"] = "no identity resolver"
		return identity.Unknown(claim.Peer), attrs
	}
	id, err := g.Callers.ResolveClaim(ctx, claim)
	if err != nil {
		if re, ok := identity.IsRefused(err); ok {
			attrs["caller"], attrs["caller_reason"] = CallerRefused, string(re.Reason)
		} else {
			attrs["caller"], attrs["caller_reason"] = CallerError, "identity could not be resolved"
			g.logErr("resolving an ask's caller failed; evaluating it as unknown", err)
		}
		if len(claim.KubernetesToken) > 0 && claim.SessionID == "" {
			attrs["caller_token"] = CallerKube
		}
		if len(claim.ClientCertificateChain) > 0 {
			attrs["caller_token"] = CallerCert
		}
		return identity.Unknown(claim.Peer), attrs
	}
	switch {
	case !id.Known():
		attrs["caller"] = CallerUnmapped
	case id.Source == identity.SourceSession:
		attrs["caller"] = CallerSession
	case id.Source == identity.SourceKubernetes:
		attrs["caller"] = CallerKube
		attrs["namespace"] = id.Labels[identity.LabelNamespace]
		attrs["service_account"] = id.Labels[identity.LabelServiceAccount]
		if p := id.Labels[identity.LabelPod]; p != "" {
			attrs["pod"] = p
		}
	case id.Source == identity.SourceCertificate:
		attrs["caller"] = CallerCert
		for _, k := range []string{identity.LabelSPIFFEID, identity.LabelCertCN} {
			if v := id.Labels[k]; v != "" {
				attrs[k] = v
			}
		}
	default:
		attrs["caller"] = CallerPeer
	}
	return id, attrs
}

// usesValue reports whether an action puts a secret's value to use, so the
// agent's own store identity must allow reading it.
func usesValue(a policy.Action) bool {
	return a == policy.ActionInject || a == policy.ActionRestore
}

// StoreAccess checks an agent's own store identity ([agentstore.Checker]).
type StoreAccess interface {
	Check(ctx context.Context, who identity.Identity, kubeToken []byte, op stores.Op, ref stores.Ref) (string, error)
}
