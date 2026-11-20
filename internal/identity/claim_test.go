// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
)

// TestSessionProofVector pins the proof both halves compute (the data
// plane's asks::tests::session_proof_matches_the_control_plane uses the same
// vector).
func TestSessionProofVector(t *testing.T) {
	h := hashSecret([]byte(strings.Repeat("A", 43)))
	if got := hex.EncodeToString(h); got != "7cabb63bcae2fbcaef12849c770d685680ecb7a8f7286a7a8791e91cba662b8a" {
		t.Fatalf("verifier %s", got)
	}
	p := SessionProof(h, "abcdefghijklmn23", 7, 1_700_000_000_000_000_000)
	if got := hex.EncodeToString(p); got != "2f9e6c617d495d092f9b5bd93420f5735cb4d84a70ca3c068d3dfe822bbad3a7" {
		t.Fatalf("proof %s", got)
	}
}

// proofFor is what the data plane sends for a request carrying tok.
func proofFor(t *testing.T, tok []byte, askID uint64, deadline int64) (string, []byte) {
	t.Helper()
	id, h, ok := parseToken(tok)
	if !ok {
		t.Fatal("not a token")
	}
	return id, SessionProof(h, id, askID, deadline)
}

func TestResolveClaim(t *testing.T) {
	peers, err := NewPeerMap([]PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, accounts{})
	if err != nil {
		t.Fatal(err)
	}
	mgr, clk := newManager(t, machine())
	r := Resolver{Peers: peers, Sessions: mgr}
	ctx := context.Background()
	minter, _ := peers.Lookup(Peer{UID: 1000, PID: 200})
	a, err := mgr.Mint(ctx, minter, MintRequest{Name: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	tok := expose(t, a.Token)
	deadline := clk.t.Add(time.Minute).UnixNano()
	sid, proof := proofFor(t, tok, 7, deadline)

	ok := func(c TransportClaim, source Source, agent string) Identity {
		t.Helper()
		id, err := r.ResolveClaim(ctx, c)
		if err != nil || id.Source != source || id.Agent != agent {
			t.Fatalf("%+v: %+v %v", c, id, err)
		}
		return id
	}
	refused := func(c TransportClaim, why RefusalReason) {
		t.Helper()
		id, err := r.ResolveClaim(ctx, c)
		if refusal(t, err) != why || id.Known() {
			t.Fatalf("%+v: %+v %v, want %s", c, id, err, why)
		}
	}

	// A TCP session with its proof: the session, whatever the peer map says.
	id := ok(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline}, SourceSession, "dev")
	if id.SessionID != sid || id.Principal() != "dev/"+sid || id.PolicyAgent().Kind != policy.IdentitySession {
		t.Fatalf("session identity %+v", id)
	}
	// The same over a Unix socket from inside the tree; outside it is refused.
	ok(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline, UnixPeer: true, Peer: Peer{UID: 1000, PID: 202}}, SourceSession, "dev")
	refused(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline, UnixPeer: true, Peer: Peer{UID: 1000, PID: 301}}, RefusedWrongTree)
	refused(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline, UnixPeer: true, Peer: Peer{UID: 1001, PID: 202}}, RefusedWrongUser)
	// A bare session id proves nothing; a proof for another ask, another
	// deadline or a forged one is refused like an unknown token, and none of
	// them falls back to the peer mapping.
	refused(TransportClaim{SessionID: sid, UnixPeer: true, Peer: Peer{UID: 1000, PID: 202}}, RefusedNoProof)
	refused(TransportClaim{SessionID: sid, Proof: proof, AskID: 8, Deadline: deadline}, RefusedUnknown)
	refused(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline + 1}, RefusedUnknown)
	refused(TransportClaim{SessionID: sid, Proof: make([]byte, 32), AskID: 7, Deadline: deadline}, RefusedUnknown)
	refused(TransportClaim{SessionID: "nosuchsession000", Proof: proof, AskID: 7, Deadline: deadline}, RefusedUnknown)

	// A Unix peer without a session: the session whose tree it is in, else
	// its mapping, else unknown.
	ok(TransportClaim{UnixPeer: true, Peer: Peer{UID: 1000, PID: 202}}, SourceSession, "dev")
	ok(TransportClaim{UnixPeer: true, Peer: Peer{UID: 1000, PID: 301}}, SourcePeer, "dev")
	if id, err := r.ResolveClaim(ctx, TransportClaim{UnixPeer: true, Peer: Peer{UID: 4242, PID: 301}}); err != nil || id.Known() {
		t.Fatalf("unmapped: %+v %v", id, err)
	}
	// Nothing at all is unknown.
	if id, err := r.ResolveClaim(ctx, TransportClaim{}); err != nil || id.Known() || id.PolicyAgent().Kind != policy.IdentityUnknown {
		t.Fatalf("anonymous: %+v %v", id, err)
	}

	// Revoked and expired sessions are refused even with a valid proof.
	if err := mgr.Revoke(ctx, sid, RevokeOperator); err != nil {
		t.Fatal(err)
	}
	refused(TransportClaim{SessionID: sid, Proof: proof, AskID: 7, Deadline: deadline}, RefusedRevoked)
	// The revoked session no longer covers its tree: back to the mapping.
	ok(TransportClaim{UnixPeer: true, Peer: Peer{UID: 1000, PID: 202}}, SourcePeer, "dev")
	b, err := mgr.Mint(ctx, minter, MintRequest{TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	bid, bproof := proofFor(t, expose(t, b.Token), 1, deadline)
	refused(TransportClaim{SessionID: bid, Proof: bproof, AskID: 1, Deadline: deadline}, RefusedExpired)
}
