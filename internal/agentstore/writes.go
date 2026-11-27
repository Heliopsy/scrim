// SPDX-License-Identifier: AGPL-3.0-only

package agentstore

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/stores"
)

// Write check settings (specs/agent-identity "Agent writes are checked as
// the agent"). Both are read at start-up.
var (
	// SkipWriteChecks turns the write check off for every store.
	SkipWriteChecks = config.Register(config.Spec[bool]{
		Key: "identity.skip-agent-write-checks",
		Description: "Write agents' secrets (secret_gen, secret_capture, secret_ask_human, `scrim secret put`) with scrim's own store identity once scrim's rules allow them, " +
			"without asking the agent's own store identity first, also on stores that can answer (openbao, vault, gcpsm, bws, vaultwarden). " +
			"Off by default: a store with per-agent identity that can check a write refuses one the agent's identity may not make, and refuses agents without an identity of their own.",
		Weakening:       true,
		RestartRequired: true,
	})
	// RefuseUncheckedWrites lists stores that cannot check a write and
	// refuse agents' writes instead.
	RefuseUncheckedWrites = config.Register(config.Spec[[]string]{
		Key: "identity.refuse-unchecked-writes",
		Description: "Stores with per-agent identity that cannot tell whether an agent's identity may write without writing (awssm, ssm, azkv, infisical, doppler, onepassword), " +
			"by instance name, that refuse agents' writes instead of making them with scrim's own identity once scrim's rules allow them. `*` names every such store. Empty by default.",
		RestartRequired: true,
	})
)

// How an agent's write was checked, in the audit attribute
// "store_write_check".
const (
	// WriteChecked: the agent's own store identity was asked and may write.
	WriteChecked = "checked"
	// WriteUnchecked: the store cannot tell without writing, so the write
	// uses scrim's own identity once scrim's rules allowed it.
	WriteUnchecked = "unchecked"
	// WriteSkipped: identity.skip-agent-write-checks is on.
	WriteSkipped = "skipped"
	// WriteShared: the store has no per-agent identity.
	WriteShared = "shared"
)

// ErrUncheckedWrite is a write refused because its store cannot check the
// agent's identity and identity.refuse-unchecked-writes names it.
var ErrUncheckedWrite = errors.New("the store cannot check whether the agent's own identity may write, and identity.refuse-unchecked-writes refuses agents' writes to it")

// WriteResult says which store identity a write was checked with and how.
type WriteResult struct {
	Source string
	Check  string
}

// CanCheckWrites reports whether store can check an agent's write: its
// kind declared [stores.DeclareAgentWriteCheck].
func (c *Checker) CanCheckWrites(store string) bool {
	if c == nil {
		return false
	}
	return stores.ChecksAgentWrites(c.kinds[store])
}

// RefusesUncheckedWrites reports whether identity.refuse-unchecked-writes
// names store (or is `*`).
func (c *Checker) RefusesUncheckedWrites(store string) bool {
	return c != nil && (slices.Contains(c.refuseUnchecked, store) || slices.Contains(c.refuseUnchecked, "*"))
}

// SkipsWriteChecks reports whether identity.skip-agent-write-checks is on.
func (c *Checker) SkipsWriteChecks() bool { return c != nil && c.skipWrites }

// CheckWrite decides an agent's write to ref after scrim's rules allowed
// it. A store without per-agent identity passes (scrim's own identity, as
// before). For a store with per-agent identity:
//
//   - one that can check a write asks the agent's own store identity
//     (AgentCan with OpWrite) and refuses an agent without one, unless
//     identity.skip-agent-write-checks is on;
//   - one that cannot passes, with scrim's own identity, unless
//     identity.refuse-unchecked-writes names it.
//
// Refusals wrap [stores.ErrPermission], [ErrNoIdentity] or
// [ErrUncheckedWrite]; any other error is the check failing. kubeToken is
// the caller's service account token for passthrough, owned by the caller.
func (c *Checker) CheckWrite(ctx context.Context, id identity.Identity, kubeToken []byte, ref stores.Ref) (WriteResult, error) {
	if c == nil || ref.Scheme == "" {
		return WriteResult{Source: SourceShared, Check: WriteShared}, nil
	}
	a, err := c.lookup(ref)
	if err != nil {
		return WriteResult{Source: SourceNone}, err
	}
	store := a.Name()
	src := c.source(store, id, kubeToken)
	switch {
	case src == SourceShared:
		return WriteResult{Source: src, Check: WriteShared}, nil
	case !c.CanCheckWrites(store):
		if c.RefusesUncheckedWrites(store) {
			return WriteResult{Source: src, Check: WriteUnchecked}, fmt.Errorf("store %s: %w", store, ErrUncheckedWrite)
		}
		return WriteResult{Source: src, Check: WriteUnchecked}, nil
	case c.SkipsWriteChecks():
		return WriteResult{Source: src, Check: WriteSkipped}, nil
	case src == SourceNone:
		return WriteResult{Source: src, Check: WriteChecked}, fmt.Errorf("store %s: agent %s: %w", store, id.Principal(), ErrNoIdentity)
	}
	return WriteResult{Source: src, Check: WriteChecked}, c.can(ctx, a, src, id, kubeToken, stores.OpWrite, ref)
}

// WritePolicy describes, for doctor, how agents' writes to store are
// decided.
func (c *Checker) WritePolicy(store string) string {
	switch {
	case !slices.Contains(c.Governed(), store):
		return "agents' writes use scrim's own identity (no per-agent identity)"
	case !c.CanCheckWrites(store) && c.RefusesUncheckedWrites(store):
		return "agents' writes are refused: the store cannot check the agent's identity (identity.refuse-unchecked-writes)"
	case !c.CanCheckWrites(store):
		return "agents' writes are not checked against the agent's identity (the store cannot tell without writing); they use scrim's own identity once scrim's rules allow them"
	case c.SkipsWriteChecks():
		return "agents' writes are not checked against the agent's identity (identity.skip-agent-write-checks)"
	default:
		return "agents' writes are checked with the agent's own identity"
	}
}
