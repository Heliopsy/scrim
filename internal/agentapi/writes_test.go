// SPDX-License-Identifier: AGPL-3.0-only

package agentapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/agentstore"
	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// fakeWrites is the per-agent store identity checker: it refuses writes
// under refuse, fails under fail, and records the token it was given.
type fakeWrites struct {
	refuse, fail string
	tokens       []string
	refs         []stores.Ref
}

func (f *fakeWrites) Check(context.Context, identity.Identity, []byte, stores.Op, stores.Ref) (string, error) {
	return agentstore.SourceShared, nil
}

func (f *fakeWrites) CheckWrite(_ context.Context, _ identity.Identity, tok []byte, r stores.Ref) (agentstore.WriteResult, error) {
	f.tokens = append(f.tokens, string(tok))
	f.refs = append(f.refs, r)
	res := agentstore.WriteResult{Source: agentstore.SourceStatic, Check: agentstore.WriteChecked}
	switch {
	case f.refuse != "" && strings.HasPrefix(r.String(), f.refuse):
		return res, stores.NewError("bao", stores.OpWrite, r, stores.ErrPermission, errors.New("the agent's own identity may not write this path"))
	case f.fail != "" && strings.HasPrefix(r.String(), f.fail):
		return res, stores.NewError("bao", stores.OpWrite, r, stores.ErrUnavailable, nil)
	}
	return res, nil
}

func TestWritesAdapter(t *testing.T) {
	f := &fakeWrites{refuse: "bao://kv/agents/ro/", fail: "bao://kv/agents/down/"}
	w := Writes{Checker: f}
	id := identity.Identity{Agent: "agents/a", Source: identity.SourceKubernetes}
	kctx := identity.WithKubernetesToken(ctx, []byte("eyJ.pod.token"))

	got, err := w.CheckWrite(kctx, id, agenttools.Operation{Tool: agenttools.ToolSecretGen, Ref: "bao://kv/agents/rw#password"})
	if err != nil || got != (agenttools.WriteCheck{Identity: agentstore.SourceStatic, Check: agentstore.WriteChecked}) {
		t.Fatalf("allowed: %+v %v", got, err)
	}
	if f.tokens[0] != "eyJ.pod.token" || f.refs[0].String() != "bao://kv/agents/rw" {
		t.Fatalf("checked %q with token %q", f.refs[0], f.tokens[0])
	}
	// A bare name with a store resolves like the write does.
	if _, err := w.CheckWrite(ctx, id, agenttools.Operation{Ref: "kv/agents/rw", Store: "bao"}); err != nil || f.refs[1].String() != "bao://kv/agents/rw" || f.tokens[1] != "" {
		t.Fatalf("bare name: %v %q %q", err, f.refs[1], f.tokens[1])
	}
	var refused *agenttools.WriteRefusedError
	_, err = w.CheckWrite(ctx, id, agenttools.Operation{Ref: "bao://kv/agents/ro/x"})
	if !errors.As(err, &refused) || !strings.Contains(refused.Reason, "bao://kv/agents/ro/x") {
		t.Fatalf("refused: %v", err)
	}
	if _, err := w.CheckWrite(ctx, id, agenttools.Operation{Ref: "bao://kv/agents/down/x"}); err == nil || errors.As(err, &refused) {
		t.Fatalf("a failed check is not a refusal: %v", err)
	}
	if _, err := w.CheckWrite(ctx, id, agenttools.Operation{Ref: "::"}); !errors.As(err, &refused) {
		t.Fatalf("invalid reference: %v", err)
	}
}

// Through the local API: the gate's per-agent store identity checker is
// asked before every agent write, and its refusal stores nothing.
func TestRuntimeWritesAskStoreIdentity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	dir, err := os.MkdirTemp("", "scrim")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "api.sock")
	home := t.TempDir()
	opts := config.Options{Registry: config.Default, SystemDir: home, Environ: []string{"HOME=" + home,
		"XDG_CONFIG_HOME=" + home, "XDG_STATE_HOME=" + home, "SCRIM_API_SOCKET=" + sock}}
	var logs bytes.Buffer
	a, err := app.New(ctx, opts, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	set, mem := storeSet(t)
	a.Stores = set
	a.Policy = rules(policy.Rule{Name: "agents", Match: under("bao://kv/agents/"), Effect: policy.Allow})
	f := &fakeWrites{refuse: "bao://kv/agents/ro/"}
	a.PolicyParts.Gate.StoreAccess = f

	rt, err := New(a, Options{Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- rt.Serve(sctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	c := localapi.NewClient(sock, secret.Value{})
	defer c.Close()

	_, err = c.Generate(ctx, agenttools.GenInput{Ref: "bao://kv/agents/ro/db#password"})
	if agenttools.CodeOf(err) != agenttools.CodeDenied || !strings.Contains(err.Error(), "agent's store identity") {
		t.Fatalf("gen refused by the store identity: %v", err)
	}
	if _, err := mem.Read(ctx, stores.MustParseRef("bao://kv/agents/ro/db")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("refused write was stored: %v", err)
	}
	if _, err := c.Put(ctx, agenttools.PutInput{Ref: "bao://kv/agents/ro/key"}, secret.FromString("v-test-7e6d5c4b")); agenttools.CodeOf(err) != agenttools.CodeDenied {
		t.Fatalf("put refused by the store identity: %v", err)
	}
	if _, err := c.Generate(ctx, agenttools.GenInput{Ref: "bao://kv/agents/rw#password"}); err != nil {
		t.Fatal(err)
	}
	if len(f.refs) != 3 {
		t.Fatalf("store identity asked for %v", f.refs)
	}
	err = a.State.View(ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(ctx, state.AuditQuery{})
		if err != nil {
			return err
		}
		n := 0
		for _, e := range es {
			if e.Attrs["store_write_check"] == agentstore.WriteChecked && e.Attrs["store_identity"] == agentstore.SourceStatic {
				n++
			}
		}
		if n != 3 {
			t.Errorf("%d audit entries say how the write was checked, want 3", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
