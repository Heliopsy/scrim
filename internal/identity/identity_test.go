// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// tree is a fake process table.
type tree struct {
	mu sync.Mutex
	m  map[int32]Proc
}

func newTree(procs ...Proc) *tree {
	t := &tree{m: map[int32]Proc{}}
	for _, p := range procs {
		t.m[p.PID] = p
	}
	return t
}

func (t *tree) Lookup(pid int32) (Proc, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[pid]
	if !ok {
		return Proc{}, errNoProcess
	}
	return p, nil
}

func (t *tree) set(p Proc) { t.mu.Lock(); t.m[p.PID] = p; t.mu.Unlock() }
func (t *tree) kill(pid int32) {
	t.mu.Lock()
	delete(t.m, pid)
	t.mu.Unlock()
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// The fake machine: init(1) -> shell(100) -> scrim run A (200) -> agent A (201)
// -> scrim mcp (202); shell(100) -> scrim run B (300) -> agent B (301).
func machine() *tree {
	return newTree(
		Proc{PID: 1, PPID: 0, Start: 1},
		Proc{PID: 100, PPID: 1, Start: 10},
		Proc{PID: 200, PPID: 100, Start: 20},
		Proc{PID: 201, PPID: 200, Start: 21},
		Proc{PID: 202, PPID: 201, Start: 22},
		Proc{PID: 300, PPID: 100, Start: 30},
		Proc{PID: 301, PPID: 300, Start: 31},
	)
}

func peerID(agent string, uid uint32, pid int32) Identity {
	return Identity{Agent: agent, Source: SourcePeer, Peer: Peer{UID: uid, GID: uid, PID: pid},
		Scopes: slices.Clone(AllScopes)}
}

func newManager(t *testing.T, procs ProcInfo) (*Manager, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	return NewManager(NewMemorySessions(), ManagerOptions{Procs: procs, Now: c.now}), c
}

func expose(t *testing.T, v secret.Value) []byte {
	t.Helper()
	var out []byte
	if err := v.Expose(func(b []byte) error { out = bytes.Clone(b); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func refusal(t *testing.T, err error) RefusalReason {
	t.Helper()
	re, ok := IsRefused(err)
	if !ok {
		t.Fatalf("want a refused credential, got %v", err)
	}
	return re.Reason
}

func TestPeerOfReportsThisProcess(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan Peer, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer func() { _ = c.Close() }()
		p, err := PeerOf(c)
		if err != nil {
			errc <- err
			return
		}
		got <- p
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	select {
	case err := <-errc:
		t.Fatal(err)
	case p := <-got:
		if p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) { // #nosec G115
			t.Errorf("peer = %+v, want uid %d gid %d", p, os.Getuid(), os.Getgid())
		}
		if p.PID != int32(os.Getpid()) { // #nosec G115
			t.Errorf("peer pid = %d, want %d", p.PID, os.Getpid())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no connection")
	}
}

func TestPeerOfRefusesNonUnixConnections(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, err := PeerOf(a); !errors.Is(err, ErrNoPeerCredentials) {
		t.Fatalf("err = %v, want ErrNoPeerCredentials", err)
	}
}

func TestOSProcsFollowsARealChild(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("process information is implemented on Linux and macOS")
	}
	self, err := OSProcs{}.Lookup(int32(os.Getpid())) // #nosec G115
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start sleep:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	child := int32(cmd.Process.Pid) // #nosec G115
	in, err := descends(OSProcs{}, child, self)
	if err != nil || !in {
		t.Fatalf("child descends from this process = %v, %v; want true", in, err)
	}
	in, err = descends(OSProcs{}, int32(os.Getppid()), self) // #nosec G115
	if err != nil || in {
		t.Fatalf("parent descends from this process = %v, %v; want false", in, err)
	}
	if _, err := (OSProcs{}).Lookup(1 << 30); !errors.Is(err, errNoProcess) {
		t.Fatalf("missing pid: err = %v, want errNoProcess", err)
	}
}

func TestDescends(t *testing.T) {
	m := machine()
	root := Proc{PID: 200, Start: 20}
	for _, tc := range []struct {
		pid  int32
		want bool
	}{{200, true}, {201, true}, {202, true}, {300, false}, {301, false}, {100, false}, {1, false}, {999, false}, {0, false}} {
		got, err := descends(m, tc.pid, root)
		if err != nil || got != tc.want {
			t.Errorf("descends(%d) = %v, %v; want %v", tc.pid, got, err, tc.want)
		}
	}
	// PID 200 exits and an unrelated process reuses it.
	m.set(Proc{PID: 200, PPID: 100, Start: 99})
	if got, _ := descends(m, 201, root); got {
		t.Error("a reused root PID still counts as the root")
	}
}

type accounts map[string]uint32

func (a accounts) UserID(n string) (uint32, error) {
	if id, ok := a["u:"+n]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("no user %s", n)
}

func (a accounts) GroupID(n string) (uint32, error) {
	if id, ok := a["g:"+n]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("no group %s", n)
}

func TestPeerMap(t *testing.T) {
	acc := accounts{"u:agent1": 2001, "g:agents": 3000}
	m, err := NewPeerMap([]PeerRule{
		{Agent: "builder", Users: []string{"agent1"}, Labels: map[string]string{"team": "infra"}},
		{Agent: "pool", Groups: []string{"agents"}, Scopes: []Scope{ScopeSecretsList}},
		{Agent: "me", UIDs: []uint32{1000}},
	}, acc)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		peer  Peer
		agent string
		ok    bool
	}{
		{Peer{UID: 2001, GID: 3000}, "builder", true}, // user match wins over group
		{Peer{UID: 2002, GID: 3000}, "pool", true},
		{Peer{UID: 1000, GID: 1000}, "me", true},
		{Peer{UID: 4000, GID: 4000}, "", false},
	} {
		id, ok := m.Lookup(tc.peer)
		if ok != tc.ok || id.Agent != tc.agent || id.Known() != tc.ok {
			t.Errorf("Lookup(%+v) = %q %v, want %q %v", tc.peer, id.Agent, ok, tc.agent, tc.ok)
		}
		if ok && id.Source != SourcePeer {
			t.Errorf("source = %s", id.Source)
		}
	}
	pool, _ := m.Lookup(Peer{UID: 2002, GID: 3000})
	if !pool.Has(ScopeSecretsList) || pool.Has(ScopeSecretsWrite) {
		t.Errorf("pool scopes = %v", pool.Scopes)
	}
	b, _ := m.Lookup(Peer{UID: 2001})
	if b.Labels["team"] != "infra" || !b.Has(ScopeSessionsMint) {
		t.Errorf("builder = %+v", b)
	}
}

func TestPeerMapRejectsBadConfiguration(t *testing.T) {
	for name, rules := range map[string][]PeerRule{
		"conflict":     {{Agent: "a", UIDs: []uint32{1}}, {Agent: "b", UIDs: []uint32{1}}},
		"bad name":     {{Agent: "Bad Name", UIDs: []uint32{1}}},
		"no match":     {{Agent: "a"}},
		"unknown user": {{Agent: "a", Users: []string{"nobody-here"}}},
		"bad scope":    {{Agent: "a", UIDs: []uint32{1}, Scopes: []Scope{"secrets:read"}}},
	} {
		if _, err := NewPeerMap(rules, accounts{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDefaultPeerRulesMapThisUser(t *testing.T) {
	m, err := NewPeerMap(DefaultPeerRules(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := m.Lookup(Peer{UID: uint32(os.Getuid())}) // #nosec G115
	if !ok || !ValidAgentName(id.Agent) {
		t.Fatalf("default map: %+v %v", id, ok)
	}
	if _, ok := m.Lookup(Peer{UID: uint32(os.Getuid()) + 1}); ok { // #nosec G115
		t.Fatal("another user is mapped by default")
	}
}

func TestTokenShape(t *testing.T) {
	id, tok, hash, err := mintToken(defaultRand)
	if err != nil {
		t.Fatal(err)
	}
	raw := expose(t, tok)
	if !bytes.HasPrefix(raw, []byte(TokenPrefix+id+"_")) || len(raw) != tokenLen {
		t.Fatalf("token shape: %d bytes", len(raw))
	}
	pid, phash, ok := parseToken(raw)
	if !ok || pid != id || !bytes.Equal(phash, hash) {
		t.Fatal("token does not parse back")
	}
	if bytes.Contains(hash, raw[len(raw)-secretLen:]) {
		t.Fatal("hash contains the secret part")
	}
	if got := fmt.Sprint(tok); strings.Contains(got, string(raw)) {
		t.Fatal("token printed")
	}
	for _, bad := range [][]byte{nil, []byte("scrim_st_"), raw[:len(raw)-1], append([]byte("x"), raw[1:]...),
		[]byte(strings.Replace(string(raw), "_", "-", 2)), bytes.ToUpper(raw)} {
		if LooksLikeToken(bad) {
			t.Errorf("accepted malformed token of %d bytes", len(bad))
		}
	}
}

func TestMintBindsToTheCallersProcessTree(t *testing.T) {
	mgr, _ := newManager(t, machine())
	ctx := context.Background()
	a, err := mgr.Mint(ctx, peerID("dev", 1000, 200), MintRequest{Name: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Session.Root != (Proc{PID: 200, PPID: 100, Start: 20}) {
		t.Fatalf("root = %+v", a.Session.Root)
	}
	if slices.Contains(a.Session.Scopes, ScopeSessionsMint) || len(a.Session.Scopes) != len(AgentScopes) {
		t.Fatalf("scopes = %v", a.Session.Scopes)
	}
	if a.Session.ExpiresAt.Sub(a.Session.CreatedAt) != DefaultSessionTTL {
		t.Fatalf("ttl = %v", a.Session.ExpiresAt.Sub(a.Session.CreatedAt))
	}
	tok := expose(t, a.Token)
	for _, pid := range []int32{200, 201, 202} {
		id, err := mgr.Verify(ctx, Peer{UID: 1000, GID: 1000, PID: pid}, tok)
		if err != nil {
			t.Fatalf("pid %d: %v", pid, err)
		}
		if id.Source != SourceSession || id.Agent != "dev" || id.SessionID != a.Session.ID || id.SessionName != "claude" {
			t.Fatalf("identity = %+v", id)
		}
		if id.Has(ScopeSessionsMint) {
			t.Fatal("session can mint")
		}
	}
}

// TestOneAgentCannotUseAnothersToken is the 8.1 verification: agent B reads
// agent A's token (same user, so it can read A's environment) and presents
// it. It is refused, and B's own session has a different principal, so
// nothing owned by A is reachable from B.
func TestOneAgentCannotUseAnothersToken(t *testing.T) {
	mgr, _ := newManager(t, machine())
	ctx := context.Background()
	a, err := mgr.Mint(ctx, peerID("dev", 1000, 200), MintRequest{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := mgr.Mint(ctx, peerID("dev", 1000, 300), MintRequest{Name: "b"})
	if err != nil {
		t.Fatal(err)
	}
	tokA, tokB := expose(t, a.Token), expose(t, b.Token)
	if bytes.Equal(tokA, tokB) || a.Session.ID == b.Session.ID {
		t.Fatal("two sessions share a token")
	}

	_, err = mgr.Verify(ctx, Peer{UID: 1000, PID: 301}, tokA)
	if refusal(t, err) != RefusedWrongTree {
		t.Fatalf("B with A's token: %v", err)
	}
	_, err = mgr.Verify(ctx, Peer{UID: 1001, PID: 201}, tokA)
	if refusal(t, err) != RefusedWrongUser {
		t.Fatalf("other user with A's token: %v", err)
	}

	idA, err := mgr.Verify(ctx, Peer{UID: 1000, PID: 201}, tokA)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := mgr.Verify(ctx, Peer{UID: 1000, PID: 301}, tokB)
	if err != nil {
		t.Fatal(err)
	}
	peer := peerID("dev", 1000, 100)
	if idA.Principal() == idB.Principal() || idA.Principal() == peer.Principal() || idB.Principal() == peer.Principal() {
		t.Fatalf("principals collide: %q %q %q", idA.Principal(), idB.Principal(), peer.Principal())
	}
}

func TestVerifyRefusals(t *testing.T) {
	procs := machine()
	mgr, clk := newManager(t, procs)
	ctx := context.Background()
	m, err := mgr.Mint(ctx, peerID("dev", 1000, 200), MintRequest{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	tok := expose(t, m.Token)
	peer := Peer{UID: 1000, PID: 201}

	tampered := bytes.Clone(tok)
	last := len(tampered) - 1
	tampered[last] = 'A'
	if tok[last] == 'A' {
		tampered[last] = 'B'
	}
	if _, err := mgr.Verify(ctx, peer, tampered); refusal(t, err) != RefusedUnknown {
		t.Errorf("tampered secret: %v", err)
	}
	if _, err := mgr.Verify(ctx, peer, []byte("scrim_st_nope")); refusal(t, err) != RefusedMalformed {
		t.Errorf("malformed: %v", err)
	}
	_, unknown, _, _ := mintToken(defaultRand)
	if _, err := mgr.Verify(ctx, peer, expose(t, unknown)); refusal(t, err) != RefusedUnknown {
		t.Errorf("unknown: %v", err)
	}
	if _, err := mgr.Verify(ctx, Peer{UID: 1000}, tok); refusal(t, err) != RefusedWrongTree {
		t.Errorf("no pid: %v", err)
	}

	clk.t = clk.t.Add(time.Hour)
	if _, err := mgr.Verify(ctx, peer, tok); refusal(t, err) != RefusedExpired {
		t.Errorf("expired: %v", err)
	}
	clk.t = clk.t.Add(-time.Minute)
	if _, err := mgr.Verify(ctx, peer, tok); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	if err := mgr.Revoke(ctx, m.Session.ID, RevokeEnded); err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Verify(ctx, peer, tok)
	if re, _ := IsRefused(err); re == nil || re.Reason != RefusedRevoked || re.SessionID != m.Session.ID {
		t.Errorf("revoked: %v", err)
	}
	s, _ := mgr.Get(ctx, m.Session.ID)
	if s.RevokeReason != RevokeEnded {
		t.Errorf("reason = %q", s.RevokeReason)
	}
}

func TestMintRefusals(t *testing.T) {
	mgr, _ := newManager(t, machine())
	ctx := context.Background()
	sess := peerID("dev", 1000, 201)
	sess.Source = SourceSession
	noMint := peerID("dev", 1000, 200)
	noMint.Scopes = slices.Clone(AgentScopes)
	listOnly := peerID("dev", 1000, 200)
	listOnly.Scopes = []Scope{ScopeSecretsList, ScopeSessionsMint}
	for name, tc := range map[string]struct {
		who Identity
		req MintRequest
	}{
		"unknown":       {Unknown(Peer{UID: 5, PID: 200}), MintRequest{}},
		"session":       {sess, MintRequest{}},
		"no mint scope": {noMint, MintRequest{}},
		"no pid":        {peerID("dev", 1000, 0), MintRequest{}},
		"dead process":  {peerID("dev", 1000, 777), MintRequest{}},
		"wider scopes":  {listOnly, MintRequest{Scopes: []Scope{ScopeSecretsWrite}}},
		"mint scope":    {peerID("dev", 1000, 200), MintRequest{Scopes: []Scope{ScopeSessionsMint}}},
		"bad scope":     {peerID("dev", 1000, 200), MintRequest{Scopes: []Scope{"x"}}},
		"long name":     {peerID("dev", 1000, 200), MintRequest{Name: strings.Repeat("n", 65)}},
	} {
		if _, err := mgr.Mint(ctx, tc.who, tc.req); !errors.Is(err, ErrMintRefused) {
			t.Errorf("%s: err = %v, want ErrMintRefused", name, err)
		}
	}
	m, err := mgr.Mint(ctx, listOnly, MintRequest{Scopes: []Scope{ScopeSecretsList, ScopeSecretsList}, TTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Session.Scopes, []Scope{ScopeSecretsList}) {
		t.Errorf("scopes = %v", m.Session.Scopes)
	}
	if got := m.Session.ExpiresAt.Sub(m.Session.CreatedAt); got != MaxSessionTTL {
		t.Errorf("ttl = %v, want capped at %v", got, MaxSessionTTL)
	}
}

func TestSweepRevokesSessionsWhoseRootExited(t *testing.T) {
	procs := machine()
	mgr, _ := newManager(t, procs)
	ctx := context.Background()
	a, _ := mgr.Mint(ctx, peerID("dev", 1000, 200), MintRequest{})
	b, _ := mgr.Mint(ctx, peerID("dev", 1000, 300), MintRequest{})
	procs.kill(200)
	procs.set(Proc{PID: 300, PPID: 1, Start: 31337}) // B's root PID reused
	gone, err := mgr.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 2 {
		t.Fatalf("swept %d, want 2", len(gone))
	}
	for _, m := range []Minted{a, b} {
		s, _ := mgr.Get(ctx, m.Session.ID)
		if s.RevokeReason != RevokeRootExited {
			t.Errorf("session %s: reason %q", s.ID, s.RevokeReason)
		}
	}
	if again, _ := mgr.Sweep(ctx); len(again) != 0 {
		t.Errorf("second sweep revoked %d", len(again))
	}
}

func TestRevokeAgent(t *testing.T) {
	mgr, _ := newManager(t, machine())
	ctx := context.Background()
	a, _ := mgr.Mint(ctx, peerID("dev", 1000, 200), MintRequest{})
	_, _ = mgr.Mint(ctx, peerID("dev", 1000, 300), MintRequest{})
	o, _ := mgr.Mint(ctx, peerID("ops", 1001, 300), MintRequest{})
	n, err := mgr.RevokeAgent(ctx, "dev")
	if err != nil || n != 2 {
		t.Fatalf("revoked %d, %v", n, err)
	}
	if _, err := mgr.Verify(ctx, Peer{UID: 1000, PID: 201}, expose(t, a.Token)); refusal(t, err) != RefusedRevoked {
		t.Error("dev session still valid")
	}
	if _, err := mgr.Verify(ctx, Peer{UID: 1001, PID: 301}, expose(t, o.Token)); err != nil {
		t.Errorf("ops session: %v", err)
	}
}

func TestResolver(t *testing.T) {
	peers, err := NewPeerMap([]PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, accounts{})
	if err != nil {
		t.Fatal(err)
	}
	mgr, _ := newManager(t, machine())
	r := Resolver{Peers: peers, Sessions: mgr}
	ctx := context.Background()

	id, err := r.Resolve(ctx, Peer{UID: 1000, PID: 201}, nil)
	if err != nil || id.Source != SourcePeer || id.Agent != "dev" {
		t.Fatalf("peer: %+v %v", id, err)
	}
	id, err = r.Resolve(ctx, Peer{UID: 4242, PID: 201}, nil)
	if err != nil || id.Known() || id.Principal() != "" || id.Has(ScopeSecretsList) {
		t.Fatalf("unmapped: %+v %v", id, err)
	}
	m, err := mgr.Mint(ctx, func() Identity { i, _ := peers.Lookup(Peer{UID: 1000, PID: 200}); return i }(), MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	id, err = r.Resolve(ctx, Peer{UID: 1000, PID: 202}, expose(t, m.Token))
	if err != nil || id.Source != SourceSession {
		t.Fatalf("session: %+v %v", id, err)
	}
	// A refused token never falls back to the peer identity.
	if _, err := r.Resolve(ctx, Peer{UID: 1000, PID: 301}, expose(t, m.Token)); err == nil {
		t.Fatal("token from outside the tree fell back to the peer identity")
	}
	if !strings.Contains(id.String(), m.Session.ID) || strings.Contains(id.String(), string(expose(t, m.Token))) {
		t.Errorf("String() = %q", id.String())
	}
}

func TestRulesFromMap(t *testing.T) {
	rules, err := RulesFromMap(map[string]string{
		"claude": "user:agent1 uid:2002",
		"ci":     "group:ci gid:3001 scope:secrets:list label:team=infra",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Agent != "ci" || rules[1].Agent != "claude" {
		t.Fatalf("rules = %+v", rules)
	}
	ci, claude := rules[0], rules[1]
	if !slices.Equal(ci.Groups, []string{"ci"}) || !slices.Equal(ci.GIDs, []uint32{3001}) ||
		!slices.Equal(ci.Scopes, []Scope{ScopeSecretsList}) || ci.Labels["team"] != "infra" {
		t.Errorf("ci = %+v", ci)
	}
	if !slices.Equal(claude.Users, []string{"agent1"}) || !slices.Equal(claude.UIDs, []uint32{2002}) {
		t.Errorf("claude = %+v", claude)
	}
	for _, bad := range []string{"uid:x", "nokind", "shell:bash", "label:novalue", "user:"} {
		if _, err := RulesFromMap(map[string]string{"a": bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	def, err := RulesFromMap(nil)
	if err != nil || len(def) != 1 {
		t.Fatalf("default: %+v %v", def, err)
	}
}
