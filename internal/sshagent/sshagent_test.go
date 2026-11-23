// SPDX-License-Identifier: AGPL-3.0-only

package sshagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// fakeBackend signs with keys it holds and records what it was asked.
type fakeBackend struct {
	mu       sync.Mutex
	signers  []ssh.Signer
	lists    [][]Binding
	requests []SignRequest
	refuse   bool
}

func (f *fakeBackend) SSHKeys(_ context.Context, b []Binding) ([]Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists = append(f.lists, b)
	var out []Key
	for i, s := range f.signers {
		out = append(out, Key{Blob: s.PublicKey().Marshal(), Comment: "key" + string(rune('0'+i))})
	}
	return out, nil
}

func (f *fakeBackend) SSHSign(_ context.Context, req SignRequest) (Signature, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.refuse {
		return Signature{}, errors.New("denied")
	}
	for _, s := range f.signers {
		if bytes.Equal(s.PublicKey().Marshal(), req.Key) {
			sig, err := s.Sign(rand.Reader, req.Data)
			if err != nil {
				return Signature{}, err
			}
			return Signature{Format: sig.Format, Blob: sig.Blob}, nil
		}
	}
	return Signature{}, errors.New("no such key")
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// serve starts a Server on a Unix socket and returns an agent client.
func serve(t *testing.T, b Backend) agent.ExtendedAgent {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Backend: b}).Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return agent.NewClient(c)
}

func bindMsg(t *testing.T, host ssh.Signer, session []byte, fwd bool) []byte {
	t.Helper()
	sig, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	f := byte(0)
	if fwd {
		f = 1
	}
	out := appendString(nil, host.PublicKey().Marshal())
	out = appendString(out, session)
	out = appendString(out, ssh.Marshal(sig))
	return append(out, f)
}

func TestListAndSign(t *testing.T) {
	user := newSigner(t)
	b := &fakeBackend{signers: []ssh.Signer{user}}
	c := serve(t, b)
	keys, err := c.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, user.PublicKey().Marshal()) || keys[0].Comment != "key0" {
		t.Fatalf("List = %v, %v", keys, err)
	}
	data := userauthData(t, []byte("session-1"), "git", publicKeyOf(t, user), methodPublickey, nil)
	sig, err := c.Sign(keys[0], data)
	if err != nil {
		t.Fatal(err)
	}
	if err := user.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	b.refuse = true
	if _, err := c.Sign(keys[0], data); err == nil {
		t.Fatal("a refused signature must fail")
	}
}

func publicKeyOf(t *testing.T, s ssh.Signer) []byte {
	t.Helper()
	return s.PublicKey().Marshal()
}

func TestAgentSideCannotChangeKeys(t *testing.T) {
	b := &fakeBackend{signers: []ssh.Signer{newSigner(t)}}
	c := serve(t, b)
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.Add(agent.AddedKey{PrivateKey: k, Comment: "planted"}); err == nil {
		t.Error("adding an identity must fail")
	}
	keys, _ := c.List()
	if err := c.Remove(keys[0]); err == nil {
		t.Error("removing an identity must fail")
	}
	if err := c.RemoveAll(); err == nil {
		t.Error("removing all identities must fail")
	}
	if err := c.Lock([]byte("x")); err == nil {
		t.Error("locking must fail")
	}
	if err := c.Unlock([]byte("x")); err == nil {
		t.Error("unlocking must fail")
	}
	if keys, _ := c.List(); len(keys) != 1 {
		t.Errorf("the keys changed: %v", keys)
	}
	if _, err := c.Extension("query", nil); err == nil {
		t.Error("an unknown extension must fail")
	}
}

func TestSessionBind(t *testing.T) {
	user, host, other := newSigner(t), newSigner(t), newSigner(t)
	b := &fakeBackend{signers: []ssh.Signer{user}}
	c := serve(t, b)
	session := []byte("0123456789abcdef0123456789abcdef")
	if _, err := c.Extension(ExtSessionBind, bindMsg(t, host, session, false)); err != nil {
		t.Fatalf("a valid binding failed: %v", err)
	}
	// A binding whose signature is by another key than the host key.
	bad := bindMsg(t, other, session, false)
	bad = append(appendString(nil, host.PublicKey().Marshal()), bad[4+len(other.PublicKey().Marshal()):]...)
	if _, err := c.Extension(ExtSessionBind, bad); err == nil {
		t.Fatal("a binding that does not verify must fail")
	}
	keys, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(keys[0], userauthData(t, session, "git", publicKeyOf(t, user), methodPublickey, nil)); err != nil {
		t.Fatal(err)
	}
	if n := len(b.requests[0].Bindings); n != 1 || !bytes.Equal(b.requests[0].Bindings[0].HostKey, host.PublicKey().Marshal()) {
		t.Fatalf("the backend got %d bindings", n)
	}
	if len(b.lists) != 1 || len(b.lists[0]) != 1 {
		t.Fatal("the list did not carry the binding")
	}

	// A forwarded channel: refused, and so is everything after it.
	if _, err := c.Extension(ExtSessionBind, bindMsg(t, host, session, true)); err == nil {
		t.Fatal("a forwarding binding must fail")
	}
	if _, err := c.List(); err == nil {
		t.Error("listing on a forwarded connection must fail")
	}
	if _, err := c.Sign(keys[0], userauthData(t, session, "git", publicKeyOf(t, user), methodPublickey, nil)); err == nil {
		t.Error("signing on a forwarded connection must fail")
	}
	if len(b.requests) != 1 {
		t.Errorf("the backend was asked %d times; a forwarded connection must not reach it", len(b.requests))
	}
}

// TestGoSSHClientLogin logs in to an x/crypto/ssh server through the agent,
// so the parser is checked against what a real client signs.
func TestGoSSHClientLogin(t *testing.T) {
	user, host := newSigner(t), newSigner(t)
	b := &fakeBackend{signers: []ssh.Signer{user}}
	c := serve(t, b)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), user.PublicKey().Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "no")
		}
	}()
	cl, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "git",
		Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(c.Signers)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	_ = cl.Close()
	if len(b.requests) == 0 {
		t.Fatal("no signature was requested")
	}
	s, err := ParseSigned(b.requests[len(b.requests)-1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != KindUserauth || s.User != "git" || !bytes.Equal(s.Key, user.PublicKey().Marshal()) {
		t.Fatalf("parsed %+v", s)
	}
	if _, err := Check(s, user.PublicKey().Marshal(), nil); err != nil {
		t.Fatal(err)
	}
}
