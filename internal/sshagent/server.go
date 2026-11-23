// SPDX-License-Identifier: AGPL-3.0-only

package sshagent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Agent protocol message numbers (draft-miller-ssh-agent, PROTOCOL.agent).
const (
	msgFailure           = 5
	msgSuccess           = 6
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12
	msgSignRequest       = 13
	msgSignResponse      = 14
	msgExtension         = 27
	msgExtensionFailure  = 28
)

// ExtSessionBind is the OpenSSH extension that binds a connection to a host.
const ExtSessionBind = "session-bind@openssh.com"

// maxMessage bounds one request, as OpenSSH's agent does.
const maxMessage = 256 << 10

// maxBindings bounds the bindings of one connection, as OpenSSH's agent does.
const maxBindings = 16

// Server serves the agent protocol in front of a Backend.
type Server struct {
	Backend Backend
	// Accept, when set, vets each connection before it is served (the
	// peer's uid); an error closes it.
	Accept func(net.Conn) error
	// Log receives one line per refused request, without request data.
	Log *slog.Logger

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

// Serve accepts connections on ln until ctx ends or ln fails, then closes
// ln and every connection.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if s.Accept != nil {
			if err := s.Accept(c); err != nil {
				s.log().Warn("ssh-agent connection refused", "error", err)
				_ = c.Close()
				continue
			}
		}
		s.mu.Lock()
		if s.conns == nil {
			s.conns = map[net.Conn]struct{}{}
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		wg.Go(func() {
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				_ = c.Close()
			}()
			_ = s.ServeConn(ctx, c)
		})
	}
}

// ServeConn serves one connection until it closes or ctx ends. Each
// connection keeps its own bindings.
func (s *Server) ServeConn(ctx context.Context, c io.ReadWriter) error {
	st := &connState{}
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxMessage {
			return errors.New("sshagent: request size out of range")
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(c, req); err != nil {
			return err
		}
		rep := s.handle(ctx, st, req)
		out := make([]byte, 4+len(rep))
		binary.BigEndian.PutUint32(out, uint32(len(rep))) //nolint:gosec // replies are small
		copy(out[4:], rep)
		if _, err := c.Write(out); err != nil {
			return err
		}
	}
}

type connState struct {
	bindings  []Binding
	forwarded bool
}

func (s *Server) handle(ctx context.Context, st *connState, req []byte) []byte {
	switch req[0] {
	case msgRequestIdentities:
		return s.list(ctx, st)
	case msgSignRequest:
		return s.sign(ctx, st, req)
	case msgExtension:
		return s.extension(st, req)
	default:
		// Adding, removing, locking, smartcards: the agent side holds no
		// keys and changes none.
		return []byte{msgFailure}
	}
}

func (s *Server) list(ctx context.Context, st *connState) []byte {
	if st.forwarded {
		s.log().Warn("ssh-agent list refused", "error", ErrForwarded)
		return []byte{msgFailure}
	}
	keys, err := s.Backend.SSHKeys(ctx, st.bindings)
	if err != nil {
		s.log().Warn("ssh-agent list failed", "error", err)
		return []byte{msgFailure}
	}
	out := []byte{msgIdentitiesAnswer}
	out = binary.BigEndian.AppendUint32(out, uint32(len(keys))) //nolint:gosec // a few keys
	for _, k := range keys {
		out = appendString(out, k.Blob)
		out = appendString(out, []byte(k.Comment))
	}
	return out
}

func (s *Server) sign(ctx context.Context, st *connState, req []byte) []byte {
	var m struct {
		Key   []byte
		Data  []byte
		Flags uint32
	}
	if err := ssh.Unmarshal(req[1:], &m); err != nil {
		return []byte{msgFailure}
	}
	if st.forwarded {
		s.log().Warn("ssh-agent signature refused", "error", ErrForwarded)
		return []byte{msgFailure}
	}
	sig, err := s.Backend.SSHSign(ctx, SignRequest{Key: m.Key, Data: m.Data, Flags: m.Flags, Bindings: st.bindings})
	if err != nil {
		s.log().Warn("ssh-agent signature refused", "error", err)
		return []byte{msgFailure}
	}
	blob := ssh.Marshal(&ssh.Signature{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest})
	return appendString([]byte{msgSignResponse}, blob)
}

func (s *Server) extension(st *connState, req []byte) []byte {
	r := &reader{b: req[1:], ok: true}
	name := string(r.str())
	if !r.ok {
		return []byte{msgFailure}
	}
	if name != ExtSessionBind {
		return []byte{msgFailure}
	}
	var b Binding
	b.HostKey = r.str()
	b.SessionID = r.str()
	b.Signature = r.str()
	fwd := r.byte1()
	if !r.done() || fwd > 1 {
		return []byte{msgExtensionFailure}
	}
	b.Forwarding = fwd == 1
	if _, err := b.Verify(); err != nil {
		s.log().Warn("ssh-agent session binding refused", "error", err)
		return []byte{msgExtensionFailure}
	}
	if b.Forwarding {
		// A forwarded channel: refuse it now and everything after.
		st.forwarded = true
		s.log().Warn("ssh-agent session binding refused", "error", ErrForwarded)
		return []byte{msgExtensionFailure}
	}
	if len(st.bindings) >= maxBindings {
		return []byte{msgExtensionFailure}
	}
	st.bindings = append(st.bindings, b)
	return []byte{msgSuccess}
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // bounded by maxMessage
	return append(b, s...)
}
