// SPDX-License-Identifier: AGPL-3.0-only

// Package sshagent is scrim's ssh-agent (specs/credential-injection, "SSH
// agent"): the agent protocol on any listener, in front of a [Backend] that
// holds no keys itself.
//
//	ssh, git ──▶ SSH_AUTH_SOCK ──▶ Serve ──▶ Backend ──▶ control plane
//	             (session dir)    protocol    (local API)  keys from stores,
//	                              bindings                  policy, approval,
//	                                                        audit, signing
//
// The server speaks three requests: list identities, sign, and the
// session-bind@openssh.com extension. Everything else fails, so the agent
// side can neither add nor remove identities, nor lock, unlock or reach
// keys any other way. A connection that binds with is_forwarding set comes
// from a forwarded agent channel on a remote host, and every list and sign
// request on it is refused.
//
// Bindings are kept per connection and sent with every request: the backend
// verifies each host key signature again and takes the host from it, since
// a caller can reach the backend without this server.
package sshagent

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
)

// Binding is one session-bind@openssh.com from the client: the server's
// host key, the session identifier and the host key's signature over it.
// All wire-format bytes; none of it is secret.
type Binding struct {
	HostKey    []byte `json:"host_key"`
	SessionID  []byte `json:"session_id"`
	Signature  []byte `json:"signature"`
	Forwarding bool   `json:"forwarding,omitempty"`
}

// Verify checks the host key's signature over the session identifier and
// returns the host key.
func (b Binding) Verify() (ssh.PublicKey, error) {
	key, err := ssh.ParsePublicKey(b.HostKey)
	if err != nil {
		return nil, errors.New("sshagent: session binding: malformed host key")
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Signature, &sig); err != nil {
		return nil, errors.New("sshagent: session binding: malformed signature")
	}
	if len(b.SessionID) == 0 || len(b.SessionID) > 64 {
		return nil, errors.New("sshagent: session binding: bad session identifier")
	}
	if err := key.Verify(b.SessionID, &sig); err != nil {
		return nil, errors.New("sshagent: session binding: the host key's signature does not verify")
	}
	return key, nil
}

// Key is one identity offered to the client: a public key or certificate in
// wire format and its comment.
type Key struct {
	Blob    []byte `json:"blob"`
	Comment string `json:"comment"`
}

// SignRequest is one signature the client asks for, with the connection's
// bindings.
type SignRequest struct {
	Key      []byte    `json:"key"`
	Data     []byte    `json:"data"`
	Flags    uint32    `json:"flags,omitempty"`
	Bindings []Binding `json:"bindings,omitempty"`
}

// Signature is an SSH signature, as ssh.Signature.
type Signature struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// Backend lists keys and signs. It decides; the server only speaks the
// protocol. *localapi.Client implements it against the control plane.
type Backend interface {
	SSHKeys(ctx context.Context, bindings []Binding) ([]Key, error)
	SSHSign(ctx context.Context, req SignRequest) (Signature, error)
}

// Signature flags (PROTOCOL.agent).
const (
	FlagRSASHA256 uint32 = 2
	FlagRSASHA512 uint32 = 4
)

// Errors a request can fail with. None of them carries data from the
// request.
var (
	ErrForwarded       = errors.New("sshagent: the connection is a forwarded agent channel; scrim's keys are not offered there")
	ErrUnknownData     = errors.New("sshagent: the data to sign is neither an SSH login nor an SSHSIG signature")
	ErrSessionMismatch = errors.New("sshagent: the login's session identifier does not match the connection's session binding")
	ErrHostMismatch    = errors.New("sshagent: the login names another host key than the connection's session binding")
	ErrKeyMismatch     = errors.New("sshagent: the login names another key than the one asked to sign")
)

// HostOf verifies bindings and returns the host key of the last one, the
// host the client is talking to, or nil without bindings. Any forwarding
// binding refuses the connection.
func HostOf(bindings []Binding) (ssh.PublicKey, error) {
	var host ssh.PublicKey
	for _, b := range bindings {
		k, err := b.Verify()
		if err != nil {
			return nil, err
		}
		if b.Forwarding {
			return nil, ErrForwarded
		}
		host = k
	}
	return host, nil
}
