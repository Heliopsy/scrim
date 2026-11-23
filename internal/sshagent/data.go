// SPDX-License-Identifier: AGPL-3.0-only

package sshagent

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

// Kinds of signed data (policy.SSHKindUserauth, policy.SSHKindSSHSig).
const (
	KindUserauth = "userauth"
	KindSSHSig   = "sshsig"
)

const (
	msgUserauthRequest = 50
	methodPublickey    = "publickey"
	methodHostbound    = "publickey-hostbound-v00@openssh.com"
	sshsigMagic        = "SSHSIG"
)

// Signed is what the data of a sign request says.
type Signed struct {
	// Kind is KindUserauth or KindSSHSig.
	Kind string
	// SessionID, User, Service, Algorithm and Key are the login's
	// (RFC 4252 section 7). HostKey is set by the hostbound method.
	SessionID []byte
	User      string
	Service   string
	Algorithm string
	Key       []byte
	HostKey   []byte
	// Namespace and HashAlgorithm are the SSHSIG blob's (PROTOCOL.sshsig).
	Namespace     string
	HashAlgorithm string
}

// ParseSigned reads the data of a sign request. Data that is neither an SSH
// login nor an SSHSIG blob is ErrUnknownData: scrim does not sign arbitrary
// bytes.
func ParseSigned(data []byte) (Signed, error) {
	if s, ok := parseSSHSig(data); ok {
		return s, nil
	}
	if s, ok := parseUserauth(data); ok {
		return s, nil
	}
	return Signed{}, ErrUnknownData
}

type reader struct {
	b  []byte
	ok bool
}

func (r *reader) str() []byte {
	if !r.ok || len(r.b) < 4 {
		r.ok = false
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		r.ok = false
		return nil
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s
}

func (r *reader) byte1() byte {
	if !r.ok || len(r.b) < 1 {
		r.ok = false
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *reader) done() bool { return r.ok && len(r.b) == 0 }

func parseUserauth(data []byte) (Signed, bool) {
	r := &reader{b: data, ok: true}
	s := Signed{Kind: KindUserauth}
	s.SessionID = r.str()
	if r.byte1() != msgUserauthRequest {
		return Signed{}, false
	}
	s.User = string(r.str())
	s.Service = string(r.str())
	method := string(r.str())
	if r.byte1() != 1 {
		return Signed{}, false
	}
	s.Algorithm = string(r.str())
	s.Key = r.str()
	switch method {
	case methodPublickey:
	case methodHostbound:
		s.HostKey = r.str()
	default:
		return Signed{}, false
	}
	if !r.done() || len(s.SessionID) == 0 || len(s.SessionID) > 64 || s.Service != "ssh-connection" {
		return Signed{}, false
	}
	if _, err := ssh.ParsePublicKey(s.Key); err != nil {
		return Signed{}, false
	}
	return s, true
}

func parseSSHSig(data []byte) (Signed, bool) {
	rest, ok := bytes.CutPrefix(data, []byte(sshsigMagic))
	if !ok {
		return Signed{}, false
	}
	r := &reader{b: rest, ok: true}
	s := Signed{Kind: KindSSHSig}
	s.Namespace = string(r.str())
	_ = r.str() // reserved
	s.HashAlgorithm = string(r.str())
	hash := r.str()
	if !r.done() || s.Namespace == "" || len(hash) == 0 {
		return Signed{}, false
	}
	switch s.HashAlgorithm {
	case "sha256", "sha512":
	default:
		return Signed{}, false
	}
	return s, true
}

// Check checks s against the key asked to sign and the connection's
// bindings, and returns the host key the signature is for: the last
// binding's for a login, nil for an SSHSIG signature or without bindings.
// A login must carry the session identifier of the last binding, and the
// key it names must be the key asked to sign.
func Check(s Signed, key []byte, bindings []Binding) (ssh.PublicKey, error) {
	host, err := HostOf(bindings)
	if err != nil {
		return nil, err
	}
	if s.Kind != KindUserauth {
		return nil, nil
	}
	if !bytes.Equal(s.Key, key) {
		return nil, ErrKeyMismatch
	}
	if len(bindings) == 0 {
		return nil, nil
	}
	last := bindings[len(bindings)-1]
	if !bytes.Equal(s.SessionID, last.SessionID) {
		return nil, ErrSessionMismatch
	}
	if s.HostKey != nil && !bytes.Equal(s.HostKey, last.HostKey) {
		return nil, ErrHostMismatch
	}
	return host, nil
}
