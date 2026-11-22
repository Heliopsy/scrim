// SPDX-License-Identifier: AGPL-3.0-only

package sshagent

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func userauthData(t *testing.T, session []byte, user string, key []byte, method string, hostKey []byte) []byte {
	t.Helper()
	b := appendString(nil, session)
	b = append(b, msgUserauthRequest)
	b = appendString(b, []byte(user))
	b = appendString(b, []byte("ssh-connection"))
	b = appendString(b, []byte(method))
	b = append(b, 1)
	b = appendString(b, []byte(ssh.KeyAlgoED25519))
	b = appendString(b, key)
	if method == methodHostbound {
		b = appendString(b, hostKey)
	}
	return b
}

func sshsigData(namespace string) []byte {
	h := sha512.Sum512([]byte("commit"))
	b := []byte(sshsigMagic)
	b = appendString(b, []byte(namespace))
	b = appendString(b, nil)
	b = appendString(b, []byte("sha512"))
	return appendString(b, h[:])
}

func binding(t *testing.T, host ssh.Signer, session []byte, fwd bool) Binding {
	t.Helper()
	sig, err := host.Sign(rand.Reader, session)
	if err != nil {
		t.Fatal(err)
	}
	return Binding{HostKey: host.PublicKey().Marshal(), SessionID: session, Signature: ssh.Marshal(sig), Forwarding: fwd}
}

func TestParseSigned(t *testing.T) {
	user, host := newSigner(t), newSigner(t)
	key, hk := user.PublicKey().Marshal(), host.PublicKey().Marshal()
	s, err := ParseSigned(userauthData(t, []byte("sess"), "git", key, methodPublickey, nil))
	if err != nil || s.Kind != KindUserauth || s.User != "git" || string(s.SessionID) != "sess" || s.HostKey != nil {
		t.Fatalf("publickey: %+v %v", s, err)
	}
	s, err = ParseSigned(userauthData(t, []byte("sess"), "git", key, methodHostbound, hk))
	if err != nil || string(s.HostKey) != string(hk) {
		t.Fatalf("hostbound: %+v %v", s, err)
	}
	s, err = ParseSigned(sshsigData("git"))
	if err != nil || s.Kind != KindSSHSig || s.Namespace != "git" || s.HashAlgorithm != "sha512" {
		t.Fatalf("sshsig: %+v %v", s, err)
	}
	for name, data := range map[string][]byte{
		"empty":          nil,
		"random":         []byte("arbitrary bytes a caller wants signed"),
		"trailing":       append(userauthData(t, []byte("sess"), "git", key, methodPublickey, nil), 0),
		"other method":   userauthData(t, []byte("sess"), "git", key, "password", nil),
		"truncated":      userauthData(t, []byte("sess"), "git", key, methodPublickey, nil)[:20],
		"no namespace":   sshsigData(""),
		"sshsig + junk":  append(sshsigData("git"), 1),
		"malformed key":  userauthData(t, []byte("sess"), "git", []byte("not a key"), methodPublickey, nil),
		"long session":   userauthData(t, make([]byte, 65), "git", key, methodPublickey, nil),
		"magic only":     []byte(sshsigMagic),
		"length too big": {0xff, 0xff, 0xff, 0xff, 1},
	} {
		if _, err := ParseSigned(data); !errors.Is(err, ErrUnknownData) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestCheck(t *testing.T) {
	user, host, other := newSigner(t), newSigner(t), newSigner(t)
	key := user.PublicKey().Marshal()
	sess := []byte("0123456789abcdef")
	login, _ := ParseSigned(userauthData(t, sess, "git", key, methodHostbound, host.PublicKey().Marshal()))

	h, err := Check(login, key, []Binding{binding(t, host, sess, false)})
	if err != nil || h == nil || string(h.Marshal()) != string(host.PublicKey().Marshal()) {
		t.Fatalf("bound login: %v %v", h, err)
	}
	if h, err := Check(login, key, nil); err != nil || h != nil {
		t.Fatalf("unbound login: %v %v", h, err)
	}
	for name, tc := range map[string]struct {
		key      []byte
		bindings []Binding
		want     error
	}{
		"other session":   {key, []Binding{binding(t, host, []byte("another-session"), false)}, ErrSessionMismatch},
		"other host":      {key, []Binding{binding(t, other, sess, false)}, ErrHostMismatch},
		"other key":       {other.PublicKey().Marshal(), []Binding{binding(t, host, sess, false)}, ErrKeyMismatch},
		"forwarded":       {key, []Binding{binding(t, host, sess, false), binding(t, host, sess, true)}, ErrForwarded},
		"unverified bind": {key, []Binding{{HostKey: host.PublicKey().Marshal(), SessionID: sess, Signature: binding(t, other, sess, false).Signature}}, nil},
	} {
		_, err := Check(login, tc.key, tc.bindings)
		if tc.want == nil {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	// An SSHSIG signature is for no host, whatever the connection is bound to.
	sig, _ := ParseSigned(sshsigData("git"))
	if h, err := Check(sig, key, []Binding{binding(t, host, sess, false)}); err != nil || h != nil {
		t.Fatalf("sshsig: %v %v", h, err)
	}
}
