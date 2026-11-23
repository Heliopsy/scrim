// SPDX-License-Identifier: AGPL-3.0-only

package dbproxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- PostgreSQL's md5 password authentication is defined over MD5
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- MySQL's mysql_native_password is defined over SHA-1
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
)

// scramClient is the client side of SCRAM-SHA-256 (RFC 5802, RFC 7677) as
// PostgreSQL speaks it: no channel binding, and the user name comes from the
// startup message. Every key derived from the password is wiped.
type scramClient struct {
	nonce          string
	firstBare      string
	authMessage    []byte
	serverKeyProof []byte
}

func newScramClient() (*scramClient, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	n := base64.RawStdEncoding.EncodeToString(b)
	return &scramClient{nonce: n, firstBare: "n=,r=" + n}, nil
}

// first is the client-first-message.
func (s *scramClient) first() []byte { return []byte("n,," + s.firstBare) }

// final answers the server-first-message with the client-final-message.
func (s *scramClient) final(pw secret.Value, serverFirst []byte) ([]byte, error) {
	var nonce, salt string
	iter := 0
	for _, kv := range strings.Split(string(serverFirst), ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "r":
			nonce = v
		case "s":
			salt = v
		case "i":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, errors.New("scram: bad iteration count")
			}
			iter = n
		}
	}
	if !strings.HasPrefix(nonce, s.nonce) || len(nonce) == len(s.nonce) {
		return nil, errors.New("scram: the server nonce does not extend the client nonce")
	}
	if iter < 4096 || iter > 1<<24 {
		return nil, errors.New("scram: iteration count out of range")
	}
	saltRaw, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(saltRaw) == 0 {
		return nil, errors.New("scram: bad salt")
	}
	withoutProof := "c=biws,r=" + nonce
	s.authMessage = []byte(s.firstBare + "," + string(serverFirst) + "," + withoutProof)

	var proof []byte
	err = pw.Expose(func(p []byte) error {
		salted := pbkdf2SHA256(p, saltRaw, iter)
		defer secret.WipeBytes(salted)
		clientKey := hmacSHA256(salted, []byte("Client Key"))
		defer secret.WipeBytes(clientKey)
		stored := sha256.Sum256(clientKey)
		defer secret.WipeBytes(stored[:])
		sig := hmacSHA256(stored[:], s.authMessage)
		proof = make([]byte, len(clientKey))
		for i := range clientKey {
			proof[i] = clientKey[i] ^ sig[i]
		}
		serverKey := hmacSHA256(salted, []byte("Server Key"))
		defer secret.WipeBytes(serverKey)
		s.serverKeyProof = hmacSHA256(serverKey, s.authMessage)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return []byte(withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

// verify checks the server-final-message, which proves the server knows the
// password too.
func (s *scramClient) verify(serverFinal []byte) error {
	v, ok := bytes.CutPrefix(serverFinal, []byte("v="))
	if !ok {
		return errors.New("scram: the server sent no signature")
	}
	sig, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil || !hmac.Equal(sig, s.serverKeyProof) {
		return errors.New("scram: the server signature does not match")
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// pbkdf2SHA256 is PBKDF2-HMAC-SHA-256 for one 32-byte block, which is all
// SCRAM-SHA-256 needs. It takes the password as bytes, so no string copy of
// it is made.
func pbkdf2SHA256(pw, salt []byte, iter int) []byte {
	m := hmac.New(sha256.New, pw)
	var one [4]byte
	binary.BigEndian.PutUint32(one[:], 1)
	m.Write(salt)
	m.Write(one[:])
	u := m.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		m.Reset()
		m.Write(u)
		u = m.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	secret.WipeBytes(u)
	return out
}

// pgMD5 is PostgreSQL's md5 response: "md5" || hex(md5(hex(md5(pw||user)) || salt)).
func pgMD5(pw secret.Value, user string, salt []byte) []byte {
	var out []byte
	_ = pw.Expose(func(p []byte) error {
		h := md5.New() // #nosec G401 -- the protocol's own hash
		h.Write(p)
		h.Write([]byte(user))
		inner := make([]byte, hex.EncodedLen(md5.Size))
		hex.Encode(inner, h.Sum(nil))
		defer secret.WipeBytes(inner)
		h2 := md5.New() // #nosec G401 -- the protocol's own hash
		h2.Write(inner)
		h2.Write(salt)
		out = make([]byte, 3+hex.EncodedLen(md5.Size))
		copy(out, "md5")
		hex.Encode(out[3:], h2.Sum(nil))
		return nil
	})
	return out
}

// mysqlNative is mysql_native_password's scramble:
// SHA1(pw) XOR SHA1(nonce || SHA1(SHA1(pw))). An empty password answers
// empty.
func mysqlNative(pw secret.Value, nonce []byte) []byte {
	var out []byte
	_ = pw.Expose(func(p []byte) error {
		if len(p) == 0 {
			return nil
		}
		s1 := sha1.Sum(p) // #nosec G401 -- the protocol's own hash
		defer secret.WipeBytes(s1[:])
		s2 := sha1.Sum(s1[:]) // #nosec G401 -- the protocol's own hash
		h := sha1.New()       // #nosec G401 -- the protocol's own hash
		h.Write(nonce)
		h.Write(s2[:])
		s3 := h.Sum(nil)
		out = make([]byte, len(s1))
		for i := range s1 {
			out[i] = s1[i] ^ s3[i]
		}
		return nil
	})
	return out
}

// mysqlCachingSHA2 is caching_sha2_password's fast scramble:
// SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) || nonce).
func mysqlCachingSHA2(pw secret.Value, nonce []byte) []byte {
	var out []byte
	_ = pw.Expose(func(p []byte) error {
		if len(p) == 0 {
			return nil
		}
		s1 := sha256.Sum256(p)
		defer secret.WipeBytes(s1[:])
		s2 := sha256.Sum256(s1[:])
		h := sha256.New()
		h.Write(s2[:])
		h.Write(nonce)
		s3 := h.Sum(nil)
		out = make([]byte, len(s1))
		for i := range s1 {
			out[i] = s1[i] ^ s3[i]
		}
		return nil
	})
	return out
}
