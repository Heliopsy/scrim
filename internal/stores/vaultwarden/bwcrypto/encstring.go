// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// EncType is the encryption type prefix of an EncString.
type EncType int

// Encryption types defined by the Bitwarden protocol.
const (
	EncAESCBC256B64                   EncType = 0 // unauthenticated, refused
	EncAESCBC128HMACSHA256B64         EncType = 1 // deprecated, refused
	EncAESCBC256HMACSHA256B64         EncType = 2
	EncRSA2048OAEPSHA256B64           EncType = 3
	EncRSA2048OAEPSHA1B64             EncType = 4
	EncRSA2048OAEPSHA256HMACSHA256B64 EncType = 5 // deprecated, refused
	EncRSA2048OAEPSHA1HMACSHA256B64   EncType = 6 // deprecated, refused
)

// Errors returned when parsing or decrypting EncStrings. None of them carry
// ciphertext or plaintext.
var (
	ErrMalformed   = errors.New("bwcrypto: malformed encrypted string")
	ErrUnsupported = errors.New("bwcrypto: unsupported encryption type")
	ErrMAC         = errors.New("bwcrypto: MAC verification failed (wrong key or tampered data)")
	ErrPadding     = errors.New("bwcrypto: invalid padding")
	ErrKey         = errors.New("bwcrypto: invalid key")
)

// EncString is a parsed Bitwarden encrypted string. Its fields hold
// ciphertext, which is not secret, but its String form is still only ever
// sent to the server.
type EncString struct {
	Type EncType
	IV   []byte
	Data []byte
	MAC  []byte
}

// ParseEncString parses the "<type>.<b64 iv>|<b64 data>|<b64 mac>" form, and
// the "<type>.<b64 data>" form of the RSA types. Strings without a type prefix
// follow the legacy rule: two parts are type 0, three parts type 1.
func ParseEncString(s string) (EncString, error) {
	if s == "" {
		return EncString{}, fmt.Errorf("%w: empty", ErrMalformed)
	}
	var (
		t    EncType
		body string
	)
	if head, rest, ok := strings.Cut(s, "."); ok {
		n, err := strconv.Atoi(head)
		if err != nil || n < 0 || n > 6 {
			return EncString{}, fmt.Errorf("%w: bad type prefix", ErrMalformed)
		}
		t, body = EncType(n), rest
	} else {
		body = s
		switch strings.Count(s, "|") {
		case 1:
			t = EncAESCBC256B64
		case 2:
			t = EncAESCBC128HMACSHA256B64
		default:
			return EncString{}, fmt.Errorf("%w: no type prefix", ErrMalformed)
		}
	}
	parts := strings.Split(body, "|")
	dec := func(p string) ([]byte, error) {
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("%w: bad base64", ErrMalformed)
		}
		return b, nil
	}
	e := EncString{Type: t}
	var err error
	switch t {
	case EncAESCBC256B64:
		if len(parts) != 2 {
			return EncString{}, fmt.Errorf("%w: type 0 needs 2 parts", ErrMalformed)
		}
		if e.IV, err = dec(parts[0]); err != nil {
			return EncString{}, err
		}
		if e.Data, err = dec(parts[1]); err != nil {
			return EncString{}, err
		}
	case EncAESCBC128HMACSHA256B64, EncAESCBC256HMACSHA256B64:
		if len(parts) != 3 {
			return EncString{}, fmt.Errorf("%w: type %d needs 3 parts", ErrMalformed, t)
		}
		if e.IV, err = dec(parts[0]); err != nil {
			return EncString{}, err
		}
		if e.Data, err = dec(parts[1]); err != nil {
			return EncString{}, err
		}
		if e.MAC, err = dec(parts[2]); err != nil {
			return EncString{}, err
		}
	case EncRSA2048OAEPSHA256B64, EncRSA2048OAEPSHA1B64:
		if len(parts) != 1 {
			return EncString{}, fmt.Errorf("%w: type %d needs 1 part", ErrMalformed, t)
		}
		if e.Data, err = dec(parts[0]); err != nil {
			return EncString{}, err
		}
	case EncRSA2048OAEPSHA256HMACSHA256B64, EncRSA2048OAEPSHA1HMACSHA256B64:
		if len(parts) != 2 {
			return EncString{}, fmt.Errorf("%w: type %d needs 2 parts", ErrMalformed, t)
		}
		if e.Data, err = dec(parts[0]); err != nil {
			return EncString{}, err
		}
		if e.MAC, err = dec(parts[1]); err != nil {
			return EncString{}, err
		}
	}
	return e, nil
}

// String renders the EncString in wire form.
func (e EncString) String() string {
	enc := base64.StdEncoding.EncodeToString
	switch e.Type {
	case EncAESCBC256B64:
		return "0." + enc(e.IV) + "|" + enc(e.Data)
	case EncAESCBC128HMACSHA256B64, EncAESCBC256HMACSHA256B64:
		return strconv.Itoa(int(e.Type)) + "." + enc(e.IV) + "|" + enc(e.Data) + "|" + enc(e.MAC)
	case EncRSA2048OAEPSHA256HMACSHA256B64, EncRSA2048OAEPSHA1HMACSHA256B64:
		return strconv.Itoa(int(e.Type)) + "." + enc(e.Data) + "|" + enc(e.MAC)
	default:
		return strconv.Itoa(int(e.Type)) + "." + enc(e.Data)
	}
}

// MarshalText renders the wire form, so an EncString can be a JSON field.
func (e EncString) MarshalText() ([]byte, error) { return []byte(e.String()), nil }

// UnmarshalText parses the wire form.
func (e *EncString) UnmarshalText(b []byte) error {
	p, err := ParseEncString(string(b))
	if err != nil {
		return err
	}
	*e = p
	return nil
}
