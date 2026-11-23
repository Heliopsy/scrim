// SPDX-License-Identifier: AGPL-3.0-only

package sops

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/heliopsy/scrim/internal/secret"
)

// Decryption failures, mapped to store error kinds by the adapter. Their
// messages name a field at most, never a value.
var (
	// errNoKey: no configured identity opens the data key.
	errNoKey = errors.New("no configured age identity can decrypt the file's data key")
	// errIntegrity: a value or the MAC does not authenticate.
	errIntegrity = errors.New("integrity check failed")
)

// macOnlyInit starts the MAC of a file with mac_only_encrypted, so its MAC
// differs from the same file without the setting (sops'
// MACOnlyEncryptedInitialization).
var macOnlyInit = []byte{0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3,
	0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81,
	0x76, 0xf2, 0x7d, 0x69}

// encPattern is sops' encrypted value format (aes.Cipher).
var encPattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]`)

type encValue struct {
	data, iv, tag []byte
	typ           string
}

func parseEnc(s string) (encValue, bool) {
	m := encPattern.FindStringSubmatch(s)
	if m == nil {
		return encValue{}, false
	}
	var ev encValue
	var err error
	if ev.data, err = base64.StdEncoding.DecodeString(m[1]); err != nil {
		return encValue{}, false
	}
	if ev.iv, err = base64.StdEncoding.DecodeString(m[2]); err != nil || len(ev.iv) == 0 {
		return encValue{}, false
	}
	if ev.tag, err = base64.StdEncoding.DecodeString(m[3]); err != nil {
		return encValue{}, false
	}
	ev.typ = m[4]
	return ev, true
}

// open decrypts one value with AES-256-GCM. additional is the value's path
// (keys joined by ':' plus a trailing ':') or, for the MAC, the file's
// lastmodified. The caller wipes the result.
func open(key []byte, ev encValue, additional string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errIntegrity
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(ev.iv))
	if err != nil {
		return nil, errIntegrity
	}
	sealed := make([]byte, 0, len(ev.data)+len(ev.tag))
	sealed = append(append(sealed, ev.data...), ev.tag...)
	pt, err := gcm.Open(nil, ev.iv, sealed, []byte(additional))
	if err != nil {
		return nil, errIntegrity
	}
	return pt, nil
}

// macText returns the bytes sops hashes into the MAC for a decrypted value
// of type typ (sops.ToBytes of what aes.Cipher.Decrypt returns), and false
// for a comment, which is neither hashed nor a field. When the result is
// not pt itself the caller wipes it.
//
// Integers and booleans are canonicalised byte by byte. Floats and times
// go through strconv and time as a short-lived string: sops hashes their
// re-formatted value, and there is no byte-level parser for either.
func macText(typ string, pt []byte) ([]byte, bool, error) {
	switch typ {
	case "str", "bytes":
		return pt, true, nil
	case "comment":
		return nil, false, nil
	case "int":
		b, ok := canonicalInt(pt)
		if !ok {
			return nil, false, errors.New("an int value does not parse")
		}
		return b, true, nil
	case "bool":
		switch string(pt) {
		case "1", "t", "T", "TRUE", "true", "True":
			return []byte("True"), true, nil
		case "0", "f", "F", "FALSE", "false", "False":
			return []byte("False"), true, nil
		}
		return nil, false, errors.New("a bool value does not parse")
	case "float":
		f, err := strconv.ParseFloat(string(pt), 64)
		if err != nil {
			return nil, false, errors.New("a float value does not parse")
		}
		return strconv.AppendFloat(nil, f, 'f', -1, 64), true, nil
	case "time":
		var t time.Time
		if err := t.UnmarshalText(pt); err != nil {
			return nil, false, errors.New("a time value does not parse")
		}
		b, err := t.MarshalText()
		if err != nil {
			return nil, false, errors.New("a time value does not parse")
		}
		return b, true, nil
	}
	return nil, false, errors.New("a value has an unknown sops type")
}

// canonicalInt is strconv.Itoa(strconv.Atoi(b)) without making a string:
// optional sign, decimal digits, leading zeros dropped, "-0" as "0", and
// out-of-range values refused.
func canonicalInt(b []byte) ([]byte, bool) {
	neg := false
	if len(b) > 0 && (b[0] == '+' || b[0] == '-') {
		neg = b[0] == '-'
		b = b[1:]
	}
	if len(b) == 0 {
		return nil, false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	for len(b) > 1 && b[0] == '0' {
		b = b[1:]
	}
	limit := []byte("9223372036854775807")
	if neg {
		limit = []byte("9223372036854775808")
	}
	if len(b) > len(limit) || len(b) == len(limit) && bytes.Compare(b, limit) > 0 {
		return nil, false
	}
	out := make([]byte, 0, len(b)+1)
	if neg && (len(b) != 1 || b[0] != '0') {
		out = append(out, '-')
	}
	return append(out, b...), true
}

// dataKey decrypts the file's 32-byte data key with the configured
// identities. The caller wipes it.
func dataKey(md *metadata, ids []age.Identity) ([]byte, error) {
	if md.groups > 1 {
		return nil, errUnsupported{"files with several key groups (Shamir secret sharing) are not supported"}
	}
	if len(md.age) == 0 {
		return nil, errUnsupported{"the file has no age recipient; only age keys are supported"}
	}
	for _, k := range md.age {
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(k.enc)), ids...)
		if err != nil {
			continue
		}
		buf := make([]byte, 33)
		n, err := io.ReadFull(r, buf)
		if n == 32 && errors.Is(err, io.ErrUnexpectedEOF) {
			return buf[:32], nil
		}
		secret.WipeBytes(buf)
	}
	return nil, errNoKey
}

// fieldError is a decryption failure tied to one field (a key path, never
// a value).
type fieldError struct {
	field string
	err   error
}

func (e fieldError) Error() string { return fmt.Sprintf("field %s: %v", e.field, e.err) }
func (e fieldError) Unwrap() error { return e.err }

// decrypt decrypts every encrypted leaf of data, verifies the file's MAC
// over all of them, and returns the fields: every encrypted, non-empty,
// non-comment leaf, or only want when it is set. Nothing is returned unless
// the MAC matches. Unencrypted leaves count toward the MAC but are not
// fields.
func decrypt(data *node, md *metadata, key []byte, want string) (map[string]secret.Value, error) {
	if md.commentRules {
		return nil, errUnsupported{"encrypted_comment_regex and unencrypted_comment_regex are not supported"}
	}
	fields := map[string]secret.Value{}
	wipe := func() {
		for _, v := range fields {
			v.Wipe()
		}
	}
	h := sha512.New()
	if md.macOnly {
		h.Write(macOnlyInit)
	}
	err := walk(data, nil, "", func(n *node, path []string, field string) error {
		if !md.encrypted(path) {
			if !md.macOnly {
				h.Write([]byte(n.text))
			}
			return nil
		}
		if !n.str {
			return fieldError{field, errors.New("an encrypted value is not a string")}
		}
		if n.text == "" {
			return nil // sops leaves empty strings as they are
		}
		ev, ok := parseEnc(n.text)
		if !ok {
			return fieldError{field, errors.New("a value that should be encrypted is not in sops' format")}
		}
		pt, err := open(key, ev, strings.Join(path, ":")+":")
		if err != nil {
			return fieldError{field, err}
		}
		mt, isValue, err := macText(ev.typ, pt)
		if err != nil {
			secret.WipeBytes(pt)
			return fieldError{field, err}
		}
		if !isValue {
			secret.WipeBytes(pt)
			return nil
		}
		h.Write(mt)
		if ev.typ == "bool" {
			// sops encrypts booleans as "True"/"False" and decrypts them
			// to the document's true/false; return what the document
			// shows.
			b := []byte("false")
			if mt[0] == 'T' {
				b = []byte("true")
			}
			secret.WipeBytes(pt)
			pt = b
		}
		if len(mt) > 0 && len(pt) > 0 && &mt[0] != &pt[0] {
			secret.WipeBytes(mt)
		}
		if (want == "" || want == field) && len(pt) > 0 {
			if old, dup := fields[field]; dup {
				old.Wipe()
			}
			fields[field] = secret.Adopt(pt)
		} else {
			secret.WipeBytes(pt)
		}
		return nil
	})
	if err != nil {
		wipe()
		return nil, err
	}
	if err := verifyMAC(md, key, h.Sum(nil)); err != nil {
		wipe()
		return nil, err
	}
	return fields, nil
}

// verifyMAC checks the file's MAC (encrypted with the data key, the
// lastmodified time as additional data) against the computed SHA-512.
func verifyMAC(md *metadata, key, sum []byte) error {
	if md.mac == "" {
		return fmt.Errorf("%w: the file has no MAC", errIntegrity)
	}
	ev, ok := parseEnc(md.mac)
	if !ok {
		return errIntegrity
	}
	stored, err := open(key, ev, md.lastModified.Format(time.RFC3339))
	if err != nil {
		return errIntegrity
	}
	defer secret.WipeBytes(stored)
	want := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(want, sum)
	defer secret.WipeBytes(want)
	for i, c := range want {
		if c >= 'a' && c <= 'f' {
			want[i] = c - 'a' + 'A' // sops formats the MAC with %X
		}
	}
	if !hmac.Equal(want, stored) {
		return errIntegrity
	}
	return nil
}

// fieldNames lists the fields Read would return, from the document alone:
// the leaves the encryption rules cover whose value is a non-empty sops
// value that is not a comment. Keys and value types are plaintext in a SOPS
// file, so nothing is decrypted.
func fieldNames(data *node, md *metadata) []string {
	var out []string
	_ = walk(data, nil, "", func(n *node, path []string, field string) error {
		if !md.encrypted(path) || !n.str || n.text == "" {
			return nil
		}
		if ev, ok := parseEnc(n.text); ok && ev.typ != "comment" {
			out = append(out, field)
		}
		return nil
	})
	return out
}
