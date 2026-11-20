// SPDX-License-Identifier: AGPL-3.0-only

package bwcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/heliopsy/scrim/internal/secret"
)

// SymmetricKeySize is the size of a Bitwarden AES-256-CBC-HMAC-SHA256 key:
// 32 bytes of encryption key followed by 32 bytes of MAC key.
const SymmetricKeySize = 64

// SymmetricKey is a 64-byte encryption and MAC key pair. It prints as a
// redaction marker. The zero SymmetricKey is invalid.
type SymmetricKey struct {
	v secret.Value
}

// NewSymmetricKey takes ownership of a 64-byte key.
func NewSymmetricKey(v secret.Value) (SymmetricKey, error) {
	if v.Len() != SymmetricKeySize {
		n := v.Len()
		v.Wipe()
		return SymmetricKey{}, fmt.Errorf("%w: symmetric key must be %d bytes, got %d", ErrKey, SymmetricKeySize, n)
	}
	return SymmetricKey{v: v}, nil
}

// GenerateSymmetricKey returns a new random key.
func GenerateSymmetricKey() (SymmetricKey, error) {
	b := make([]byte, SymmetricKeySize)
	if _, err := rand.Read(b); err != nil {
		return SymmetricKey{}, fmt.Errorf("bwcrypto: random: %w", err)
	}
	return NewSymmetricKey(secret.Adopt(b))
}

// Valid reports whether the key holds 64 unwiped bytes.
func (k SymmetricKey) Valid() bool { return k.v.Len() == SymmetricKeySize && !k.v.Wiped() }

// Wipe clears the key material.
func (k SymmetricKey) Wipe() { k.v.Wipe() }

// Value returns the raw key as a secret Value, for encrypting it under
// another key. Wiping the returned Value wipes the key.
func (k SymmetricKey) Value() secret.Value { return k.v }

// String implements fmt.Stringer and never shows key material.
func (SymmetricKey) String() string { return secret.Marker }

// Format implements fmt.Formatter so every verb prints the marker.
func (SymmetricKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(secret.Marker)) }

// GoString implements fmt.GoStringer.
func (SymmetricKey) GoString() string { return "bwcrypto.SymmetricKey(" + secret.Marker + ")" }

func (k SymmetricKey) expose(fn func(enc, mac []byte) error) error {
	if !k.Valid() {
		return fmt.Errorf("%w: key is empty or wiped", ErrKey)
	}
	return k.v.Expose(func(b []byte) error { return fn(b[:32], b[32:]) })
}

// Decrypt verifies and decrypts a type 2 EncString. The MAC over IV and
// ciphertext is checked in constant time before the ciphertext is touched.
func (k SymmetricKey) Decrypt(e EncString) (secret.Value, error) {
	if e.Type != EncAESCBC256HMACSHA256B64 {
		return secret.Value{}, fmt.Errorf("%w: type %d for symmetric data (only type 2 is accepted)", ErrUnsupported, e.Type)
	}
	if len(e.IV) != aes.BlockSize || len(e.MAC) != sha256.Size ||
		len(e.Data) == 0 || len(e.Data)%aes.BlockSize != 0 {
		return secret.Value{}, fmt.Errorf("%w: bad lengths", ErrMalformed)
	}
	var out secret.Value
	err := k.expose(func(encKey, macKey []byte) error {
		if !hmac.Equal(macOf(macKey, e.IV, e.Data), e.MAC) {
			return ErrMAC
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrKey, err)
		}
		pt := make([]byte, len(e.Data))
		cipher.NewCBCDecrypter(block, e.IV).CryptBlocks(pt, e.Data)
		n, ok := unpad(pt)
		if !ok {
			secret.WipeBytes(pt)
			return ErrPadding
		}
		// Copy the unpadded plaintext so the Value's buffer is exact, then
		// wipe the padded working copy.
		out = secret.New(pt[:n])
		secret.WipeBytes(pt)
		return nil
	})
	return out, err
}

// DecryptString parses and decrypts a wire-form EncString.
func (k SymmetricKey) DecryptString(s string) (secret.Value, error) {
	e, err := ParseEncString(s)
	if err != nil {
		return secret.Value{}, err
	}
	return k.Decrypt(e)
}

// DecryptKey decrypts a wrapped 64-byte symmetric key, such as a user key
// under the stretched master key or an item key under the user key.
func (k SymmetricKey) DecryptKey(s string) (SymmetricKey, error) {
	v, err := k.DecryptString(s)
	if err != nil {
		return SymmetricKey{}, err
	}
	return NewSymmetricKey(v)
}

// DecryptMetadata decrypts a string that is not a secret value, such as an
// item, folder or field name. Do not use it for passwords, notes or field
// values: those stay in a secret.Value.
func (k SymmetricKey) DecryptMetadata(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	v, err := k.DecryptString(s)
	if err != nil {
		return "", err
	}
	defer v.Wipe()
	var out string
	_ = v.Expose(func(b []byte) error { out = string(b); return nil })
	return out, nil
}

// Encrypt encrypts plaintext as a type 2 EncString with a random IV.
func (k SymmetricKey) Encrypt(plaintext secret.Value) (EncString, error) {
	var out EncString
	err := plaintext.Expose(func(pt []byte) error {
		e, err := k.encryptBytes(pt)
		out = e
		return err
	})
	return out, err
}

// EncryptMetadata encrypts a non-secret string such as an item name.
func (k SymmetricKey) EncryptMetadata(s string) (EncString, error) {
	return k.encryptBytes([]byte(s))
}

func (k SymmetricKey) encryptBytes(pt []byte) (EncString, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return EncString{}, fmt.Errorf("bwcrypto: random: %w", err)
	}
	var out EncString
	err := k.expose(func(encKey, macKey []byte) error {
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrKey, err)
		}
		padded := pad(pt)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		secret.WipeBytes(padded)
		out = EncString{Type: EncAESCBC256HMACSHA256B64, IV: iv, Data: ct, MAC: macOf(macKey, iv, ct)}
		return nil
	})
	return out, err
}

// macOf is HMAC-SHA256 over iv || data.
func macOf(macKey, iv, data []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(iv)
	m.Write(data)
	return m.Sum(nil)
}

// pad applies PKCS#7 padding into a new slice.
func pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// unpad checks PKCS#7 padding and returns the unpadded length. It runs after
// MAC verification, so it is not a padding oracle; it still checks every
// padding byte.
func unpad(b []byte) (int, bool) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return 0, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize {
		return 0, false
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return 0, false
		}
	}
	return len(b) - n, true
}
