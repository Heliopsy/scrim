// SPDX-License-Identifier: AGPL-3.0-only

// Package bwcrypto implements the client-side cryptography of the Bitwarden
// protocol, as used by Vaultwarden and every Bitwarden-compatible server.
//
// The server never sees plaintext. A client derives a master key from the
// master password and the account's KDF parameters (PBKDF2-SHA256 or
// Argon2id), stretches it with HKDF-Expand into an encryption key and a MAC
// key, and uses that to decrypt the account's symmetric user key. The user key
// decrypts the account's RSA private key, which in turn decrypts the
// organisation keys. Items (ciphers) are encrypted with the user key, an
// organisation key, or a per-item key that is itself encrypted with one of
// those.
//
// Only authenticated encryption is accepted for symmetric data: EncString
// type 2 (AES-256-CBC with HMAC-SHA256, encrypt-then-MAC). The MAC is checked
// in constant time before any decryption. Unauthenticated type 0 and type 1
// strings are refused. Asymmetric strings of type 3 (RSA-OAEP-SHA256) and
// type 4 (RSA-OAEP-SHA1) are accepted for organisation keys.
//
// All primitives come from the Go standard library and golang.org/x/crypto.
// Key material is held in [secret.Value] and in byte slices that are wiped
// once used.
package bwcrypto
