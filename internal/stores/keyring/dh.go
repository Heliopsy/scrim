// SPDX-License-Identifier: AGPL-3.0-only

package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"

	"github.com/heliopsy/scrim/internal/secret"
)

// The Secret Service's encrypted transfer
// (secret-service-spec, "Transfer of Secrets"): Diffie-Hellman over the
// 1024-bit MODP group of RFC 2409 (Second Oakley Group), HKDF-SHA256 of the
// shared secret with no salt and no info to a 128-bit key, AES-128-CBC with
// PKCS#7 padding, the IV in the secret's parameters. It keeps values off
// the bus in clear, where any process of the same user could monitor them.
const dhAlgorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7"

var (
	dhPrime, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	dhGenerator = big.NewInt(2)
	dhPrimeLen  = (dhPrime.BitLen() + 7) / 8
)

type dhSession struct {
	priv *big.Int
	pub  *big.Int
}

func newDHSession() (*dhSession, error) {
	b := make([]byte, dhPrimeLen)
	defer secret.WipeBytes(b)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	priv := new(big.Int).SetBytes(b)
	// 1 < priv < p-1
	priv.Mod(priv, new(big.Int).Sub(dhPrime, big.NewInt(2)))
	priv.Add(priv, big.NewInt(2))
	return &dhSession{priv: priv, pub: new(big.Int).Exp(dhGenerator, priv, dhPrime)}, nil
}

// public is the client's public key, big-endian.
func (d *dhSession) public() []byte { return d.pub.Bytes() }

// key derives the AES key from the service's public key.
func (d *dhSession) key(peer []byte) ([]byte, error) {
	y := new(big.Int).SetBytes(peer)
	one := big.NewInt(1)
	if y.Cmp(one) <= 0 || y.Cmp(new(big.Int).Sub(dhPrime, one)) >= 0 {
		return nil, errors.New("peer public key out of range")
	}
	shared := new(big.Int).Exp(y, d.priv, dhPrime)
	ikm := make([]byte, dhPrimeLen)
	shared.FillBytes(ikm)
	defer secret.WipeBytes(ikm)
	shared.SetInt64(0)
	return hkdf.Key(sha256.New, ikm, nil, "", 16)
}

func (d *dhSession) wipe() {
	if d == nil {
		return
	}
	d.priv.SetInt64(0)
}

// decrypt returns the plaintext of an AES-128-CBC, PKCS#7 padded secret. It
// never returns part of the plaintext on failure.
func decrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("bad IV length")
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a whole number of blocks")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize {
		secret.WipeBytes(out)
		return nil, errors.New("bad padding")
	}
	want := make([]byte, pad)
	for i := range want {
		want[i] = byte(pad)
	}
	if subtle.ConstantTimeCompare(out[len(out)-pad:], want) != 1 {
		secret.WipeBytes(out)
		return nil, errors.New("bad padding")
	}
	secret.WipeBytes(out[len(out)-pad:])
	return out[:len(out)-pad], nil
}
