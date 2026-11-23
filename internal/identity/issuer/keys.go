// SPDX-License-Identifier: AGPL-3.0-only

package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

// KeyBits is the size of generated RSA keys. RS256 with 2048-bit keys is
// what every verifier scrim targets accepts (OpenBao and Vault, AWS STS,
// Google STS, Entra ID, Infisical); Entra ID takes RSA only.
const KeyBits = 2048

// minKeyBits is the smallest operator-supplied key accepted.
const minKeyBits = 2048

// signingKey is one RSA key. It never prints, logs or serialises its
// private part: every formatting path shows the key ID only.
type signingKey struct {
	kid  string
	priv *rsa.PrivateKey
}

func newSigningKey(priv *rsa.PrivateKey) signingKey {
	return signingKey{kid: thumbprint(&priv.PublicKey), priv: priv}
}

func (k signingKey) String() string               { return "issuer.signingKey(" + k.kid + ")" }
func (k signingKey) GoString() string             { return k.String() }
func (k signingKey) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.String()) }
func (k signingKey) LogValue() slog.Value         { return slog.StringValue(k.String()) }
func (k signingKey) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }
func (k signingKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }
func (k *signingKey) UnmarshalJSON([]byte) error {
	return errors.New("issuer: signing keys are not decoded")
}
func (k signingKey) public() *rsa.PublicKey             { return &k.priv.PublicKey }
func (k signingKey) equal(o signingKey) bool            { return k.kid == o.kid }
func (k signingKey) bits() int                          { return k.priv.N.BitLen() }
func (k signingKey) sign(digest []byte) ([]byte, error) { return signPKCS1(k.priv, digest) }

// thumbprint is the RFC 7638 JWK thumbprint of an RSA public key, used as
// the key ID: stable, derived from the public key alone.
func thumbprint(pub *rsa.PublicKey) string {
	// Members in lexicographic order, no whitespace (RFC 7638 section 3).
	canon := `{"e":"` + b64(big.NewInt(int64(pub.E)).Bytes()) + `","kty":"RSA","n":"` + b64(pub.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(canon))
	return b64(sum[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// generateKey makes a new RSA key.
func generateKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, KeyBits) }

// parseKeys reads one or more PKCS#8 "PRIVATE KEY" PEM blocks. Errors never
// quote the input.
func parseKeys(v secret.Value) ([]signingKey, error) {
	var keys []signingKey
	err := v.Expose(func(b []byte) error {
		rest := b
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "PRIVATE KEY" {
				return fmt.Errorf("PEM block %d is %q, want PRIVATE KEY (PKCS#8)", len(keys)+1, blk.Type)
			}
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			secret.WipeBytes(blk.Bytes)
			if err != nil {
				return fmt.Errorf("PEM block %d is not a PKCS#8 private key", len(keys)+1)
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("PEM block %d is not an RSA key (RS256 needs RSA)", len(keys)+1)
			}
			if rk.N.BitLen() < minKeyBits {
				return fmt.Errorf("PEM block %d is a %d-bit key, want at least %d", len(keys)+1, rk.N.BitLen(), minKeyBits)
			}
			keys = append(keys, newSigningKey(rk))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM private key found")
	}
	for i, k := range keys {
		if slices.ContainsFunc(keys[:i], k.equal) {
			return nil, fmt.Errorf("PEM block %d repeats an earlier key", i+1)
		}
	}
	return keys, nil
}

// Layout of the key directory:
//
//	<dir>/              0700
//	  keys.json         0600  which key signs, which is next, which are retiring
//	  <kid>.pem         0600  PKCS#8 private key
//
// A rotation writes the new key file first and then replaces keys.json
// atomically, so keys.json is the commit point; key files it no longer
// names are removed afterwards.
const (
	stateFile    = "keys.json"
	stateVersion = 1
	maxFileSize  = 64 << 10
)

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// diskState is keys.json.
type diskState struct {
	Version int `json:"version"`
	// Current signs; ActivatedAt is when it started to.
	Current     string    `json:"current"`
	ActivatedAt time.Time `json:"activated_at"`
	// Next is published now and signs after the next rotation.
	Next string `json:"next"`
	// Retiring keys are published until RetireAt, when the last token
	// they signed has expired.
	Retiring []retiring `json:"retiring,omitempty"`
}

type retiring struct {
	Kid      string    `json:"kid"`
	RetireAt time.Time `json:"retire_at"`
}

func (s diskState) validate() error {
	if s.Version != stateVersion {
		return fmt.Errorf("%s: unsupported version %d", stateFile, s.Version)
	}
	seen := map[string]bool{}
	for _, k := range append([]string{s.Current, s.Next}, kidsOf(s.Retiring)...) {
		if !kidPattern.MatchString(k) {
			return fmt.Errorf("%s: invalid key id %q", stateFile, k)
		}
		if seen[k] {
			return fmt.Errorf("%s: key id %q listed twice", stateFile, k)
		}
		seen[k] = true
	}
	if s.ActivatedAt.IsZero() {
		return fmt.Errorf("%s: no activated_at", stateFile)
	}
	return nil
}

func kidsOf(r []retiring) []string {
	out := make([]string, len(r))
	for i, x := range r {
		out[i] = x.Kid
	}
	return out
}

// DefaultKeyDir is the key directory used when identity.issuer.key-dir is
// empty: $XDG_STATE_HOME/scrim/issuer, or ~/.local/state/scrim/issuer.
func DefaultKeyDir(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if dir := getenv("XDG_STATE_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, "scrim", "issuer"), nil
	}
	if h := getenv("HOME"); h != "" && filepath.IsAbs(h) {
		return filepath.Join(h, ".local", "state", "scrim", "issuer"), nil
	}
	return "", errors.New("issuer: no XDG_STATE_HOME and no home directory ($HOME is not set)")
}

// keyDir is the generated, rotated key set on disk.
type keyDir struct {
	dir      string
	generate func() (*rsa.PrivateKey, error)
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("issuer: create %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("issuer: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("issuer: %s is accessible to group or others (mode %04o); run `chmod 700 %s`", dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// load reads keys.json and every key it names. A missing keys.json is
// (diskState{}, nil, fs.ErrNotExist).
func (d keyDir) load() (diskState, map[string]signingKey, error) {
	var st diskState
	b, err := readSmall(filepath.Join(d.dir, stateFile))
	if err != nil {
		return st, nil, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, nil, fmt.Errorf("issuer: %s: %w", stateFile, err)
	}
	if err := st.validate(); err != nil {
		return st, nil, fmt.Errorf("issuer: %w", err)
	}
	keys := map[string]signingKey{}
	for _, kid := range append([]string{st.Current, st.Next}, kidsOf(st.Retiring)...) {
		k, err := d.readKey(kid)
		if err != nil {
			return st, nil, err
		}
		keys[kid] = k
	}
	return st, keys, nil
}

func (d keyDir) readKey(kid string) (signingKey, error) {
	path := filepath.Join(d.dir, kid+".pem")
	if err := checkPrivateFile(path); err != nil {
		return signingKey{}, err
	}
	b, err := readSmall(path)
	if err != nil {
		return signingKey{}, fmt.Errorf("issuer: key %s: %w", kid, err)
	}
	v := secret.Adopt(b)
	defer v.Wipe()
	keys, err := parseKeys(v)
	if err != nil {
		return signingKey{}, fmt.Errorf("issuer: key %s: %w", kid, err)
	}
	if len(keys) != 1 || keys[0].kid != kid {
		return signingKey{}, fmt.Errorf("issuer: key file %s does not hold the key it is named for", path)
	}
	return keys[0], nil
}

// newKey generates and writes a key file, returning the key.
func (d keyDir) newKey() (signingKey, error) {
	priv, err := d.generate()
	if err != nil {
		return signingKey{}, fmt.Errorf("issuer: generate key: %w", err)
	}
	k := newSigningKey(priv)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return signingKey{}, fmt.Errorf("issuer: encode key: %w", err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	secret.WipeBytes(der)
	defer secret.WipeBytes(p)
	if err := writeAtomic(filepath.Join(d.dir, k.kid+".pem"), p); err != nil {
		return signingKey{}, err
	}
	return k, nil
}

// save commits st and removes key files st no longer names.
func (d keyDir) save(st diskState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(d.dir, stateFile), append(b, '\n')); err != nil {
		return err
	}
	keep := map[string]bool{st.Current: true, st.Next: true}
	for _, r := range st.Retiring {
		keep[r.Kid] = true
	}
	// keys.json is committed; a key file left behind by a failed listing
	// is removed on the next save.
	ents, _ := os.ReadDir(d.dir)
	for _, e := range ents {
		kid, ok := strings.CutSuffix(e.Name(), ".pem")
		if ok && kidPattern.MatchString(kid) && !keep[kid] {
			_ = os.Remove(filepath.Join(d.dir, e.Name()))
		}
	}
	return nil
}

func checkPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("issuer: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("issuer: %s is accessible to group or others (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is inside the configured key directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		secret.WipeBytes(b)
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	return b, nil
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("issuer: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("issuer: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("issuer: write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	ok = true
	return nil
}
