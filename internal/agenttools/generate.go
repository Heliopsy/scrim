// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/heliopsy/scrim/internal/secret"
)

// Generated value formats.
const (
	FormatChars      = "chars"
	FormatHex        = "hex"
	FormatBase64     = "base64"
	FormatBase64URL  = "base64url"
	FormatUUID       = "uuid"
	FormatPassphrase = "passphrase"
)

// Character sets for FormatChars.
const (
	CharsetAlnum        = "alnum"
	CharsetAlnumSymbols = "alnum-symbols"
	CharsetAlpha        = "alpha"
	CharsetLower        = "lower"
	CharsetDigits       = "digits"
)

// Generation bounds.
const (
	DefaultLength = 32
	MinLength     = 8
	MaxLength     = 4096
	DefaultWords  = 6
	MinWords      = 4
	MaxWords      = 64
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!#%+-.:=@^_~"
)

var alphabets = map[string]string{
	CharsetAlnum:        lower + upper + digits,
	CharsetAlnumSymbols: lower + upper + digits + symbols,
	CharsetAlpha:        lower + upper,
	CharsetLower:        lower,
	CharsetDigits:       digits,
	FormatHex:           "0123456789abcdef",
	FormatBase64:        upper + lower + digits + "+/",
	FormatBase64URL:     upper + lower + digits + "-_",
}

// effWords is the EFF large wordlist (7,776 words, 12.9 bits per word),
// published by the Electronic Frontier Foundation under CC BY 3.0 US.
//
//go:embed eff_large_wordlist.txt
var effWords string

var words = sync.OnceValue(func() []string { return strings.Fields(effWords) })

// GenSpec is a normalised generation request.
type GenSpec struct {
	Format    string
	Length    int
	Charset   string
	Words     int
	Separator string
}

// NormalizeGen checks a secret_gen input and fills in the defaults.
func NormalizeGen(in GenInput) (GenSpec, error) {
	s := GenSpec{Format: in.Format, Length: in.Length, Charset: in.Charset, Words: in.Words, Separator: in.Separator}
	if s.Format == "" {
		s.Format = FormatChars
	}
	switch s.Format {
	case FormatChars, FormatHex, FormatBase64, FormatBase64URL:
		if s.Length == 0 {
			s.Length = DefaultLength
		}
		if s.Length < MinLength || s.Length > MaxLength {
			return GenSpec{}, Errorf(CodeInvalid, "length must be between %d and %d", MinLength, MaxLength)
		}
		if s.Format == FormatChars {
			if s.Charset == "" {
				s.Charset = CharsetAlnum
			}
			if _, ok := alphabets[s.Charset]; !ok || s.Charset == FormatHex || strings.HasPrefix(s.Charset, "base64") {
				return GenSpec{}, Errorf(CodeInvalid, "charset must be alnum, alnum-symbols, alpha, lower or digits")
			}
		} else if s.Charset != "" {
			return GenSpec{}, Errorf(CodeInvalid, "charset applies to the chars format only")
		}
		if s.Words != 0 || s.Separator != "" {
			return GenSpec{}, Errorf(CodeInvalid, "words and separator apply to the passphrase format only")
		}
	case FormatUUID:
		if s.Length != 0 || s.Charset != "" || s.Words != 0 || s.Separator != "" {
			return GenSpec{}, Errorf(CodeInvalid, "the uuid format takes no length, charset, words or separator")
		}
		s.Length = 36
	case FormatPassphrase:
		if s.Length != 0 || s.Charset != "" {
			return GenSpec{}, Errorf(CodeInvalid, "the passphrase format takes words, not length or charset")
		}
		if s.Words == 0 {
			s.Words = DefaultWords
		}
		if s.Words < MinWords || s.Words > MaxWords {
			return GenSpec{}, Errorf(CodeInvalid, "words must be between %d and %d", MinWords, MaxWords)
		}
		if s.Separator == "" {
			s.Separator = "-"
		}
		if len(s.Separator) > 4 || strings.ContainsAny(s.Separator, "\x00\r\n\t") {
			return GenSpec{}, Errorf(CodeInvalid, "separator must be at most 4 printable bytes")
		}
	default:
		return GenSpec{}, Errorf(CodeInvalid, "format must be chars, hex, base64, base64url, uuid or passphrase")
	}
	return s, nil
}

// Generate makes a value from spec using r, normally crypto/rand. Every
// character is drawn uniformly; there is no modulo bias.
func Generate(spec GenSpec, r io.Reader) (secret.Value, error) {
	if r == nil {
		r = rand.Reader
	}
	switch spec.Format {
	case FormatUUID:
		b := make([]byte, 16)
		defer secret.WipeBytes(b)
		if _, err := io.ReadFull(r, b); err != nil {
			return secret.Value{}, fmt.Errorf("agenttools: reading randomness: %w", err)
		}
		b[6] = b[6]&0x0f | 0x40 // version 4
		b[8] = b[8]&0x3f | 0x80 // RFC 9562 variant
		const hx = "0123456789abcdef"
		out := make([]byte, 0, 36)
		for i, c := range b {
			if i == 4 || i == 6 || i == 8 || i == 10 {
				out = append(out, '-')
			}
			out = append(out, hx[c>>4], hx[c&0x0f])
		}
		return secret.Adopt(out), nil
	case FormatPassphrase:
		list := words()
		var out []byte
		for i := range spec.Words {
			n, err := rand.Int(r, big.NewInt(int64(len(list))))
			if err != nil {
				secret.WipeBytes(out)
				return secret.Value{}, fmt.Errorf("agenttools: reading randomness: %w", err)
			}
			if i > 0 {
				out = append(out, spec.Separator...)
			}
			out = append(out, list[n.Int64()]...)
		}
		return secret.Adopt(out), nil
	default:
		alpha := alphabets[spec.Charset]
		if spec.Format != FormatChars {
			alpha = alphabets[spec.Format]
		}
		if alpha == "" || spec.Length <= 0 {
			return secret.Value{}, Errorf(CodeInvalid, "unsupported generation spec")
		}
		out := make([]byte, spec.Length)
		max := big.NewInt(int64(len(alpha)))
		for i := range out {
			n, err := rand.Int(r, max)
			if err != nil {
				secret.WipeBytes(out)
				return secret.Value{}, fmt.Errorf("agenttools: reading randomness: %w", err)
			}
			out[i] = alpha[n.Int64()]
		}
		return secret.Adopt(out), nil
	}
}
