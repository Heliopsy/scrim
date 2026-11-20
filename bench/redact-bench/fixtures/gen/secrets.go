package main

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strings"
)

const (
	base62   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64std   = base62 + "+/"
	b64url   = base62 + "-_"
	base32up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	pwChars  = base62 + "!@#$%^&*/\"\\"
)

var nonASCII = []string{"é", "ü", "ß", "€", "ø", "ñ", "Ж", "😀"}

func randStr(r *rand.Rand, alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.IntN(len(alpha))]
	}
	return string(b)
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

var kinds = []string{"ghp", "github_pat", "sk-ant", "akia", "aws_secret", "b62_32", "b62_48", "b62_64", "jwt", "pem", "password"}

var smallKinds = []string{"ghp", "github_pat", "sk-ant", "akia", "aws_secret", "b62_32", "b62_64", "jwt", "pem", "password"}

// weights per kind for large sets (sum 1000)
var kindWeights = []int{150, 100, 100, 100, 100, 85, 85, 80, 80, 20, 100}

func genSecret(r *rand.Rand, kind string) string {
	switch kind {
	case "ghp":
		return "ghp_" + randStr(r, base62, 36)
	case "github_pat":
		return "github_pat_" + randStr(r, base62, 22) + "_" + randStr(r, base62, 59)
	case "sk-ant":
		return "sk-ant-api03-" + randStr(r, b64url, 91) + "AA"
	case "akia":
		return "AKIA" + randStr(r, base32up, 16)
	case "aws_secret":
		return randStr(r, b64std, 40)
	case "b62_32":
		return randStr(r, base62, 32)
	case "b62_48":
		return randStr(r, base62, 48)
	case "b62_64":
		return randStr(r, base62, 64)
	case "jwt":
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"user-%d","iat":%d,"scope":"%s"}`, r.IntN(1e6), 1700000000+r.IntN(1e8), randStr(r, base62, 12))))
		s := base64.RawURLEncoding.EncodeToString(randBytes(r, 32))
		return h + "." + p + "." + s
	case "pem":
		body := base64.StdEncoding.EncodeToString(randBytes(r, 1218))
		var sb strings.Builder
		sb.WriteString("-----BEGIN PRIVATE KEY-----\n")
		for i := 0; i < len(body); i += 64 {
			e := min(i+64, len(body))
			sb.WriteString(body[i:e])
			sb.WriteByte('\n')
		}
		sb.WriteString("-----END PRIVATE KEY-----")
		return sb.String()
	case "password":
		s := []byte(randStr(r, pwChars, 8))
		if r.IntN(5) == 0 {
			i := r.IntN(8)
			return string(s[:i]) + nonASCII[r.IntN(len(nonASCII))] + string(s[i+1:])
		}
		return string(s)
	}
	panic(kind)
}

func genSecrets(seed uint64, n int) []string {
	r := rand.New(rand.NewPCG(seed, 1))
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if n <= len(smallKinds) {
		for i := 0; len(out) < n; i++ {
			add(genSecret(r, smallKinds[i%len(smallKinds)]))
		}
		return out
	}
	for len(out) < n {
		x := r.IntN(1000)
		k := 0
		for ; x >= kindWeights[k]; k++ {
			x -= kindWeights[k]
		}
		add(genSecret(r, kinds[k]))
	}
	return out
}
