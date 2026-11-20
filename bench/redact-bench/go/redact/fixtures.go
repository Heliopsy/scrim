package redact

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// LoadSecrets reads fixtures/data/secrets-N.json.
func LoadSecrets(path string) ([][]byte, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f struct {
		Key     string   `json:"hmac_key_hex"`
		Secrets []string `json:"secrets"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, err
	}
	key, err := hex.DecodeString(f.Key)
	if err != nil {
		return nil, nil, err
	}
	out := make([][]byte, len(f.Secrets))
	for i, s := range f.Secrets {
		out[i] = []byte(s)
	}
	return out, key, nil
}

// LoadChunks reads a .chunks file (one size per line) and slices data accordingly.
func LoadChunks(path string, data []byte) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	off := 0
	for _, l := range strings.Fields(string(b)) {
		n, err := strconv.Atoi(l)
		if err != nil {
			return nil, err
		}
		out = append(out, data[off:off+n])
		off += n
	}
	return out, nil
}
