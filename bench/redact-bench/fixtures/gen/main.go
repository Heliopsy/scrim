// Command gen writes all deterministic synthetic fixtures into fixtures/data.
// Nothing here is a real secret.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const seed = 20261120

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type manifest struct {
	Seed     int                       `json:"seed"`
	Files    map[string]string         `json:"sha256"`
	Bodies   map[string]map[string]any `json:"bodies"`
	Secrets  map[string]map[string]any `json:"secret_sets"`
	Streams  map[string]map[string]any `json:"streams"`
	KeyHex   string                    `json:"hmac_key_hex"`
	MaxPHLen int                       `json:"max_placeholder_len"`
}

func main() {
	out := flag.String("out", "data", "output dir")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))
	m := manifest{Seed: seed, Files: map[string]string{}, Bodies: map[string]map[string]any{},
		Secrets: map[string]map[string]any{}, Streams: map[string]map[string]any{}}
	write := func(name string, b []byte) {
		must(os.WriteFile(filepath.Join(*out, name), b, 0o644))
		h := sha256.Sum256(b)
		m.Files[name] = hex.EncodeToString(h[:])
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 13) // fixed synthetic HMAC key
	}
	m.KeyHex = hex.EncodeToString(key)
	m.MaxPHLen = len(placeholder(key, "x"))

	sets := map[int][]string{}
	for _, n := range []int{10, 1000, 10000} {
		s := genSecrets(seed+uint64(n), n)
		sets[n] = s
		j, _ := json.Marshal(map[string]any{"hmac_key_hex": m.KeyHex, "secrets": s})
		write(fmt.Sprintf("secrets-%d.json", n), j)
		pats := patternList(s)
		var sb strings.Builder
		tot := 0
		for _, p := range pats {
			fmt.Fprintf(&sb, "%d\t%s\n", p.secret, hex.EncodeToString([]byte(p.bytes)))
			tot += len(p.bytes)
		}
		write(fmt.Sprintf("secrets-%d.patterns.txt", n), []byte(sb.String()))
		m.Secrets[fmt.Sprint(n)] = map[string]any{"secrets": len(s), "patterns": len(pats), "pattern_bytes": tot}
	}

	sizes := []struct {
		name string
		n    int
	}{{"100k", 100 << 10}, {"1m", 1 << 20}, {"4m", 4 << 20}}
	for _, sz := range sizes {
		b, _ := genBody(seed+uint64(sz.n), sz.n, nil, false)
		name := fmt.Sprintf("body-%s-clean.json", sz.name)
		write(name, b)
		m.Bodies[name] = map[string]any{"bytes": len(b), "hits": 0}
		for _, n := range []int{10, 1000, 10000} {
			b, hits := genBody(seed+uint64(sz.n)+uint64(n), sz.n, sets[n], true)
			name := fmt.Sprintf("body-%s-s%d.json", sz.name, n)
			write(name, b)
			tot := 0
			for _, v := range hits {
				tot += v
			}
			m.Bodies[name] = map[string]any{"bytes": len(b), "hits": tot, "by_form": hits}
		}
	}
	// round-trip body: only JSON-string forms, so restore(redact(x)) must equal x exactly
	saved := hitForms
	hitForms = []string{"json"}
	b, hits := genBody(seed+99, 256<<10, sets[1000], true)
	hitForms = saved
	write("body-rt-s1000.json", b)
	m.Bodies["body-rt-s1000.json"] = map[string]any{"bytes": len(b), "hits": hits["json"], "by_form": hits}

	for _, st := range []struct {
		name   string
		events int
		set    int
	}{{"2k", 2000, 1000}, {"20k", 20000, 1000}, {"proxy", 300, 1000}, {"proxy-s10000", 300, 10000}} {
		sse, exp := genStream(seed+uint64(st.events), st.events, key, sets[st.set])
		chunks := genChunks(seed+uint64(st.events), len(sse))
		write("stream-"+st.name+".sse", sse)
		var cb strings.Builder
		for _, c := range chunks {
			fmt.Fprintf(&cb, "%d\n", c)
		}
		write("stream-"+st.name+".chunks", []byte(cb.String()))
		j, _ := json.MarshalIndent(exp, "", " ")
		write("stream-"+st.name+".expected.json", j)
		m.Streams[st.name] = map[string]any{"bytes": len(sse), "events": strings.Count(string(sse), "\n\n"), "chunks": len(chunks), "blocks": len(exp), "secret_set": st.set}
	}
	keys := make([]string, 0, len(m.Files))
	for k := range m.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	j, _ := json.MarshalIndent(m, "", "  ")
	must(os.WriteFile(filepath.Join(*out, "manifest.json"), j, 0o644))
	fmt.Printf("wrote %d files to %s\n", len(keys), *out)
}
