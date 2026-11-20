package redact

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixtures() string {
	if d := os.Getenv("RB_FIXTURES"); d != "" {
		return d
	}
	return "../../fixtures/data"
}

var (
	cacheMu   sync.Mutex
	redactors = map[string]*Redactor{}
	secretSet = map[int][][]byte{}
	hmacKey   []byte
)

func secretsN(tb testing.TB, n int) [][]byte {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if s, ok := secretSet[n]; ok {
		return s
	}
	s, k, err := LoadSecrets(filepath.Join(fixtures(), fmt.Sprintf("secrets-%d.json", n)))
	if err != nil {
		tb.Skip("fixtures missing; run `just fixtures`: ", err)
	}
	secretSet[n], hmacKey = s, k
	return s
}

func redactor(tb testing.TB, engine string, n int) *Redactor {
	s := secretsN(tb, n)
	key := fmt.Sprintf("%s/%d", engine, n)
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if r, ok := redactors[key]; ok {
		return r
	}
	r, err := NewRedactor(s, hmacKey, engine)
	if err != nil {
		tb.Fatal(err)
	}
	redactors[key] = r
	return r
}

func read(tb testing.TB, name string) []byte {
	b, err := os.ReadFile(filepath.Join(fixtures(), name))
	if err != nil {
		tb.Skip("fixtures missing; run `just fixtures`")
	}
	return b
}

// engines usable for a given set size (DFA builds do not fit in RAM at 10k secrets).
func enginesFor(n int) []string {
	e := strings.Fields(os.Getenv("RB_GO_ENGINES"))
	if len(e) == 0 {
		e = []string{"petar-nfa", "pgavlin-nfa", "petar-dfa", "coregx"}
	}
	if n >= 10000 {
		var out []string
		for _, x := range e {
			if strings.HasSuffix(x, "-nfa") {
				out = append(out, x)
			}
		}
		return out
	}
	return e
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1<<20); return &b }}

func BenchmarkRedact(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		for _, eng := range enginesFor(n) {
			for _, size := range []string{"100k", "1m", "4m"} {
				for _, kind := range []string{"hits", "clean"} {
					name := fmt.Sprintf("body-%s-s%d.json", size, n)
					if kind == "clean" {
						name = fmt.Sprintf("body-%s-clean.json", size)
					}
					b.Run(fmt.Sprintf("engine=%s/set=%d/size=%s/%s", eng, n, size, kind), func(b *testing.B) {
						body := read(b, name)
						r := redactor(b, eng, n)
						b.SetBytes(int64(len(body)))
						b.ReportAllocs()
						b.ResetTimer()
						for b.Loop() {
							bp := bufPool.Get().(*[]byte)
							out, _ := r.Redact(*bp, body)
							if len(out) > 0 && &out[0] != &body[0] {
								*bp = out[:0]
							}
							bufPool.Put(bp)
						}
					})
				}
			}
		}
	}
}

func BenchmarkRestore(b *testing.B) {
	s := secretsN(b, 1000)
	t := NewTable(s, hmacKey)
	for _, st := range []string{"2k", "20k"} {
		b.Run("stream="+st, func(b *testing.B) {
			data := read(b, "stream-"+st+".sse")
			chunks, err := LoadChunks(filepath.Join(fixtures(), "stream-"+st+".chunks"), data)
			if err != nil {
				b.Fatal(err)
			}
			r := NewRestorer(t)
			out := make([]byte, 0, 64<<10)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				r.Reset()
				for _, c := range chunks {
					out = r.Feed(out[:0], c) // a proxy writes each output chunk and reuses the buffer
				}
				out = r.Finish(out[:0])
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(chunks))/1000, "us/chunk")
		})
	}
}

func BenchmarkBuild(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		for _, eng := range enginesFor(n) {
			b.Run(fmt.Sprintf("engine=%s/set=%d", eng, n), func(b *testing.B) {
				s := secretsN(b, n)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := NewRedactor(s, hmacKey, eng); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// --- unit tests (small, self-contained)

func TestEscape(t *testing.T) {
	got := AppendJSONEscaped(nil, []byte("a/\"\\\n\x01é"), false, false)
	if string(got) != `a/\"\\\n\u0001é` {
		t.Fatalf("%q", got)
	}
	got = AppendJSONEscaped(nil, []byte("é😀/"), true, true)
	if string(got) != "\\u00e9\\ud83d\\ude00\\/" {
		t.Fatalf("%q", got)
	}
}

func TestSplitPlaceholder(t *testing.T) {
	key := []byte("k")
	sec := [][]byte{[]byte("s3cr3t-value-123")}
	ph := string(Placeholder(key, sec[0]))
	a, c := ph[:10], ph[10:]
	sse := `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x` + a + `"}}` + "\n\n" +
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + c + `y"}}` + "\n\n" +
		`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n"
	r := NewRestorer(NewTable(sec, key))
	var out []byte
	for i := 0; i < len(sse); i += 7 {
		out = r.Feed(out, []byte(sse[i:min(i+7, len(sse))]))
	}
	out = r.Finish(out)
	if !bytes.Contains(out, []byte(`"text":"x"`)) || !bytes.Contains(out, []byte("s3cr3t-value-123y")) {
		t.Fatalf("%s", out)
	}
}

func TestRedactRoundtrip(t *testing.T) {
	key := []byte("k")
	sec := [][]byte{[]byte("ghp_abcdefghijklmnopqrstuvwxyz0123456789")}
	for _, e := range []string{"petar-nfa", "petar-dfa", "pgavlin-nfa", "coregx"} {
		r, err := NewRedactor(sec, key, e)
		if err != nil {
			t.Fatal(err)
		}
		out, n := r.Redact(nil, []byte(`{"t":"token ghp_abcdefghijklmnopqrstuvwxyz0123456789 end"}`))
		if n != 1 || r.Count(out) != 0 {
			t.Fatalf("%s: n=%d out=%s", e, n, out)
		}
	}
}
