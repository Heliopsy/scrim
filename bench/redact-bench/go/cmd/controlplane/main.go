// controlplane: Go control plane for the "combo" arm. Listens on a Unix domain socket,
// pushes the secret dictionary (values + variants, JSON) to the Rust data plane, pushes a
// diff of -diff-n changed secrets every -diff-every, receives audit events (async batches
// on the control connection, or sync per request on pooled connections) and answers
// "check grant" round trips. Writes a summary JSON on SIGTERM/SIGINT.
//
// Frame: u32 big-endian length of (type+payload), u8 type, payload (JSON).
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"redactbench/redact"
)

const (
	tHello      = 0
	tDictFull   = 1
	tDictDiff   = 2
	tAuditBatch = 3
	tAuditSync  = 4
	tAuditAck   = 5
	tGrantReq   = 6
	tGrantReply = 7
	tDictAck    = 8
)

type pushedSecret struct {
	ID       int      `json:"id"`
	Value    string   `json:"value"`
	Variants []string `json:"variants"`
}

type dictMsg struct {
	Version         int            `json:"version"`
	KeyHex          string         `json:"key_hex,omitempty"`
	AllowedProvider string         `json:"allowed_provider,omitempty"`
	Secrets         []pushedSecret `json:"secrets"`
}

type ack struct {
	Version    int     `json:"version"`
	Full       bool    `json:"full"`
	Bytes      int     `json:"bytes"`
	RecvUnixUs int64   `json:"recv_unix_us"`
	SwapUnixUs int64   `json:"swap_unix_us"`
	DecodeMs   float64 `json:"decode_ms"`
	BuildMs    float64 `json:"build_ms"`
	Patterns   int     `json:"patterns"`
}

type push struct {
	Version    int     `json:"version"`
	Full       bool    `json:"full"`
	Secrets    int     `json:"secrets"`
	Bytes      int     `json:"bytes"`
	EncodeMs   float64 `json:"encode_ms"`
	SendUnixUs int64   `json:"send_unix_us"`
	Ack        *ack    `json:"ack,omitempty"`
	SyncMs     float64 `json:"sync_ms"` // send start -> new automaton live in data plane
}

type auditEv struct {
	TsUs     int64 `json:"ts_us"`
	TotalUs  int64 `json:"t_total_us"`
	GrantUs  int64 `json:"t_grant_us"`
	Drops    int64 `json:"drops"`
	Matches  int   `json:"matches"`
	DictV    int   `json:"dict_v"`
	BytesIn  int   `json:"bytes_in"`
	BytesOut int   `json:"bytes_out"`
}

type cp struct {
	mu                sync.Mutex
	pushes            []*push
	events            []auditEv
	asyncEvents       atomic.Int64
	syncEvents        atomic.Int64
	grants            atomic.Int64
	batches           atomic.Int64
	bytesIn, bytesOut atomic.Int64
	start             time.Time
	firstEv, lastEv   atomic.Int64
	maxDrops          atomic.Int64
}

func writeFrame(w io.Writer, t byte, p []byte) error {
	var h [5]byte
	binary.BigEndian.PutUint32(h[:4], uint32(len(p)+1))
	h[4] = t
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	p := make([]byte, binary.BigEndian.Uint32(h[:4])-1)
	_, err := io.ReadFull(r, p)
	return h[4], p, err
}

func entry(id int, v []byte) pushedSecret {
	vs := redact.Variants(v)
	out := pushedSecret{ID: id, Value: string(v), Variants: make([]string, len(vs))}
	for i, x := range vs {
		out.Variants[i] = string(x)
	}
	return out
}

const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func (c *cp) record(ev auditEv) {
	now := time.Now().UnixMicro()
	c.firstEv.CompareAndSwap(0, now)
	c.lastEv.Store(now)
	if ev.Drops > c.maxDrops.Load() {
		c.maxDrops.Store(ev.Drops)
	}
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func (c *cp) control(conn net.Conn, secrets [][]byte, key []byte, diffEvery time.Duration, diffN int) {
	w := bufio.NewWriterSize(conn, 1<<20)
	var wmu sync.Mutex
	send := func(full bool, version int, entries []pushedSecret, keyHex string) {
		t := time.Now()
		b, _ := json.Marshal(dictMsg{Version: version, KeyHex: keyHex, AllowedProvider: "anthropic", Secrets: entries})
		p := &push{Version: version, Full: full, Secrets: len(entries), Bytes: len(b),
			EncodeMs: float64(time.Since(t).Microseconds()) / 1000, SendUnixUs: time.Now().UnixMicro()}
		c.mu.Lock()
		c.pushes = append(c.pushes, p)
		c.mu.Unlock()
		typ := byte(tDictDiff)
		if full {
			typ = tDictFull
		}
		wmu.Lock()
		writeFrame(w, typ, b)
		w.Flush()
		wmu.Unlock()
		c.bytesOut.Add(int64(len(b) + 5))
	}
	// full dictionary: the 10k fixture secrets plus diffN rotating slots
	rng := rand.New(rand.NewPCG(7, 7))
	rot := func() []pushedSecret {
		es := make([]pushedSecret, diffN)
		for i := range es {
			v := make([]byte, 40)
			for j := range v {
				v[j] = base62[rng.IntN(len(base62))]
			}
			es[i] = entry(len(secrets)+i, append([]byte("ghp_"), v[:36]...))
		}
		return es
	}
	all := make([]pushedSecret, 0, len(secrets)+diffN)
	for i, s := range secrets {
		all = append(all, entry(i, s))
	}
	all = append(all, rot()...)
	send(true, 1, all, hex.EncodeToString(key))
	go func() {
		if diffEvery <= 0 {
			return
		}
		v := 1
		for range time.Tick(diffEvery) {
			v++
			send(false, v, rot(), "")
		}
	}()
	r := bufio.NewReaderSize(conn, 1<<20)
	for {
		t, p, err := readFrame(r)
		if err != nil {
			return
		}
		c.bytesIn.Add(int64(len(p) + 5))
		switch t {
		case tAuditBatch:
			c.batches.Add(1)
			for _, line := range bytes.Split(p, []byte("\n")) {
				var ev auditEv
				if json.Unmarshal(line, &ev) == nil {
					c.asyncEvents.Add(1)
					c.record(ev)
				}
			}
		case tDictAck:
			var a ack
			json.Unmarshal(p, &a)
			c.mu.Lock()
			for _, ps := range c.pushes {
				if ps.Version == a.Version {
					ps.Ack = &a
					ps.SyncMs = float64(a.SwapUnixUs-ps.SendUnixUs) / 1000
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *cp) syncConn(conn net.Conn) {
	r := bufio.NewReader(conn)
	for {
		t, p, err := readFrame(r)
		if err != nil {
			return
		}
		c.bytesIn.Add(int64(len(p) + 5))
		switch t {
		case tAuditSync:
			var ev auditEv
			if json.Unmarshal(p, &ev) == nil {
				c.syncEvents.Add(1)
				c.record(ev)
			}
			writeFrame(conn, tAuditAck, []byte(`{"ok":true}`))
		case tGrantReq:
			var q map[string]any
			json.Unmarshal(p, &q)
			c.grants.Add(1)
			writeFrame(conn, tGrantReply, []byte(`{"allow":true,"ttl_s":60}`))
		}
		c.bytesOut.Add(16)
	}
}

func pct(xs []int64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	i := int(q * float64(len(xs)-1))
	return float64(xs[i]) / 1000
}

func (c *cp) summary() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	// rebuild windows: [recv, swap] of every diff; an event is "during rebuild" if its request overlapped one
	type win struct{ a, b int64 }
	var wins []win
	for _, p := range c.pushes {
		if !p.Full && p.Ack != nil {
			wins = append(wins, win{p.Ack.RecvUnixUs, p.Ack.SwapUnixUs})
		}
	}
	var in, out []int64
	var grant []int64
	for _, e := range c.events {
		s := e.TsUs - e.TotalUs
		hit := false
		for _, w := range wins {
			if s <= w.b && e.TsUs >= w.a {
				hit = true
				break
			}
		}
		if hit {
			in = append(in, e.TotalUs)
		} else {
			out = append(out, e.TotalUs)
		}
		if e.GrantUs > 0 {
			grant = append(grant, e.GrantUs)
		}
	}
	for _, xs := range [][]int64{in, out, grant} {
		sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	}
	lat := func(xs []int64) map[string]any {
		return map[string]any{"n": len(xs), "p50_ms": pct(xs, .5), "p99_ms": pct(xs, .99), "p999_ms": pct(xs, .999)}
	}
	span := float64(c.lastEv.Load()-c.firstEv.Load()) / 1e6
	var full *push
	var diffs []*push
	for _, p := range c.pushes {
		if p.Full {
			full = p
		} else {
			diffs = append(diffs, p)
		}
	}
	return map[string]any{
		"uptime_s":                time.Since(c.start).Seconds(),
		"async_events":            c.asyncEvents.Load(),
		"sync_events":             c.syncEvents.Load(),
		"grant_checks":            c.grants.Load(),
		"audit_batches":           c.batches.Load(),
		"dp_reported_drops":       c.maxDrops.Load(),
		"uds_bytes_in":            c.bytesIn.Load(),
		"uds_bytes_out":           c.bytesOut.Load(),
		"event_span_s":            span,
		"uds_in_MBps":             float64(c.bytesIn.Load()) / 1e6 / max(span, 1e-9),
		"events_per_s":            float64(c.asyncEvents.Load()+c.syncEvents.Load()) / max(span, 1e-9),
		"full_push":               full,
		"diff_pushes":             diffs,
		"latency_during_rebuild":  lat(in),
		"latency_outside_rebuild": lat(out),
		"grant_rtt":               lat(grant),
	}
}

func main() {
	sock := flag.String("sock", "", "unix socket path")
	secretsF := flag.String("secrets", "", "secrets json")
	diffEvery := flag.Duration("diff-every", 2*time.Second, "diff push interval (0 = off)")
	diffN := flag.Int("diff-n", 100, "changed secrets per diff")
	out := flag.String("out", "", "summary json path")
	flag.Parse()
	secrets, key, err := redact.LoadSecrets(*secretsF)
	if err != nil {
		log.Fatal(err)
	}
	os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	c := &cp{start: time.Now()}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		b, _ := json.MarshalIndent(c.summary(), "", " ")
		if *out != "" {
			os.WriteFile(*out, b, 0o644)
		} else {
			fmt.Println(string(b))
		}
		os.Remove(*sock)
		os.Exit(0)
	}()
	log.Printf("control plane on %s (%d secrets, diff %d every %v)", *sock, len(secrets), *diffN, *diffEvery)
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			t, p, err := readFrame(conn)
			if err != nil || t != tHello {
				conn.Close()
				return
			}
			if bytes.Contains(p, []byte(`"control"`)) {
				c.control(conn, secrets, key, *diffEvery, *diffN)
			} else {
				c.syncConn(conn)
			}
		}()
	}
}
