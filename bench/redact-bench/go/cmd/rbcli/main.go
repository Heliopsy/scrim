// rbcli: run the Go implementation over fixtures (used by the cross-check).
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"redactbench/redact"
)

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		die(fmt.Errorf("usage: rbcli patterns|redact|restore ..."))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	sec := fs.String("secrets", "", "secrets json")
	in := fs.String("in", "", "input")
	out := fs.String("out", "", "output")
	chunks := fs.String("chunks", "", "chunks file")
	engine := fs.String("engine", "petar-dfa", "engine")
	fs.Parse(os.Args[2:])
	secrets, key, err := redact.LoadSecrets(*sec)
	die(err)
	switch os.Args[1] {
	case "patterns":
		pats, owner := redact.Patterns(secrets)
		w := bufio.NewWriter(os.Stdout)
		for i, p := range pats {
			fmt.Fprintf(w, "%d\t%s\n", owner[i], hex.EncodeToString(p))
		}
		w.Flush()
	case "redact":
		r, err := redact.NewRedactor(secrets, key, *engine)
		die(err)
		for _, f := range strings.Split(*in, ",") {
			body, err := os.ReadFile(f)
			die(err)
			o, n := r.Redact(nil, body)
			base := filepath.Join(*out, filepath.Base(f))
			die(os.WriteFile(base, o, 0o644))
			meta := fmt.Sprintf("{\"matches\":%d,\"remaining\":%d,\"in_bytes\":%d,\"out_bytes\":%d}\n", n, r.Count(o), len(body), len(o))
			die(os.WriteFile(strings.TrimSuffix(base, ".json")+".meta.json", []byte(meta), 0o644))
		}
	case "restore":
		t := redact.NewTable(secrets, key)
		data, err := os.ReadFile(*in)
		die(err)
		cs, err := redact.LoadChunks(*chunks, data)
		die(err)
		rs := redact.NewRestorer(t)
		var o []byte
		for _, c := range cs {
			o = rs.Feed(o, c)
		}
		o = rs.Finish(o)
		die(os.WriteFile(*out, o, 0o644))
		fmt.Printf("{\"in_bytes\":%d,\"out_bytes\":%d,\"chunks\":%d}\n", len(data), len(o), len(cs))
	case "buildmem":
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		t0 := time.Now()
		r, err := redact.NewRedactor(secrets, key, *engine)
		die(err)
		ms := float64(time.Since(t0).Microseconds()) / 1000
		runtime.GC()
		runtime.ReadMemStats(&m1)
		runtime.KeepAlive(r)
		fmt.Printf("{\"lang\":\"go\",\"engine\":%q,\"secrets\":%d,\"build_ms\":%.1f,\"retained_bytes\":%d,\"build_alloc_bytes\":%d,\"peak_rss_kb\":%d}\n",
			*engine, len(secrets), ms, int64(m1.HeapAlloc)-int64(m0.HeapAlloc), m1.TotalAlloc-m0.TotalAlloc, peakRSS())
	default:
		die(fmt.Errorf("unknown command %s", os.Args[1]))
	}
}

func peakRSS() int {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM:") {
			f := strings.Fields(l)
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}
