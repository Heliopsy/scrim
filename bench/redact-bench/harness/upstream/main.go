// upstream: fake Anthropic Messages endpoint. Discards the request body and
// streams a fixture SSE response in its recorded chunks, with optional pacing.
package main

import (
	"crypto/sha256"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18100", "listen")
	stream := flag.String("stream", "", "sse fixture")
	chunksF := flag.String("chunks", "", "chunk sizes")
	delay := flag.Duration("delay", 0, "pause between chunks")
	verbose := flag.Bool("v", false, "log sha256 of each request body")
	flag.Parse()
	data, err := os.ReadFile(*stream)
	if err != nil {
		log.Fatal(err)
	}
	cb, err := os.ReadFile(*chunksF)
	if err != nil {
		log.Fatal(err)
	}
	var chunks [][]byte
	off := 0
	for _, l := range strings.Fields(string(cb)) {
		n, _ := strconv.Atoi(l)
		chunks = append(chunks, data[off:off+n])
		off += n
	}
	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 64<<10)
		h := sha256.New()
		for {
			n, err := r.Body.Read(b)
			if *verbose {
				h.Write(b[:n])
			}
			if err != nil {
				if err != io.EOF {
					return
				}
				break
			}
		}
		if *verbose {
			log.Printf("request body sha256=%x", h.Sum(nil))
		}
		w.Header().Set("content-type", "text/event-stream")
		w.Header().Set("cache-control", "no-cache")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		for i, c := range chunks {
			if i > 0 && *delay > 0 {
				time.Sleep(*delay)
			}
			if _, err := w.Write(c); err != nil {
				return
			}
			fl.Flush()
		}
	})
	srv := &http.Server{Addr: *addr, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("upstream on %s, %d chunks, delay %v", *addr, len(chunks), *delay)
	log.Fatal(srv.ListenAndServe())
}
