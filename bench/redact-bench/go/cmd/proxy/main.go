// proxy: minimal redacting proxy (net/http). Redacts the request body, forwards it,
// restores the streamed SSE response chunk by chunk.
package main

import (
	"bytes"
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"redactbench/redact"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18101", "listen")
	upstream := flag.String("upstream", "http://127.0.0.1:18100", "upstream base URL")
	secretsF := flag.String("secrets", "", "secrets json")
	engine := flag.String("engine", "petar-nfa", "AC engine")
	flag.Parse()
	secrets, key, err := redact.LoadSecrets(*secretsF)
	if err != nil {
		log.Fatal(err)
	}
	t0 := time.Now()
	red, err := redact.NewRedactor(secrets, key, *engine)
	if err != nil {
		log.Fatal(err)
	}
	table := redact.NewTable(secrets, key)
	log.Printf("automaton %s built in %v", *engine, time.Since(t0))

	client := &http.Client{Transport: &http.Transport{
		MaxIdleConns: 4096, MaxIdleConnsPerHost: 4096, MaxConnsPerHost: 0,
		DisableCompression: true, IdleConnTimeout: 90 * time.Second,
		WriteBufferSize: 64 << 10, ReadBufferSize: 64 << 10,
	}}
	inPool := sync.Pool{New: func() any { return new(bytes.Buffer) }}
	outPool := sync.Pool{New: func() any { b := make([]byte, 0, 4<<20); return &b }}
	rdPool := sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}
	wrPool := sync.Pool{New: func() any { b := make([]byte, 0, 64<<10); return &b }}
	resPool := sync.Pool{New: func() any { return redact.NewRestorer(table) }}

	http.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		in := inPool.Get().(*bytes.Buffer)
		in.Reset()
		defer inPool.Put(in)
		if r.ContentLength > 0 {
			in.Grow(int(r.ContentLength))
		}
		if _, err := in.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ob := outPool.Get().(*[]byte)
		body, _ := red.Redact(*ob, in.Bytes())
		req, _ := http.NewRequestWithContext(r.Context(), "POST", *upstream+"/v1/messages", bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("content-type", "application/json")
		resp, err := client.Do(req)
		defer func() {
			if len(body) > 0 && (in.Len() == 0 || &body[0] != &in.Bytes()[0]) {
				*ob = body[:0]
			}
			outPool.Put(ob)
		}()
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("content-type", resp.Header.Get("content-type"))
		w.WriteHeader(resp.StatusCode)
		fl := w.(http.Flusher)
		rs := resPool.Get().(*redact.Restorer)
		rs.Reset()
		defer resPool.Put(rs)
		rb := rdPool.Get().(*[]byte)
		defer rdPool.Put(rb)
		wb := wrPool.Get().(*[]byte)
		defer wrPool.Put(wb)
		for {
			n, err := resp.Body.Read(*rb)
			if n > 0 {
				*wb = rs.Feed((*wb)[:0], (*rb)[:n])
				if len(*wb) > 0 {
					if _, werr := w.Write(*wb); werr != nil {
						return
					}
					fl.Flush()
				}
			}
			if err != nil {
				break
			}
		}
		*wb = rs.Finish((*wb)[:0])
		if len(*wb) > 0 {
			w.Write(*wb)
		}
	})
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("go proxy on %s -> %s", *listen, *upstream)
	log.Fatal(srv.ListenAndServe())
}
