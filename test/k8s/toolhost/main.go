// SPDX-License-Identifier: AGPL-3.0-only

// Command toolhost is the tool API of the Kubernetes end-to-end test
// (test/k8s/e2e.sh): an HTTPS server that records the Authorization header
// of every request and echoes it back, so the test can check what scrim
// injected toward it and what the agent got in return.
//
//	toolhost -listen :8443 -cert tls.crt -key tls.key -control :8080
//
// The control listener serves GET /_received (every recorded request as JSON)
// over plain HTTP, for the test to read through the API server proxy.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type record struct {
	Host          string `json:"host"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Authorization string `json:"authorization"`
}

func main() {
	listen := flag.String("listen", ":8443", "HTTPS address")
	cert := flag.String("cert", "tls.crt", "certificate PEM")
	key := flag.String("key", "tls.key", "private key PEM")
	control := flag.String("control", ":8080", "plain HTTP address of /_received")
	flag.Parse()

	var mu sync.Mutex
	var got []record
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := record{Host: r.Host, Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization")}
		mu.Lock()
		got = append(got, rec)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"you_sent": rec.Authorization})
	})
	ctl := http.NewServeMux()
	ctl.HandleFunc("GET /_received", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})
	ctl.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	errs := make(chan error, 2)
	go func() {
		s := &http.Server{Addr: *control, Handler: ctl, ReadHeaderTimeout: 10 * time.Second}
		errs <- s.ListenAndServe()
	}()
	go func() {
		s := &http.Server{Addr: *listen, Handler: api, ReadHeaderTimeout: 10 * time.Second}
		errs <- s.ListenAndServeTLS(*cert, *key)
	}()
	fmt.Fprintln(os.Stderr, "toolhost:", <-errs)
	os.Exit(1)
}
