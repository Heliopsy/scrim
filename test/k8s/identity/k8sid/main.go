// SPDX-License-Identifier: AGPL-3.0-only

// Command k8sid is the in-cluster half of the Kubernetes identity test
// (test/k8s/identity/run.sh): a fake tool API that accepts only the two
// generated credentials, and an agent client that calls it through scrim's
// forward proxy with the pod's projected service account token as the
// password of the proxy user k8s.
//
//	k8sid fakeapi                      serve HTTPS on :8443 (TLS_CERT, TLS_KEY, KEY_A, KEY_B)
//	k8sid agent METHOD URL PLACEHOLDER call URL through $PROXY_HOST with Authorization: Bearer PLACEHOLDER
//	k8sid sleep                        wait forever (agent pods)
//
// The agent prints one line, `status=<code> body=<body>`. Neither side ever
// prints a credential or a token.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: k8sid fakeapi | agent METHOD URL PLACEHOLDER | sleep")
	}
	switch os.Args[1] {
	case "fakeapi":
		fakeAPI()
	case "agent":
		if len(os.Args) != 5 {
			fail("usage: k8sid agent METHOD URL PLACEHOLDER")
		}
		agent(os.Args[2], os.Args[3], os.Args[4])
	case "sleep":
		// Block until the pod is stopped (a bare select{} would trip Go's
		// deadlock detector, since nothing else runs).
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
	default:
		fail("unknown command " + os.Args[1])
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "k8sid:", msg)
	os.Exit(2)
}

// fakeAPI answers 200 with the name of the credential it received ("a" or
// "b"), 401 for anything else, and logs which one it saw.
func fakeAPI() {
	keys := map[string]string{"Bearer " + os.Getenv("KEY_A"): "a", "Bearer " + os.Getenv("KEY_B"): "b"}
	if os.Getenv("KEY_A") == "" || os.Getenv("KEY_B") == "" {
		fail("KEY_A and KEY_B must be set")
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := keys[r.Header.Get("Authorization")]
		if !ok {
			fmt.Fprintf(os.Stderr, "fakeapi: %s %s refused (no known credential)\n", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "unauthorized")
			return
		}
		fmt.Fprintf(os.Stderr, "fakeapi: %s %s with credential %s\n", r.Method, r.URL.Path, who)
		_, _ = io.WriteString(w, who)
	})
	srv := &http.Server{Addr: ":8443", Handler: h, ReadHeaderTimeout: 10 * time.Second}
	fail(srv.ListenAndServeTLS(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")).Error())
}

// agent sends one request through scrim. The token file and the proxy are
// read from TOKEN_FILE (default the projected scrim-audience token) and
// PROXY_HOST; the CA scrim's tool proxy signs with from SCRIM_CA.
func agent(method, target, placeholder string) {
	tokFile := os.Getenv("TOKEN_FILE")
	if tokFile == "" {
		tokFile = "/var/run/secrets/tokens/scrim"
	}
	tok, err := os.ReadFile(tokFile) // #nosec G304 -- test helper
	if err != nil {
		fail("reading the token file: " + err.Error())
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(os.Getenv("SCRIM_CA")) // #nosec G304 -- test helper
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		fail("reading SCRIM_CA")
	}
	proxy := &url.URL{Scheme: "http", User: url.UserPassword("k8s", strings.TrimSpace(string(tok))), Host: os.Getenv("PROXY_HOST")}
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	req, err := http.NewRequest(method, target, strings.NewReader(""))
	if err != nil {
		fail("bad request")
	}
	req.Header.Set("Authorization", "Bearer "+placeholder)
	resp, err := c.Do(req)
	if err != nil {
		// The error can quote the proxy URL; name the failure only.
		_, _ = fmt.Fprintln(os.Stdout, "status=0 body=transport error")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	_, _ = fmt.Fprintf(os.Stdout, "status=%d body=%s\n", resp.StatusCode, strings.ReplaceAll(string(b), "\n", " "))
}
