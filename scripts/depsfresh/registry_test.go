package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// An empty 200 from the module proxy is a glitch: it is retried, and a
// registry that keeps answering it fails the lookup instead of passing.
func TestGetRetriesEmpty200(t *testing.T) {
	retryBase = time.Millisecond
	t.Cleanup(func() { retryBase = time.Second })

	var calls atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			return // 200, empty body
		}
		_, _ = w.Write([]byte(`{"Version":"v1.2.3"}`))
	}))
	defer flaky.Close()
	r := newRegistry(flaky.URL, "")
	body, found, err := r.get(context.Background(), flaky.URL+"/m/@latest")
	if err != nil || !found || string(body) != `{"Version":"v1.2.3"}` || calls.Load() != 2 {
		t.Fatalf("flaky: body=%q found=%v err=%v calls=%d", body, found, err, calls.Load())
	}

	empty := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer empty.Close()
	if _, found, err := r.get(context.Background(), empty.URL+"/m/@latest"); err == nil || found {
		t.Fatalf("always empty: found=%v err=%v, want an error", found, err)
	}
}
