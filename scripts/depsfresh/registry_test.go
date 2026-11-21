package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Some proxy edges answer a module path that has no versions with an empty
// 200 on both @v/list and @latest. That names no version: not found, and
// not a lookup error that fails the gate.
func TestGoProxyEmpty200IsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	r := newRegistry(srv.URL, "")
	if v, found, err := r.goVersions(context.Background(), "example.com/m/v2"); err != nil || found || len(v) != 0 {
		t.Fatalf("@v/list: versions=%v found=%v err=%v", v, found, err)
	}
	if v, found, err := r.goLatestQuery(context.Background(), "example.com/m/v2"); err != nil || found || v != "" {
		t.Fatalf("@latest: version=%q found=%v err=%v", v, found, err)
	}
}
