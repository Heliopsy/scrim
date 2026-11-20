// SPDX-License-Identifier: AGPL-3.0-only

package vwtest

import (
	"io"
	"net"
	"sync"
	"testing"
)

// Proxy is a TCP proxy in front of a server that can simulate an outage:
// while down, it refuses new connections and drops open ones.
type Proxy struct {
	URL string

	mu     sync.Mutex
	down   bool
	conns  map[net.Conn]struct{}
	target string
}

// NewProxy proxies to target (host:port) and returns the proxy's URL.
func NewProxy(t testing.TB, target string) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{URL: "http://" + ln.Addr().String(), conns: map[net.Conn]struct{}{}, target: target}
	t.Cleanup(func() { _ = ln.Close(); p.SetDown(true) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	if !p.track(c) {
		return
	}
	u, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer func() { _ = u.Close() }()
	if !p.track(u) {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(u, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, u); done <- struct{}{} }()
	<-done
}

// SetDown starts or ends the simulated outage.
func (p *Proxy) SetDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
	if down {
		for c := range p.conns {
			_ = c.Close()
		}
		clear(p.conns)
	}
}
