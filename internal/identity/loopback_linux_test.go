// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package identity

import (
	"net"
	"os"
	"testing"
)

func TestLoopbackPeerOf(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		addr := "127.0.0.1:0"
		if network == "tcp6" {
			addr = "[::1]:0"
		}
		ln, err := net.Listen(network, addr)
		if err != nil {
			t.Skipf("%s: %v", network, err)
		}
		done := make(chan net.Conn, 1)
		go func() { c, _ := ln.Accept(); done <- c }()
		client, err := net.Dial(network, ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server := <-done
		p, err := LoopbackPeerOf(server)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if p.UID != uint32(os.Getuid()) || p.PID != int32(os.Getpid()) {
			t.Fatalf("%s: peer %+v, want uid %d pid %d", network, p, os.Getuid(), os.Getpid())
		}
		_ = client.Close()
		_ = server.Close()
		_ = ln.Close()
	}
}

func TestLoopbackPeerOfRefusesNonTCP(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, err := LoopbackPeerOf(a); err == nil {
		t.Fatal("a pipe has no loopback peer")
	}
}
