// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// generated returns n random bytes from a printable alphabet, so the test
// value cannot collide with framing bytes by accident.
func generated(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return b
}

func allZero(b []byte) bool { return !bytes.ContainsFunc(b, func(r rune) bool { return r != 0 }) }

// holdsPart reports whether b holds any 16-byte run of v.
func holdsPart(b, v []byte) bool {
	const run = 16
	for off := 0; off+run <= len(v); off += run / 2 {
		if bytes.Contains(b, v[off:off+run]) {
			return true
		}
	}
	return false
}

func TestWipingPoolZeroesReleasedBuffers(t *testing.T) {
	var p wipingPool
	h := p.Get(4096)
	copy(*h, generated(t, 4096))
	full := (*h)[:cap(*h)]
	*h = (*h)[:10] // gRPC may hand back a prefix: the whole capacity is wiped.
	p.Put(h)
	if !allZero(full) {
		t.Fatal("a released buffer still holds its bytes")
	}
}

func TestWipingCodecZeroesTheMarshalledBuffer(t *testing.T) {
	val := generated(t, 40)
	c := wipingCodec{pool: wipingPool{}}
	out, err := c.Marshal(&pb.Snapshot{Values: []*pb.ValueEntry{{Ref: "mem://a#b", Value: val}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !holdsPart(out[0].ReadOnlyData(), val) {
		t.Fatal("marshalled bytes do not hold the value")
	}
	data := out[0].ReadOnlyData()
	if mem.IsBelowBufferPoolingThreshold(cap(data)) {
		t.Fatalf("a %d byte marshal buffer is below gRPC's pooling threshold and would never be released", cap(data))
	}
	out.Free()
	if !allZero(data[:cap(data)]) {
		t.Fatal("the marshal buffer was not zeroed when gRPC released it")
	}
}

func TestWipingCodecZeroesReceivedBytes(t *testing.T) {
	val := generated(t, 40)
	wire, err := proto.Marshal(&pb.CaptureRequest{Id: 1, Value: val})
	if err != nil {
		t.Fatal(err)
	}
	c := wipingCodec{pool: wipingPool{}}
	for _, split := range []int{0, len(wire) / 2} {
		var in mem.BufferSlice
		var views [][]byte
		for _, part := range [][]byte{wire[:split], wire[split:]} {
			if len(part) == 0 {
				continue
			}
			b := bytes.Clone(part)
			views = append(views, b)
			in = append(in, mem.SliceBuffer(b)) // what gRPC uses below the pooling threshold
		}
		var got pb.CaptureRequest
		if err := c.Unmarshal(in, &got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.GetValue(), val) {
			t.Fatal("decoded value differs")
		}
		for _, v := range views {
			if !allZero(v) {
				t.Fatalf("received bytes (%d buffers) not zeroed after decoding", len(in))
			}
		}
	}
}

// echoPlane answers Redact with the text it got and accepts any snapshot, so
// secret bytes cross the connection both ways.
type echoPlane struct {
	pb.UnimplementedDataPlaneServer
}

func (echoPlane) Redact(_ context.Context, r *pb.RedactRequest) (*pb.RedactResponse, error) {
	return &pb.RedactResponse{Protocol: Protocol, Text: r.GetText()}, nil
}

func (echoPlane) ApplySnapshot(_ context.Context, s *pb.Snapshot) (*pb.ApplySnapshotResponse, error) {
	return &pb.ApplySnapshotResponse{Protocol: Protocol, AppliedVersion: s.GetVersion()}, nil
}

// recordingConn keeps every slice the gRPC transport reads into or writes
// from, so the test can look at those buffers after the calls.
type recordingConn struct {
	net.Conn
	mu   sync.Mutex
	seen [][]byte
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.seen = append(c.seen, b[:n:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.seen = append(c.seen, b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// recordingPool is wipingPool that remembers what it handed out.
type recordingPool struct {
	wipingPool
	mu   sync.Mutex
	got  [][]byte
	puts int
}

func (p *recordingPool) Get(n int) *[]byte {
	h := p.wipingPool.Get(n)
	p.mu.Lock()
	p.got = append(p.got, *h)
	p.mu.Unlock()
	return h
}

func (p *recordingPool) Put(h *[]byte) {
	p.wipingPool.Put(h)
	p.mu.Lock()
	p.puts++
	p.mu.Unlock()
}

func (p *recordingPool) buffers() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.got...)
}

// TestBoundaryLeavesNoCopyInTransportBuffers sends a snapshot and redact
// calls (large values that span HTTP/2 frames and small ones below gRPC's
// pooling threshold) and checks that, once the calls return, no buffer the
// client's transport read into or wrote from, and none its pool handed out,
// still holds any part of the values.
func TestBoundaryLeavesNoCopyInTransportBuffers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterDataPlaneServer(srv, echoPlane{})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rc := &recordingConn{Conn: nc}
	pool := &recordingPool{}
	conn, err := clientConnWith(rc, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewDataPlaneClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	big, small := generated(t, 40<<10), generated(t, 48)
	values := [][]byte{big, small}
	if _, err := client.ApplySnapshot(ctx, &pb.Snapshot{Protocol: Protocol, Version: 1, Values: []*pb.ValueEntry{
		{Ref: "mem://t#big", Value: bytes.Clone(big)},
		{Ref: "mem://t#small", Value: bytes.Clone(small)},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		resp, err := client.Redact(ctx, &pb.RedactRequest{Protocol: Protocol, Text: bytes.Clone(v)})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(resp.GetText(), v) {
			t.Fatal("echo differs")
		}
	}
	if len(pool.buffers()) == 0 {
		t.Fatal("gRPC never used the wiping pool")
	}

	leftover := func() string {
		rc.mu.Lock()
		seen := append([][]byte(nil), rc.seen...)
		rc.mu.Unlock()
		for _, b := range seen {
			for _, v := range values {
				if holdsPart(b, v) {
					return "a transport read or write buffer"
				}
			}
		}
		for _, b := range pool.buffers() {
			for _, v := range values {
				if holdsPart(b[:cap(b)], v) {
					return "a pool buffer"
				}
			}
		}
		return ""
	}
	// gRPC releases a sent message's buffer from its writer goroutine, which
	// can run just after the response arrives.
	deadline := time.Now().Add(5 * time.Second)
	for where := leftover(); where != ""; where = leftover() {
		if time.Now().After(deadline) {
			t.Fatalf("%s still holds secret bytes after the calls", where)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
