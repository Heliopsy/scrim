// SPDX-License-Identifier: AGPL-3.0-only

package dataplane

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/experimental"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// The boundary connection carries every secret value in the snapshot one
// way, and captured values and Kubernetes tokens the other. These options
// keep gRPC from leaving copies of those bytes behind:
//
//   - The codec marshals each message into a buffer that is zeroed when gRPC
//     releases it, and zeroes the received bytes once a message is decoded.
//   - The buffer pool, which gRPC reads DATA frames into, zeroes every buffer
//     it gets back and keeps none.
//   - With the read and write buffers off, the HTTP/2 framer reads DATA
//     payloads straight from the socket into pool buffers and writes the
//     codec's buffers straight to the socket, so no bufio buffer holds them.
//
// What stays out of reach is listed in docs/limitations.md.
func wipingDialOptions(pool mem.BufferPool) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(wipingCodec{pool: pool})),
		experimental.WithBufferPool(pool),
		grpc.WithReadBufferSize(0),
		grpc.WithWriteBufferSize(0),
	}
}

// wipingPool hands out fresh buffers and zeroes each one it gets back, over
// its whole capacity, before letting it go. Reusing buffers would save
// allocations, but a pooled buffer would hold its last message's bytes until
// overwritten.
type wipingPool struct{}

func (wipingPool) Get(n int) *[]byte {
	b := make([]byte, n)
	return &b
}

func (wipingPool) Put(b *[]byte) { clear((*b)[:cap(*b)]) }

// minPooled is the smallest capacity gRPC returns to a pool: smaller buffers
// are plain slices that are never released, so never zeroed.
var minPooled = func() int {
	n := 64
	for mem.IsBelowBufferPoolingThreshold(n) {
		n *= 2
	}
	return n
}()

// wipingCodec is the protobuf codec over buffers that are zeroed when
// released. Its name is "proto", so the data plane sees the standard
// content type.
type wipingCodec struct{ pool mem.BufferPool }

var _ encoding.CodecV2 = wipingCodec{}

func (wipingCodec) Name() string { return "proto" }

func (c wipingCodec) Marshal(v any) (mem.BufferSlice, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("dataplane: cannot marshal %T", v)
	}
	size := proto.Size(m)
	// Give the buffer a capacity gRPC pools, so it comes back to c.pool
	// (and is zeroed) once the last frame holding it has been written.
	h := c.pool.Get(max(size, minPooled))
	buf := (*h)[:0]
	out, err := proto.MarshalOptions{UseCachedSize: true}.MarshalAppend(buf, m)
	if err == nil && (cap(out) != cap(buf) || len(out) != size) {
		// MarshalAppend outgrew the buffer: the message changed between
		// Size and Marshal. The grown copy would not be zeroed.
		err = fmt.Errorf("dataplane: %T changed while it was marshalled", v)
	}
	if err != nil {
		clear(out[:cap(out)])
		c.pool.Put(h)
		return nil, err
	}
	*h = out
	return mem.BufferSlice{mem.NewBuffer(h, c.pool)}, nil
}

func (c wipingCodec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("dataplane: cannot unmarshal into %T", v)
	}
	// Frames below the pooling threshold arrive in plain slices that gRPC
	// never releases to the pool, so zero every received buffer here. proto
	// copies bytes fields out of the input, so the message keeps its values.
	defer wipeSlice(data)
	if len(data) == 1 {
		return proto.Unmarshal(data[0].ReadOnlyData(), m)
	}
	h := c.pool.Get(data.Len())
	defer c.pool.Put(h)
	data.CopyTo(*h)
	return proto.Unmarshal(*h, m)
}

// wipeSlice zeroes the bytes of every buffer in s. The codec is the last
// reader of a received message, so writing to its read-only view is safe.
func wipeSlice(s mem.BufferSlice) {
	for _, b := range s {
		clear(b.ReadOnlyData())
	}
}
