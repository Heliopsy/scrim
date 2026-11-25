// SPDX-License-Identifier: AGPL-3.0-only

// Package pluginv1 is the scrim plugin protocol, version 1: the code
// generated from proto/scrim/plugin/v1/plugin.proto and the codec both sides
// use. See docs/plugins.md.
package pluginv1

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// Codec is the gRPC codec both sides of the plugin protocol use. It is the
// protobuf codec with two additions for messages that carry secret
// material: once such a message is marshalled, its values are zeroed in the
// message and the marshalled bytes are zeroed when gRPC releases them; the
// contiguous copy made to unmarshal a message is zeroed afterwards. gRPC's
// own transport buffers on a plugin connection stay out of reach.
func Codec() encoding.CodecV2 { return codec{} }

type codec struct{}

// secretBearer is implemented by the messages that hold secret material.
type secretBearer interface{ WipeSecrets() }

func (codec) Name() string { return "proto" }

func (codec) Marshal(v any) (mem.BufferSlice, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("pluginv1: cannot marshal %T", v)
	}
	s, bearer := v.(secretBearer)
	if !bearer {
		b, err := proto.Marshal(m)
		if err != nil {
			return nil, err
		}
		return mem.BufferSlice{mem.SliceBuffer(b)}, nil
	}
	// gRPC only returns a buffer to its pool, where it is zeroed, when its
	// capacity is above the pooling threshold, so give it one.
	capacity := max(proto.Size(m), 64)
	for mem.IsBelowBufferPoolingThreshold(capacity) {
		capacity *= 2
	}
	b, err := proto.MarshalOptions{}.MarshalAppend(make([]byte, 0, capacity), m)
	s.WipeSecrets()
	if err != nil {
		clear(b[:cap(b)])
		return nil, err
	}
	return mem.BufferSlice{mem.NewBuffer(&b, wipingPool{})}, nil
}

func (codec) Unmarshal(data mem.BufferSlice, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("pluginv1: cannot unmarshal into %T", v)
	}
	b := data.Materialize()
	defer clear(b)
	// Bytes fields are copied out of b, so clearing it afterwards is safe.
	return proto.Unmarshal(b, m)
}

// wipingPool zeroes a buffer when gRPC is done with it and lets it go.
type wipingPool struct{}

func (wipingPool) Get(n int) *[]byte {
	b := make([]byte, n)
	return &b
}

func (wipingPool) Put(b *[]byte) { clear((*b)[:cap(*b)]) }
