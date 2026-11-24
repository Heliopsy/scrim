// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// TestCloneListenersKeepsEveryField: the snapshot carries listeners exactly as
// built. A hand copy dropped BlockUnrouted, so proxy.transparent-unrouted:
// block never reached the data plane and unrouted hosts passed through.
func TestCloneListenersKeepsEveryField(t *testing.T) {
	in := []*pb.Listener{
		{Name: "transparent", Kind: pb.ListenerKind_LISTENER_KIND_TRANSPARENT, Address: "127.0.0.1:9796", BlockUnrouted: true},
		{Name: "sni", Kind: pb.ListenerKind_LISTENER_KIND_SNI, Address: "127.0.0.1:9797", BlockUnrouted: true},
		{Name: "base-url", Kind: pb.ListenerKind_LISTENER_KIND_BASE_URL, Address: "127.0.0.1:9790"},
	}
	out := cloneListeners(in)
	if len(out) != len(in) {
		t.Fatalf("got %d listeners, want %d", len(out), len(in))
	}
	for i := range in {
		if !proto.Equal(out[i], in[i]) {
			t.Errorf("listener %d: got %v, want %v", i, out[i], in[i])
		}
		if out[i] == in[i] {
			t.Errorf("listener %d: not copied", i)
		}
	}
}
