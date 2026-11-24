// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

// The control plane refuses the snapshots the data plane would reject over
// TLS listeners and trust, so a bad trust is an error naming the setting
// instead of a data plane silently keeping the previous snapshot.
func TestCheckSnapshotTLS(t *testing.T) {
	ca := certtest.NewCA(t, "agents")
	b, _ := pem.Decode(ca.CRL(t, time.Now().Add(time.Hour)))
	crl := b.Bytes
	trust := func() *pb.ClientCertificateTrust {
		return &pb.ClientCertificateTrust{TrustAnchorsPem: string(ca.PEM), CrlsDer: [][]byte{crl}, ServerNames: []string{"localhost"}}
	}
	tlsOn := func(k pb.ListenerKind) []*pb.Listener {
		return []*pb.Listener{{Name: "l", Kind: k, Address: "127.0.0.1:0", Tls: true}}
	}
	cases := []struct {
		name string
		snap *pb.Snapshot
		want string
	}{
		{"valid", &pb.Snapshot{Listeners: tlsOn(pb.ListenerKind_LISTENER_KIND_BASE_URL), ClientCertificates: trust()}, ""},
		{"no tls, no trust", &pb.Snapshot{Listeners: []*pb.Listener{{Name: "l", Kind: pb.ListenerKind_LISTENER_KIND_BASE_URL}}}, ""},
		{"tls on a unix listener", &pb.Snapshot{Listeners: tlsOn(pb.ListenerKind_LISTENER_KIND_UNIX), ClientCertificates: trust()}, "tls is only for"},
		{"tls without trust", &pb.Snapshot{Listeners: tlsOn(pb.ListenerKind_LISTENER_KIND_FORWARD_PROXY)}, "needs identity.client-certificates.enabled"},
		{"no anchors", &pb.Snapshot{ClientCertificates: func() *pb.ClientCertificateTrust { c := trust(); c.TrustAnchorsPem = ""; return c }()}, "no trust anchors"},
		{"bad anchor", &pb.Snapshot{ClientCertificates: func() *pb.ClientCertificateTrust {
			c := trust()
			c.TrustAnchorsPem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
			return c
		}()}, "does not parse"},
		{"no server names", &pb.Snapshot{ClientCertificates: func() *pb.ClientCertificateTrust { c := trust(); c.ServerNames = []string{" "}; return c }()}, "server-names is empty"},
		{"malformed CRL", &pb.Snapshot{ClientCertificates: func() *pb.ClientCertificateTrust { c := trust(); c.CrlsDer = [][]byte{[]byte("nope")}; return c }()}, "CRL 1 does not parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkSnapshotTLS(c.snap)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
		})
	}
}
