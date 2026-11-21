// SPDX-License-Identifier: AGPL-3.0-only

package status_test

import (
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/status"
)

func TestFromFanout(t *testing.T) {
	got := status.FromFanout([]audit.SinkStatus{
		{Name: "loki", Policy: audit.Block, Queued: 1, Capacity: 100, Up: true},
		{Name: "kafka", Policy: audit.Drop, Queued: 100, Capacity: 100, Up: false, Dropped: 7, LastError: "dial tcp: refused"},
		{Name: "otlp", Policy: audit.Block, Queued: 0, Capacity: 100, Up: true, Refused: 2},
	})
	if got[0].Degraded || got[0].Policy != "block" {
		t.Fatalf("healthy sink = %+v", got[0])
	}
	if !got[1].Degraded || got[1].Dropped != 7 || got[1].Policy != "drop" || !strings.Contains(got[1].Detail, "writes failing") {
		t.Fatalf("dropping sink = %+v", got[1])
	}
	if !got[2].Degraded || !strings.Contains(got[2].Detail, "2 entries refused") {
		t.Fatalf("refusing sink = %+v", got[2])
	}
}
