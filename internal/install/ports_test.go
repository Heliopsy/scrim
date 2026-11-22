package install

import (
	"net"
	"strconv"
	"testing"

	"github.com/heliopsy/scrim/internal/obs"
)

// The transparent listener and the metrics and health listener both default
// to loopback; they must not default to the same port.
func TestTransparentPortDiffersFromMetrics(t *testing.T) {
	_, p, err := net.SplitHostPort(obs.DefaultMetricsListen)
	if err != nil {
		t.Fatal(err)
	}
	if p == strconv.Itoa(DefaultTransparentPort) {
		t.Fatalf("transparent port %d is the metrics port (%s)", DefaultTransparentPort, obs.DefaultMetricsListen)
	}
}
