// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
	_ "github.com/heliopsy/scrim/internal/netproxy" // registers network.upstream-proxy.*
)

type cfgSource struct{ cfg *config.Config }

func (c cfgSource) Status() config.Status   { return config.Status{} }
func (c cfgSource) Current() *config.Config { return c.cfg }

// TestUpstreamProxyShownWithoutCredentials: status names the upstream proxy
// as scheme://host:port, never with the credentials of the URL it came from.
func TestUpstreamProxyShownWithoutCredentials(t *testing.T) {
	cfg, err := config.Build(config.Options{SystemDir: t.TempDir(), Environ: []string{"HOME=" + t.TempDir(),
		"HTTPS_PROXY=http://alice:status-pw-82211@proxy.corp.test:3128"}})
	if err != nil {
		t.Fatal(err)
	}
	r := Collect(context.Background(), Sources{Config: cfgSource{cfg}})
	if r.UpstreamProxy != "http://proxy.corp.test:3128" {
		t.Errorf("UpstreamProxy = %q", r.UpstreamProxy)
	}
	var human, js bytes.Buffer
	_ = WriteHuman(&human, r)
	_ = WriteJSON(&js, r)
	if !strings.Contains(human.String(), "outbound: through upstream proxy http://proxy.corp.test:3128") {
		t.Errorf("human output:\n%s", human.String())
	}
	for _, out := range []string{human.String(), js.String()} {
		if strings.Contains(out, "status-pw") || strings.Contains(out, "alice") {
			t.Errorf("credentials in status output:\n%s", out)
		}
	}
}
