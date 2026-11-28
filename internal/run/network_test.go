// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/fsview"
)

// agentNet is agentLLM followed by what a hostile or careless command
// does: dial a host address itself, and fetch a URL with the proxy
// settings ignored. It prints one line per attempt.
func agentNet() int {
	if code := agentLLM(); code != 7 {
		return code
	}
	addr := os.Getenv("TEST_DIRECT_ADDR")
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		_ = c.Close()
		fmt.Println("direct-dial=ok")
	} else {
		fmt.Println("direct-dial=fail")
	}
	noProxy := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // reachability only
	for name, u := range map[string]string{"no-proxy-ip": "https://" + addr + "/", "no-proxy-host": os.Getenv("TEST_TOOL_URL")} {
		resp, err := noProxy.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			fmt.Printf("%s=ok\n", name)
		} else {
			fmt.Printf("%s=fail\n", name)
		}
	}
	return 7
}

// requireNetwork skips unless the agent network namespace works here;
// SCRIM_TEST_REQUIRE_USERNS=1 (CI) fails instead.
func requireNetwork(t *testing.T) {
	t.Helper()
	a := fsview.ProbeNetwork(context.Background(), selfAgent(t))
	if a.Namespace {
		return
	}
	if os.Getenv("SCRIM_TEST_REQUIRE_USERNS") == "1" {
		t.Fatalf("network namespaces unavailable: %s", a.Reason)
	}
	t.Skipf("network namespaces unavailable: %s", a.Reason)
}

// agentDial dials each Unix socket in TEST_DIAL, resolves a name through
// the C library (getent, as nss sees it) and reports the display
// variables it inherited, one line each.
func agentDial() int {
	for _, p := range strings.Split(os.Getenv("TEST_DIAL"), ",") {
		c, err := net.DialTimeout("unix", p, 3*time.Second)
		if err == nil {
			_ = c.Close()
			fmt.Printf("dial %s=ok\n", p)
		} else {
			fmt.Printf("dial %s=fail\n", p)
		}
	}
	if getent, err := exec.LookPath("getent"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		start := time.Now()
		err := exec.CommandContext(ctx, getent, "hosts", "scrim-proxy-only-check.example.com").Run() //nolint:gosec // test
		cancel()
		res := "ok"
		if err != nil {
			res = "fail"
		}
		fmt.Printf("getent=%s seconds=%d\n", res, int(time.Since(start).Seconds()))
	}
	fmt.Printf("DISPLAY=%q WAYLAND_DISPLAY=%q\n", os.Getenv("DISPLAY"), os.Getenv("WAYLAND_DISPLAY"))
	return 0
}
