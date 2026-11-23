// SPDX-License-Identifier: AGPL-3.0-only

// Command execprobe is the brokered command of the edge forwarder's
// end-to-end test (test/k8s/edge-e2e.sh). It runs in the central scrim's
// container through the exec broker and reports what it was given: the
// SHA-256 of PROBE_SECRET, which proves the real value reached it, and the
// value itself, which the broker must replace with its placeholder before
// the output reaches the agent pod. Never published.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	v := os.Getenv("PROBE_SECRET")
	if v == "" {
		fmt.Fprintln(os.Stderr, "execprobe: PROBE_SECRET is not set")
		os.Exit(2)
	}
	sum := sha256.Sum256([]byte(v))
	_, _ = fmt.Fprintf(os.Stdout, "sha256=%s\nvalue=%s\n", hex.EncodeToString(sum[:]), v)
}
