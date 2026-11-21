// SPDX-License-Identifier: AGPL-3.0-only

// Command scrim-load is the proxy-level load test (tasks.md 14.3).
//
//	scrim-load run   --profile smoke|full --scrim BIN --dataplane BIN --out DIR [overrides]
//	scrim-load drive --plan DIR/run/plan.json      (inside its container, started by run)
//
// run starts PostgreSQL, Valkey or NATS and N scrim replicas in rootless
// podman containers capped in memory and CPU, then the load generator in a
// container of its own. The load generator holds a fake model provider and a
// fake HTTPS tool API and drives agent traffic through the replicas: streamed
// provider requests carrying secrets to redact and placeholders to restore,
// tool requests through the forward proxy with placeholders to inject, and
// approvals held on one replica, decided on another and their grants revoked
// on a third. run samples each container's cgroup, merges what the load
// generator measured, writes result.json and report.md, checks them against
// test/load/profiles.json and exits 1 when a threshold is missed.
//
// test/load/run.sh builds the binaries and calls run; `just load-test` calls
// run.sh. docs/state-and-observability.md ("Load test") describes the run.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runMain(os.Args[2:])
	case "drive":
		err = driveMain(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "scrim-load %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scrim-load run|drive [flags]")
	os.Exit(2)
}

// logf writes a progress line to stderr.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "scrim-load: "+format+"\n", args...)
}
