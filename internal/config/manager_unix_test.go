// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

// Windows has no SIGHUP; the configuration reloads there on file changes
// (config.watch) and through the admin API.

package config_test

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestSIGHUPReloads(t *testing.T) {
	// Our own subscription keeps the default SIGHUP action (exit) away
	// while Run is still starting.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGHUP)
	defer signal.Stop(guard)

	w := newWorld(t)
	p := w.file("c.yaml", header+"config.watch: false\nlog.level: info\n")
	m, _ := newManager(t, w, p)
	runManager(t, m)
	w.file("c.yaml", header+"config.watch: false\nlog.level: error\n")
	waitVersion(t, m, 2, func() { _ = syscall.Kill(os.Getpid(), syscall.SIGHUP) })
	if st := m.Status(); st.LastReload == nil || st.LastReload.Trigger != "signal" {
		t.Fatalf("last reload = %+v", st.LastReload)
	}
}
