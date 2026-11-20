// SPDX-License-Identifier: AGPL-3.0-only

package postgres_test

import (
	"os"
	"testing"

	"github.com/heliopsy/scrim/internal/testing/pgtest"
)

// The tests need a PostgreSQL server: see package pgtest.
func TestMain(m *testing.M) {
	code := m.Run()
	pgtest.Stop()
	os.Exit(code)
}

func freshDSN(t *testing.T) string {
	t.Helper()
	return pgtest.FreshDSN(t)
}
