// SPDX-License-Identifier: AGPL-3.0-only

package audit_test

import (
	"log/slog"
	"strings"
	"sync"
)

// syncBuf is a log buffer safe to read while the logger writes.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newLog(w *syncBuf) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
