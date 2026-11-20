// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// LocalUpstream is an in-process fake provider.
type LocalUpstream struct{ Server *fp.Server }

// Reset implements Upstream.
func (l LocalUpstream) Reset(context.Context) error { l.Server.Reset(); return nil }

// Exchanges implements Upstream.
func (l LocalUpstream) Exchanges(context.Context) ([]fp.Exchange, error) {
	return l.Server.Exchanges(), nil
}

// RemoteUpstream is a scrim-fakeprovider reached over its control endpoints.
type RemoteUpstream struct {
	BaseURL string
	Client  *http.Client
}

func (r RemoteUpstream) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

// Reset implements Upstream.
func (r RemoteUpstream) Reset(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.BaseURL, "/")+"/_fake/reset", nil)
	if err != nil {
		return err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("reset: status %d", resp.StatusCode)
	}
	return nil
}

// Exchanges implements Upstream.
func (r RemoteUpstream) Exchanges(ctx context.Context) ([]fp.Exchange, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(r.BaseURL, "/")+"/_fake/exchanges", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchanges: status %d", resp.StatusCode)
	}
	var out []fp.Exchange
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
