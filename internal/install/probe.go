// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// SocketProbe asks the admin API on a Unix socket. The installing user is
// an operator there: the user the service runs as, or root.
type SocketProbe struct{}

func client(sock string) *http.Client {
	d := net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return d.DialContext(ctx, "unix", sock) },
	}}
}

func get(ctx context.Context, sock, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://scrim"+path, nil)
	if err != nil {
		return nil, err
	}
	hc := client(sock)
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", path, resp.StatusCode)
	}
	return b, nil
}

// WaitReady polls GET /v1/daemon until it reports ready or ctx ends.
func (SocketProbe) WaitReady(ctx context.Context, sock string) error {
	var last error
	for {
		b, err := get(ctx, sock, "/v1/daemon")
		if err == nil {
			var in struct {
				Ready    bool              `json:"ready"`
				Problems map[string]string `json:"problems"`
			}
			if err = json.Unmarshal(b, &in); err == nil {
				if in.Ready {
					return nil
				}
				err = fmt.Errorf("not ready: %v", in.Problems)
			}
		}
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last: %w)", ctx.Err(), last)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// CA returns the PEM certificates of GET /v1/ca.
func (SocketProbe) CA(ctx context.Context, sock string) (string, error) {
	b, err := get(ctx, sock, "/v1/ca")
	return string(b), err
}
