// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/policy"
)

type policyRuleSet = policy.RuleSet

// ErrNotRunning means no daemon answers on the admin address.
var ErrNotRunning = errors.New("daemon: no scrim daemon is running")

// localConnContext attaches Unix peer credentials for an admin socket.
func localConnContext(addr string) func(context.Context, net.Conn) context.Context {
	if strings.HasPrefix(addr, "unix:") {
		return localapi.ConnContext
	}
	return nil
}

// InfoPath is the daemon info file for the admin address: next to the admin
// socket, or under $XDG_RUNTIME_DIR/scrim for a TCP admin listener.
func InfoPath(adminURL string) string {
	if adminURL == "" {
		adminURL = "unix:" + approval.DefaultAdminSocket()
	}
	if path, ok := strings.CutPrefix(adminURL, "unix:"); ok {
		return filepath.Join(filepath.Dir(path), "daemon.json")
	}
	return filepath.Join(filepath.Dir(approval.DefaultAdminSocket()), "daemon.json")
}

// writeInfo writes the info file (mode 0600, atomically), so tools can find
// the addresses without asking the admin API. It holds no secret.
func (d *Daemon) writeInfo() error {
	if d.infoPath == "" {
		d.infoPath = InfoPath(d.Addrs().Admin)
	}
	b, err := json.MarshalIndent(d.Info(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.infoPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(d.infoPath), ".daemon-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), d.infoPath)
}

// Connect asks the daemon behind cfg's admin.url for its info. It returns
// ErrNotRunning when nothing listens there.
func Connect(ctx context.Context, cfg *config.Config) (Info, error) {
	addr := approval.AdminURL.Get(cfg)
	if addr == "" {
		addr = "unix:" + approval.DefaultAdminSocket()
	}
	var base string
	hc := &http.Client{Timeout: 5 * time.Second}
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return Info{}, ErrNotRunning
		}
		d := net.Dialer{Timeout: 2 * time.Second}
		hc.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", path)
		}}
		base = "http://scrim"
	} else {
		u, err := url.Parse(addr)
		if err != nil || u.Host == "" {
			return Info{}, fmt.Errorf("admin.url %q: want unix:/path or http(s)://host:port", addr)
		}
		base = strings.TrimRight(addr, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/daemon", nil)
	if err != nil {
		return Info{}, err
	}
	if tok, ok := cfg.Secret(AdminToken); ok {
		_ = tok.Expose(func(b []byte) error { req.Header.Set("Authorization", "Bearer "+string(b)); return nil })
	}
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return Info{}, ErrNotRunning
		}
		return Info{}, fmt.Errorf("daemon: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Info{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var e approval.ErrorBody
		_ = json.Unmarshal(body, &e)
		return Info{}, fmt.Errorf("daemon: admin API answered %d: %s", resp.StatusCode, e.Error)
	}
	var in Info
	if err := json.Unmarshal(body, &in); err != nil {
		return Info{}, fmt.Errorf("daemon: decoding info: %w", err)
	}
	return in, nil
}

// Ensure returns a running daemon's info, starting one in this process when
// none answers. d is nil when an existing daemon is reused; otherwise the
// caller owns d and shuts it down. Ensure waits until the daemon is ready
// or ctx ends.
func Ensure(ctx context.Context, o Options) (Info, *Daemon, error) {
	cfg, err := config.Build(o.Config)
	if err != nil {
		return Info{}, nil, err
	}
	in, err := Connect(ctx, cfg)
	if err == nil {
		return in, nil, nil
	}
	if !errors.Is(err, ErrNotRunning) {
		return Info{}, nil, err
	}
	d, err := Start(ctx, o)
	if err != nil {
		return Info{}, nil, err
	}
	if err := d.WaitReady(ctx); err != nil {
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = d.Shutdown(shut)
		return Info{}, nil, err
	}
	return d.Info(), d, nil
}
