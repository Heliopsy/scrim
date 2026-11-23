// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
)

// FromConfig builds the forwarder from the edge-forwarder.* settings.
func FromConfig(cfg *config.Config, log *slog.Logger) (*Forwarder, error) {
	central := Central.Get(cfg)
	if central == "" {
		return nil, fmt.Errorf("%s is not set", Central.Name())
	}
	host, _, err := net.SplitHostPort(central)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Central.Name(), err)
	}
	name := ServerName.Get(cfg)
	if name == "" {
		name = host
	}
	caPEM, err := os.ReadFile(CAFile.Get(cfg))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CAFile.Name(), err)
	}
	tc, err := NewTLSConfig(caPEM, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CAFile.Name(), err)
	}
	return &Forwarder{Central: central, TLS: tc, Token: TokenFile(TokenPath.Get(cfg)),
		DialTimeout: ConnectTimeout.Get(cfg), Log: log}, nil
}

// Endpoint is one local listener the forwarder serves.
type Endpoint struct {
	// Name is what logs call it: ssh-agent, api, database <name>.
	Name string
	// Addr is the socket path or the loopback address.
	Addr string
	ln   net.Listener
	// serve runs until ctx ends.
	serve func(ctx context.Context) error
}

// Listen opens every endpoint the edge-forwarder.* settings name. It
// refuses a configuration that serves nothing.
func Listen(cfg *config.Config, f *Forwarder) ([]*Endpoint, error) {
	mode, err := ParseMode(SocketPermissions.Get(cfg))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SocketPermissions.Name(), err)
	}
	var eps []*Endpoint
	fail := func(err error) ([]*Endpoint, error) {
		for _, e := range eps {
			_ = e.ln.Close()
		}
		return nil, err
	}
	if p := SSHAgentSocket.Get(cfg); p != "" {
		ln, err := listenUnix(p, fs.FileMode(mode))
		if err != nil {
			return fail(fmt.Errorf("%s: %w", SSHAgentSocket.Name(), err))
		}
		eps = append(eps, &Endpoint{Name: "ssh-agent", Addr: p, ln: ln,
			serve: func(ctx context.Context) error { return f.ServeTunnel(ctx, ln, PathSSHAgent) }})
	}
	if p := APISocket.Get(cfg); p != "" {
		ln, err := listenUnix(p, fs.FileMode(mode))
		if err != nil {
			return fail(fmt.Errorf("%s: %w", APISocket.Name(), err))
		}
		eps = append(eps, &Endpoint{Name: "api", Addr: p, ln: ln,
			serve: func(ctx context.Context) error { return f.ServeAPI(ctx, ln) }})
	}
	dbs := Databases.Get(cfg)
	for _, name := range slices.Sorted(maps.Keys(dbs)) {
		addr := dbs[name]
		if err := loopbackAddr(addr); err != nil {
			return fail(fmt.Errorf("%s.%s: %w", Databases.Name(), name, err))
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fail(fmt.Errorf("%s.%s: %w", Databases.Name(), name, err))
		}
		path := PathDatabase + "/" + name
		eps = append(eps, &Endpoint{Name: "database " + name, Addr: ln.Addr().String(), ln: ln,
			serve: func(ctx context.Context) error { return f.ServeTunnel(ctx, ln, path) }})
	}
	if len(eps) == 0 {
		return nil, fmt.Errorf("nothing to forward: set %s, %s or %s", SSHAgentSocket.Name(), APISocket.Name(), Databases.Name())
	}
	return eps, nil
}

func listenUnix(path string, mode fs.FileMode) (net.Listener, error) {
	// localapi.Listen replaces a stale socket, refuses a live one and sets
	// the mode.
	return localapi.Listen(path, localapi.ListenOptions{Mode: mode})
}

// Serve runs every endpoint until ctx ends or one fails, then stops them
// all and removes the Unix sockets.
func Serve(ctx context.Context, eps []*Endpoint) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, len(eps))
	for _, e := range eps {
		go func() {
			err := e.serve(ctx)
			if err != nil {
				err = fmt.Errorf("%s: %w", e.Name, err)
			}
			errc <- err
		}()
	}
	var errs []error
	for range eps {
		if err := <-errc; err != nil {
			errs = append(errs, err)
		}
		cancel()
	}
	for _, e := range eps {
		if _, ok := e.ln.(*net.UnixListener); ok {
			_ = os.Remove(e.Addr)
		}
	}
	return errors.Join(errs...)
}
