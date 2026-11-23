// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/testing/podtest"

	// The adapters the matrix writes seeds through.
	_ "github.com/heliopsy/scrim/internal/stores/aws"
	_ "github.com/heliopsy/scrim/internal/stores/openbao"
	_ "github.com/heliopsy/scrim/internal/stores/vault"
)

// Container images of the store servers, the same versions the store
// conformance tests run.
const (
	OpenBaoImage    = "quay.io/openbao/openbao:2.7.3"
	VaultImage      = "docker.io/hashicorp/vault:2.2.2"
	LocalStackImage = "docker.io/localstack/localstack:4.14.0"
)

// StoreName is the store instance every cell configures; references are
// mx://...
const StoreName = "mx"

// Credentials of the emulators, generated per run like the OpenBao and
// Vault root tokens. LocalStack accepts any key; scrim redacts a store's own
// credentials too, so they are shaped like real AWS keys rather than
// LocalStack's usual "test", a substring of the api-key seeds.
var (
	awsTestKeyID  = "AKIA" + strings.ToUpper(podtest.RandHex(8))
	awsTestSecret = podtest.RandHex(20)
)

// storeServer is the store's server as the sandboxed side reaches it: an
// address on the host (a published container port) that a relay carries into
// the sandbox's network namespace through a Unix socket.
type storeServer struct {
	Kind   Store  `json:"kind"`
	Socket string `json:"socket,omitempty"` // relay socket, empty for the file store
	Token  string `json:"token,omitempty"`  // OpenBao and Vault root token
}

// startStore starts the server of a store kind in rootless podman (nothing
// for the file store) and returns it with a stop function.
func startStore(t testing.TB, kind Store, dir string) (storeServer, func(), error) {
	srv := storeServer{Kind: kind}
	var svc *podtest.Service
	ready := func(path string) func(context.Context, string) error {
		return func(ctx context.Context, addr string) error {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: %s", path, resp.Status)
			}
			return nil
		}
	}
	switch kind {
	case StoreFile:
		return srv, func() {}, nil
	case StoreOpenBao:
		srv.Token = "mx-" + podtest.RandHex(16)
		svc = &podtest.Service{Name: "openbao", Image: OpenBaoImage, ImageEnv: "SCRIM_TEST_OPENBAO_IMAGE", Port: "8200/tcp",
			Memory: "512m", RunArgs: []string{"-e", "BAO_DEV_ROOT_TOKEN_ID=" + srv.Token},
			Args:  []string{"server", "-dev", "-dev-listen-address=0.0.0.0:8200"},
			Ready: ready("/v1/sys/health")}
	case StoreVault:
		srv.Token = "mx-" + podtest.RandHex(16)
		svc = &podtest.Service{Name: "vault", Image: VaultImage, ImageEnv: "SCRIM_TEST_VAULT_IMAGE", Port: "8200/tcp",
			Memory: "512m", RunArgs: []string{"-e", "VAULT_DEV_ROOT_TOKEN_ID=" + srv.Token, "-e", "SKIP_SETCAP=1"},
			Args:  []string{"server", "-dev", "-dev-listen-address=0.0.0.0:8200"},
			Ready: ready("/v1/sys/health")}
	case StoreAWSSM:
		svc = &podtest.Service{Name: "localstack", Image: LocalStackImage, ImageEnv: "SCRIM_TEST_LOCALSTACK_IMAGE", Port: "4566/tcp",
			Memory: "1g", RunArgs: []string{"-e", "SERVICES=secretsmanager", "-e", "LOCALSTACK_TELEMETRY=0", "-e", "DISABLE_EVENTS=1"},
			Ready: ready("/_localstack/health"), ReadyTimeout: 3 * time.Minute}
	default:
		return srv, nil, fmt.Errorf("unknown store %q", kind)
	}
	addr := svc.Addr(t) // fails the test without podman when SCRIM_TEST_PODMAN=1
	srv.Socket = filepath.Join(dir, string(kind)+".sock")
	stopRelay, err := relayUnixToTCP(srv.Socket, addr)
	if err != nil {
		svc.Stop()
		return srv, nil, err
	}
	return srv, func() { stopRelay(); svc.Stop() }, nil
}

// relayUnixToTCP serves socket, carrying every connection to addr.
func relayUnixToTCP(socket, addr string) (func(), error) {
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	go serveRelay(ln, func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 5*time.Second) })
	return func() { _ = ln.Close() }, nil
}

// relayTCPToUnix listens on a free loopback port and carries every
// connection to socket. It returns the address.
func relayTCPToUnix(socket string) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go serveRelay(ln, func() (net.Conn, error) { return net.DialTimeout("unix", socket, 5*time.Second) })
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

func serveRelay(ln net.Listener, dial func() (net.Conn, error)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			u, err := dial()
			if err != nil {
				return
			}
			defer func() { _ = u.Close() }()
			var wg sync.WaitGroup
			wg.Add(2)
			pipe := func(dst, src net.Conn) {
				defer wg.Done()
				_, _ = io.Copy(dst, src)
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}
			go pipe(u, c)
			go pipe(c, u)
			wg.Wait()
		}()
	}
}

// cellStore is the store of one cell inside the sandbox: where its secrets
// live, how scrim reaches it and how the test writes to it.
type cellStore struct {
	server storeServer
	addr   string // loopback address of the relay, empty for the file store
	root   string // file store directory
	prefix string // path of this cell's secrets, below the mount for KV
	env    []string
}

// newCellStore prepares the store for one cell. prefix is unique per cell,
// so cells sharing one server never see each other's secrets.
func newCellStore(srv storeServer, addr, dir, prefix string) *cellStore {
	s := &cellStore{server: srv, addr: addr, prefix: prefix}
	switch srv.Kind {
	case StoreFile:
		s.root = filepath.Join(dir, "secrets")
	case StoreOpenBao, StoreVault:
		s.env = []string{"SCRIM_MATRIX_STORE_TOKEN=" + srv.Token}
	case StoreAWSSM:
		s.env = []string{"SCRIM_MATRIX_AWS_KEY_ID=" + awsTestKeyID, "SCRIM_MATRIX_AWS_SECRET=" + awsTestSecret}
	}
	return s
}

// path is where a secret of this cell lives, as a reference path.
func (s *cellStore) path(name string) string {
	switch s.server.Kind {
	case StoreOpenBao, StoreVault:
		return "secret/" + s.prefix + "/" + name
	}
	return s.prefix + "/" + name
}

// Ref is the store reference of a secret of this cell.
func (s *cellStore) Ref(name string) string { return StoreName + "://" + s.path(name) }

// FieldRef names the field a value is written to (the file store has one).
func (s *cellStore) FieldRef(name string) string {
	if s.server.Kind == StoreFile {
		return s.Ref(name)
	}
	return s.Ref(name) + "#value"
}

// Writable reports whether an agent can write to the store (the file store
// is read-only).
func (s *cellStore) Writable() bool { return s.server.Kind != StoreFile }

// Config is the stores block of scrim's configuration, indented under
// "stores:".
func (s *cellStore) Config() string {
	redact := fmt.Sprintf("    redact: [%q]\n", s.Ref("*"))
	switch s.server.Kind {
	case StoreFile:
		return fmt.Sprintf("  %s:\n    kind: file\n    root: %s\n    format: raw\n    trim-newline: false\n%s", StoreName, s.root, redact)
	case StoreOpenBao, StoreVault:
		return fmt.Sprintf("  %s:\n    kind: %s\n    address: http://%s\n    token: env:SCRIM_MATRIX_STORE_TOKEN\n%s",
			StoreName, s.server.Kind, s.addr, redact)
	case StoreAWSSM:
		return fmt.Sprintf("  %s:\n    kind: awssm\n    endpoint: http://%s\n    region: us-east-1\n"+
			"    access-key-id: env:SCRIM_MATRIX_AWS_KEY_ID\n    secret-access-key: env:SCRIM_MATRIX_AWS_SECRET\n%s",
			StoreName, s.addr, redact)
	}
	return ""
}

// adapter opens the store the way scrim does, for the test's own writes and
// reads.
func (s *cellStore) adapter(ctx context.Context) (stores.Adapter, error) {
	opts := map[string]any{}
	creds := map[string]string{}
	switch s.server.Kind {
	case StoreOpenBao, StoreVault:
		opts["address"], opts["token"] = "http://"+s.addr, "test:token"
		creds["test:token"] = s.server.Token
	case StoreAWSSM:
		opts["endpoint"], opts["region"] = "http://"+s.addr, "us-east-1"
		opts["access-key-id"], opts["secret-access-key"] = "test:id", "test:key"
		creds["test:id"], creds["test:key"] = awsTestKeyID, awsTestSecret
	default:
		return nil, fmt.Errorf("no adapter for store %s", s.server.Kind)
	}
	return stores.DefaultRegistry.Open(ctx, stores.Instance{Name: StoreName, Kind: string(s.server.Kind), Options: opts,
		Resolve: func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
			v, ok := creds[string(ref)]
			if !ok {
				return secret.Value{}, errors.New("no such reference")
			}
			return secret.FromString(v), nil
		}})
}

// Put writes values (name to value) before scrim starts: files for the file
// store, through the adapter otherwise.
func (s *cellStore) Put(ctx context.Context, values map[string]string) error {
	if s.server.Kind == StoreFile {
		dir := filepath.Join(s.root, filepath.FromSlash(s.prefix))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		for name, v := range values {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	a, err := s.adapter(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = a.Close() }()
	for name, v := range values {
		ref, err := stores.ParseRef(s.Ref(name))
		if err != nil {
			return err
		}
		if _, err := a.Write(ctx, ref, map[string]secret.Value{"value": secret.FromString(v)}, stores.WriteOptions{}); err != nil {
			return fmt.Errorf("write %s: %w", ref, err)
		}
	}
	return nil
}

// Get reads a value back (for values scrim generated or captured), or ""
// when it is not there.
func (s *cellStore) Get(ctx context.Context, name string) (string, error) {
	if s.server.Kind == StoreFile {
		b, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(s.prefix), name))
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return string(b), err
	}
	a, err := s.adapter(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = a.Close() }()
	ref, err := stores.ParseRef(s.Ref(name))
	if err != nil {
		return "", err
	}
	sec, err := a.Read(ctx, ref)
	if err != nil {
		if errors.Is(err, stores.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	defer sec.Wipe()
	v, ok := sec.Field("value")
	if !ok {
		return "", nil
	}
	var out string
	_ = v.Expose(func(b []byte) error { out = string(b); return nil })
	return out, nil
}
