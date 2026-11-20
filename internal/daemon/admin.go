// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

// adminListener is the operator API's socket and how it attributes
// requests to an operator.
type adminListener struct {
	ln       net.Listener
	addr     string // admin.url form: unix:/path or http://host:port
	operator func(*http.Request) (string, bool)
}

// listenAdmin opens the admin listener admin.url names. A Unix socket
// (the default) is mode 0600 and accepts only the user scrim runs as, or
// root, by peer credentials. A TCP listener requires admin.token and
// accepts only requests that present it; it is refused without one.
func listenAdmin(addr string, token secret.Value) (*adminListener, error) {
	if addr == "" {
		addr = "unix:" + approval.DefaultAdminSocket()
	}
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		ln, err := localapi.Listen(path, localapi.ListenOptions{Mode: 0o600})
		if err != nil {
			return nil, fmt.Errorf("admin.url: %w", err)
		}
		return &adminListener{ln: ln, addr: addr, operator: peerOperator(uint32(os.Getuid()))}, nil //nolint:gosec // uids fit in 32 bits
	}
	u, err := url.Parse(addr)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return nil, fmt.Errorf("admin.url %q: the daemon serves unix:/path or http://host:port (terminate TLS in front of it)", addr)
	}
	if token.IsZero() || token.Len() < 16 {
		return nil, errors.New("admin.url is a TCP address: set admin.token to a reference to a token of at least 16 bytes")
	}
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("admin.url: %w", err)
	}
	return &adminListener{ln: ln, addr: "http://" + ln.Addr().String(), operator: tokenOperator(token)}, nil
}

// peerOperator accepts peers running as uid or as root, named by user.
func peerOperator(uid uint32) func(*http.Request) (string, bool) {
	return func(r *http.Request) (string, bool) {
		p, ok := localapi.PeerFrom(r.Context())
		if !ok || (p.UID != uid && p.UID != 0) {
			return "", false
		}
		id := strconv.FormatUint(uint64(p.UID), 10)
		if u, err := user.LookupId(id); err == nil && u.Username != "" {
			return "user:" + u.Username, true
		}
		return "uid:" + id, true
	}
}

// tokenOperator accepts requests carrying the bearer token.
func tokenOperator(token secret.Value) func(*http.Request) (string, bool) {
	return func(r *http.Request) (string, bool) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || got == "" {
			return "", false
		}
		match := false
		_ = token.Expose(func(b []byte) error {
			match = subtle.ConstantTimeCompare([]byte(got), b) == 1
			return nil
		})
		if !match {
			return "", false
		}
		return "token", true
	}
}

// adminMux serves the operator API, the decision links and the daemon's own
// info endpoint.
func adminMux(svcs adminServices, operator func(*http.Request) (string, bool), info func() Info) *http.ServeMux {
	mux := http.NewServeMux()
	if svcs.decision != nil {
		// Decision links carry their own signed token; no operator needed.
		mux.Handle("GET /v1/approvals/{id}/decide", svcs.decision)
		mux.Handle("POST /v1/approvals/{id}/decide", svcs.decision)
	}
	mux.HandleFunc("GET /v1/daemon", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := operator(r); !ok {
			writeJSON(w, http.StatusUnauthorized, approval.ErrorBody{Error: "not an operator", Code: "unauthenticated"})
			return
		}
		writeJSON(w, http.StatusOK, info())
	})
	mux.Handle("/", svcs.admin)
	return mux
}

// adminServices are the handlers the admin listener mounts.
type adminServices struct {
	admin    http.Handler
	decision http.Handler
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
