// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// projectValueStore is the store name project values carry in the snapshot,
// and ProjectScheme the scheme of their references
// (project://<file>#<key>). Neither is a configured store: the references
// only name where a value was found, so placeholders and audit entries say
// so. They are redacted and never injected.
const (
	projectValueStore = "scrim-project"
	ProjectScheme     = "project"
)

// projectValues holds the values `scrim run` found in each session's
// project files (specs/credential-injection "Secrets in project files"),
// until the session ends. The copies live in memory only and are wiped when
// replaced, when the session ends and on Close.
type projectValues struct {
	mu       sync.Mutex
	sessions map[string][]projectValue
	// apply pushes a snapshot holding the current set and returns once the
	// data plane applied it.
	apply func(ctx context.Context) error
}

type projectValue struct {
	ref stores.Ref
	v   secret.Value
}

func newProjectValues(apply func(ctx context.Context) error) *projectValues {
	return &projectValues{sessions: map[string][]projectValue{}, apply: apply}
}

// Store implements ValueSource.
func (p *projectValues) Store() string { return projectValueStore }

// EachValue implements ValueSource.
func (p *projectValues) EachValue(fn func(refresh.Source, secret.Value)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := make([]string, 0, len(p.sessions))
	for id := range p.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, v := range p.sessions[id] {
			fn(refresh.Source{Ref: v.ref}, v.v)
		}
	}
}

// set replaces a session's values (taking ownership of them) and applies
// the new snapshot before returning, so the agent's first request is
// already redacted.
func (p *projectValues) set(ctx context.Context, session string, values []localapi.NamedValue) error {
	if session == "" {
		for _, v := range values {
			v.Value.Wipe()
		}
		return errors.New("project values need a session")
	}
	vs := make([]projectValue, 0, len(values))
	for _, v := range values {
		vs = append(vs, projectValue{ref: projectRef(v.Name), v: v.Value})
	}
	p.mu.Lock()
	for _, old := range p.sessions[session] {
		old.v.Wipe()
	}
	if len(vs) == 0 {
		delete(p.sessions, session)
	} else {
		p.sessions[session] = vs
	}
	p.mu.Unlock()
	if p.apply == nil {
		return nil
	}
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.apply(actx)
}

// projectRef is project://<file>#<key>; a name without a file or key falls
// back to project://values#<name>.
func projectRef(name string) stores.Ref {
	file, key, ok := strings.Cut(name, "#")
	file = strings.Trim(file, "/")
	if !ok || file == "" || key == "" || strings.Contains(file, "//") {
		return stores.Ref{Scheme: ProjectScheme, Path: "values", Field: strings.ReplaceAll(name, "#", "_")}
	}
	return stores.Ref{Scheme: ProjectScheme, Path: file, Field: key}
}

// end drops a session's values and reports whether it had any.
func (p *projectValues) end(session string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	vs, ok := p.sessions[session]
	for _, v := range vs {
		v.v.Wipe()
	}
	delete(p.sessions, session)
	return ok
}

// prune drops the values of sessions active reports as over.
func (p *projectValues) prune(active func(id string) bool) bool {
	p.mu.Lock()
	ids := make([]string, 0, len(p.sessions))
	for id := range p.sessions {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	gone := false
	for _, id := range ids {
		if !active(id) && p.end(id) {
			gone = true
		}
	}
	return gone
}

func (p *projectValues) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, vs := range p.sessions {
		for _, v := range vs {
			v.v.Wipe()
		}
		delete(p.sessions, id)
	}
}
