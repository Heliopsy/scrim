// SPDX-License-Identifier: AGPL-3.0-only

// Command dirstore is an example scrim store plugin (docs/plugins.md): a
// store kept as files in one directory, one JSON file per secret with every
// version it has had.
//
// It exists to show the plugin contract and to run the store conformance
// suite through the plugin bridge. It keeps values unencrypted on disk, so it
// is not a store to keep real secrets in.
//
//	stores:
//	  dir:
//	    kind: plugin
//	    command: /usr/local/libexec/scrim/dirstore
//	    options: {root: /var/lib/scrim-dirstore, poll-interval: 1s}
//
// It imports only the public SDK, github.com/heliopsy/scrim/pkg/plugin, as a
// plugin outside the scrim repository would.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/pkg/plugin"
)

func main() {
	if err := plugin.ServeStore(&store{}); err != nil {
		fmt.Fprintln(os.Stderr, "dirstore:", err)
		os.Exit(1)
	}
}

const suffix = ".secret.json"

type options struct {
	Root         string `json:"root"`
	PollInterval string `json:"poll-interval"`
}

type store struct {
	mu   sync.RWMutex
	root string
	poll time.Duration
}

func (*store) Info() plugin.Info {
	return plugin.Info{Name: "dirstore", Version: "1.0.0", Capabilities: []plugin.Capability{
		plugin.CapRead, plugin.CapList, plugin.CapWatch, plugin.CapWrite,
	}}
}

func parse(c plugin.Config) (options, time.Duration, []string) {
	var o options
	var problems []string
	dec := json.NewDecoder(strings.NewReader(string(c.Options)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		// The decoder's message names the offending key, not a value.
		return o, 0, []string{"options: " + err.Error()}
	}
	if o.Root == "" || !filepath.IsAbs(o.Root) {
		problems = append(problems, "options.root must be an absolute directory path")
	}
	poll := time.Second
	if o.PollInterval != "" {
		d, err := time.ParseDuration(o.PollInterval)
		if err != nil || d < 10*time.Millisecond {
			problems = append(problems, "options.poll-interval must be a duration of at least 10ms")
		}
		poll = d
	}
	for name := range c.Secrets {
		problems = append(problems, "dirstore takes no credentials; remove "+name)
	}
	return o, poll, problems
}

func (*store) ValidateConfig(c plugin.Config) []string {
	_, _, p := parse(c)
	return p
}

func (s *store) Configure(_ context.Context, c plugin.Config) error {
	o, poll, p := parse(c)
	if len(p) > 0 {
		return errors.New(strings.Join(p, "; "))
	}
	s.mu.Lock()
	s.root, s.poll = filepath.Clean(o.Root), poll
	s.mu.Unlock()
	return nil
}

// record is one secret on disk.
type record struct {
	Labels   map[string]string `json:"labels,omitempty"`
	Created  time.Time         `json:"created"`
	Versions []version         `json:"versions"`
}

type version struct {
	N       int               `json:"n"`
	Written time.Time         `json:"written"`
	Fields  map[string][]byte `json:"fields"`
}

func (r *record) latest() version { return r.Versions[len(r.Versions)-1] }

func (r *record) meta(path string, v version) plugin.Metadata {
	return plugin.Metadata{
		Path: path, Fields: slices.Sorted(maps.Keys(v.Fields)), Version: strconv.Itoa(v.N),
		Created: r.Created, Updated: v.Written, Labels: r.Labels,
	}
}

// up returns the root, or ErrUnavailable when the directory is gone: a
// missing root is an outage, never "every secret was deleted".
func (s *store) up() (string, error) {
	s.mu.RLock()
	root := s.root
	s.mu.RUnlock()
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return "", plugin.ErrUnavailable
	}
	return root, nil
}

// file maps a secret path to its file, refusing anything that could step
// outside the root.
func file(root, path string) (string, error) {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return "", plugin.ErrInvalid
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "\\\x00") {
			return "", plugin.ErrInvalid
		}
	}
	return filepath.Join(root, filepath.FromSlash(path)) + suffix, nil
}

func load(name string) (*record, error) {
	b, err := os.ReadFile(name) //nolint:gosec // name is built by file() under the root
	if errors.Is(err, fs.ErrNotExist) {
		return nil, plugin.ErrNotFound
	}
	if err != nil {
		return nil, plugin.ErrUnavailable
	}
	defer clear(b)
	var r record
	if err := json.Unmarshal(b, &r); err != nil || len(r.Versions) == 0 {
		return nil, plugin.ErrUnavailable
	}
	return &r, nil
}

func wipe(r *record) {
	for _, v := range r.Versions {
		for _, b := range v.Fields {
			clear(b)
		}
	}
}

func (s *store) Read(_ context.Context, ref plugin.Ref) (plugin.Secret, error) {
	root, err := s.up()
	if err != nil {
		return plugin.Secret{}, err
	}
	want := 0
	if ref.Selectors != "" {
		q, err := url.ParseQuery(ref.Selectors)
		if err != nil || len(q) != 1 || len(q["version"]) != 1 {
			return plugin.Secret{}, plugin.ErrInvalid
		}
		if want, err = strconv.Atoi(q.Get("version")); err != nil || want < 1 {
			return plugin.Secret{}, plugin.ErrInvalid
		}
	}
	name, err := file(root, ref.Path)
	if err != nil {
		return plugin.Secret{}, err
	}
	s.mu.RLock()
	r, err := load(name)
	s.mu.RUnlock()
	if err != nil {
		return plugin.Secret{}, err
	}
	defer wipe(r)
	v := r.latest()
	if want != 0 {
		i := slices.IndexFunc(r.Versions, func(v version) bool { return v.N == want })
		if i < 0 {
			return plugin.Secret{}, plugin.ErrNotFound
		}
		v = r.Versions[i]
	}
	out := plugin.Secret{Meta: r.meta(ref.Path, v), Fields: map[string][]byte{}}
	for k, b := range v.Fields {
		if ref.Field == "" || ref.Field == k {
			out.Fields[k] = slices.Clone(b)
		}
	}
	if ref.Field != "" && len(out.Fields) == 0 {
		return plugin.Secret{}, plugin.ErrNotFound
	}
	return out, nil
}

// walk calls fn for every secret under prefix.
func (s *store) walk(root, prefix string, fn func(path string, r *record)) error {
	prefix = strings.Trim(prefix, "/")
	dir := root
	if prefix != "" {
		if _, err := file(root, prefix); err != nil {
			return err
		}
		dir = filepath.Join(root, filepath.FromSlash(prefix))
		if r, err := load(dir + suffix); err == nil {
			fn(prefix, r)
			wipe(r)
		}
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == dir {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, suffix) {
			return nil
		}
		rel, err := filepath.Rel(root, strings.TrimSuffix(p, suffix))
		if err != nil {
			return err
		}
		if r, err := load(p); err == nil {
			fn(filepath.ToSlash(rel), r)
			wipe(r)
		}
		return nil
	})
	if err != nil {
		return plugin.ErrUnavailable
	}
	return nil
}

func (s *store) List(_ context.Context, prefix string) ([]plugin.Metadata, error) {
	root, err := s.up()
	if err != nil {
		return nil, err
	}
	var out []plugin.Metadata
	s.mu.RLock()
	defer s.mu.RUnlock()
	err = s.walk(root, prefix, func(path string, r *record) {
		out = append(out, r.meta(path, r.latest()))
	})
	return out, err
}

// Watch polls: it snapshots the versions under prefix and reports what
// differs at every interval. While the root is gone (an outage) it reports
// nothing and picks up where it left off once the root is back.
func (s *store) Watch(ctx context.Context, prefix string) (<-chan plugin.Change, error) {
	root, err := s.up()
	if err != nil {
		return nil, err
	}
	snap := func() (map[string]int, error) {
		m := map[string]int{}
		s.mu.RLock()
		defer s.mu.RUnlock()
		err := s.walk(root, prefix, func(path string, r *record) { m[path] = r.latest().N })
		return m, err
	}
	last, err := snap()
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	poll := s.poll
	s.mu.RUnlock()
	ch := make(chan plugin.Change)
	go func() {
		defer close(ch)
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if _, err := s.up(); err != nil {
				continue
			}
			cur, err := snap()
			if err != nil {
				continue
			}
			var changes []plugin.Change
			for _, p := range slices.Sorted(maps.Keys(cur)) {
				if last[p] != cur[p] {
					changes = append(changes, plugin.Change{Path: p})
				}
			}
			for _, p := range slices.Sorted(maps.Keys(last)) {
				if _, ok := cur[p]; !ok {
					changes = append(changes, plugin.Change{Path: p, Deleted: true})
				}
			}
			last = cur
			for _, c := range changes {
				select {
				case ch <- c:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

func (s *store) Write(_ context.Context, path string, fields map[string][]byte, opts plugin.WriteOptions) (plugin.Metadata, error) {
	root, err := s.up()
	if err != nil {
		return plugin.Metadata{}, err
	}
	name, err := file(root, path)
	if err != nil {
		return plugin.Metadata{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := load(name)
	switch {
	case errors.Is(err, plugin.ErrNotFound):
		r = &record{Created: time.Now().UTC()}
	case err != nil:
		return plugin.Metadata{}, err
	case opts.CreateOnly:
		wipe(r)
		return plugin.Metadata{}, plugin.ErrConflict
	}
	defer wipe(r)
	v := version{N: 1, Written: time.Now().UTC(), Fields: map[string][]byte{}}
	if len(r.Versions) > 0 {
		v.N = r.latest().N + 1
	}
	for k, b := range fields {
		// fields is borrowed: keep a copy.
		v.Fields[k] = slices.Clone(b)
	}
	r.Versions = append(r.Versions, v)
	if opts.Labels != nil {
		r.Labels = maps.Clone(opts.Labels)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return plugin.Metadata{}, plugin.ErrUnavailable
	}
	defer clear(b)
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return plugin.Metadata{}, plugin.ErrUnavailable
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return plugin.Metadata{}, plugin.ErrUnavailable
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), name) != nil {
		_ = os.Remove(tmp.Name())
		return plugin.Metadata{}, plugin.ErrUnavailable
	}
	return r.meta(path, v), nil
}

func (s *store) Health(context.Context) error {
	_, err := s.up()
	return err
}
