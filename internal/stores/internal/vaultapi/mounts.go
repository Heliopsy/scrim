// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// MountInfo is what sys/internal/ui/mounts or sys/mounts says about a
// mount.
type MountInfo struct {
	// Path is the mount path with its trailing slash, as
	// sys/internal/ui/mounts/<path> reports it for any path inside the
	// mount. sys/mounts/<mount> leaves it empty.
	Path           string            `json:"path"`
	Type           string            `json:"type"`
	Description    string            `json:"description"`
	Accessor       string            `json:"accessor"`
	Local          bool              `json:"local"`
	SealWrap       bool              `json:"seal_wrap"`
	PluginVersion  string            `json:"plugin_version"`
	Options        map[string]string `json:"options"`
	Config         map[string]any    `json:"config"`
	ExternalAccess bool              `json:"external_entropy_access"`
}

// Engine names the secrets engine: kv-v2 or kv-v1 for KV, else the type.
func (m *MountInfo) Engine() string {
	if m.IsKV() {
		if m.Options["version"] == "2" {
			return "kv-v2"
		}
		return "kv-v1"
	}
	return m.Type
}

// IsKV reports whether the mount is a KV engine of either version.
func (m *MountInfo) IsKV() bool { return m.Type == "kv" || m.Type == "generic" }

// MountPath is Path without its trailing slash.
func (m *MountInfo) MountPath() string { return strings.Trim(m.Path, "/") }

// MountTTL is how long mount information, or the lack of it, is kept.
const MountTTL = 5 * time.Minute

type mountEntry struct {
	info *MountInfo
	at   time.Time
}

// MountCache keeps mount information per key (a mount or a path).
type MountCache struct {
	mu sync.Mutex
	m  map[string]mountEntry
}

// Get returns the entry for key if it is younger than MountTTL. A cached
// nil means the lookup failed and is not to be retried yet.
func (c *MountCache) Get(key string, now time.Time) (*MountInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.Sub(e.at) >= MountTTL {
		return nil, false
	}
	return e.info, true
}

// Put records info (nil for a failed lookup) for key.
func (c *MountCache) Put(key string, info *MountInfo, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]mountEntry{}
	}
	c.m[key] = mountEntry{info: info, at: now}
}

// Mount returns the information of the mount at mount (or, through
// sys/internal/ui/mounts, of the mount holding the path mount), using and
// filling cache: at most one lookup per key per MountTTL. It is optional: a
// refusal or any other failure gives nil and is remembered for the same
// time, so a token without access costs one request per mount per period,
// not one per read. sys/internal/ui/mounts answers any token with a
// capability on the mount; sys/mounts/<path> needs read on that sys path.
func (c *Client) Mount(ctx context.Context, cache *MountCache, ref stores.Ref, mount string) *MountInfo {
	now := c.Now()
	if info, ok := cache.Get(mount, now); ok {
		return info
	}
	var info *MountInfo
	for _, p := range []string{"sys/internal/ui/mounts/", "sys/mounts/"} {
		if info = c.fetchMount(ctx, ref, p+EscapePath(mount)); info != nil {
			break
		}
	}
	if ctx.Err() == nil {
		cache.Put(mount, info, now)
	}
	return info
}

func (c *Client) fetchMount(ctx context.Context, ref stores.Ref, path string) *MountInfo {
	resp, err := c.Do(ctx, Request{Op: stores.OpRead, Ref: ref, Method: http.MethodGet, Path: path, Optional: true})
	defer resp.Wipe()
	if err != nil {
		return nil
	}
	var mr struct {
		Data *MountInfo `json:"data"`
	}
	if json.Unmarshal(resp.Body, &mr) != nil || mr.Data == nil || mr.Data.Type == "" {
		return nil
	}
	return mr.Data
}
