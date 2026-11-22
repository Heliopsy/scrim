// SPDX-License-Identifier: AGPL-3.0-only

package bws

import (
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/bws.md, "Policy labels").
//
// Secrets Manager's own attributes of a secret go into
// stores.Metadata.Labels under "bws.<attr>": organisation, secret ID, key,
// project names and IDs, and times. Secrets Manager has no user-editable
// metadata besides the note, which is free text that may hold a secret and
// is therefore never a label. Keys are set with stores.SetNative only.

// multiAttrs are the multi-valued attributes: they get presence keys even
// for a single value. The API returns a list of projects per secret, though
// Bitwarden currently allows at most one.
var multiAttrs = []string{"project", "project-id"}

func setTime(labels map[string]string, attr string, t time.Time) {
	if !t.IsZero() {
		stores.SetNative(labels, Kind, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

// labelsFor are the native labels of a secret in the index. They carry
// names and IDs only, never a value or a note.
func labelsFor(e entry, ix *index) map[string]string {
	l := map[string]string{}
	org := e.org
	if org == "" {
		org = ix.org
	}
	stores.SetNative(l, Kind, "org", org)
	stores.SetNative(l, Kind, "id", e.id)
	stores.SetNative(l, Kind, "key", e.key)
	var names, ids []string
	for _, pid := range e.projectIDs {
		ids = append(ids, pid)
		if p, ok := ix.projects[pid]; ok {
			names = append(names, p.name)
		}
	}
	stores.SetNative(l, Kind, "project", names...)
	stores.SetNative(l, Kind, "project-id", ids...)
	setTime(l, "created", e.created)
	setTime(l, "updated", e.revised)
	return l
}

// WriteLabels implements stores.WriteLabeler: the labels a secret written at
// ref would get, from the reference alone. A project written as a UUID is
// taken as its ID, anything else as its name.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	loc, ok := parseLocation(ref.Path)
	if !ok {
		return nil
	}
	l := map[string]string{}
	if loc.id != "" {
		stores.SetNative(l, Kind, "id", loc.id)
		return l
	}
	stores.SetNative(l, Kind, "key", loc.key)
	if uuidPattern.MatchString(loc.projectSel) {
		stores.SetNative(l, Kind, "project-id", strings.ToLower(loc.projectSel))
	} else {
		stores.SetNative(l, Kind, "project", loc.projectSel)
	}
	return l
}
