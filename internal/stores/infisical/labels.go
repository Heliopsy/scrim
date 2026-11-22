// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/infisical.md, "Policy labels").
//
// Infisical's own attributes of a secret go into stores.Metadata.Labels
// under "infisical.<attr>", so policy rules can match on project,
// environment, folder, tags and the rest. User-editable secret metadata goes
// under "infisical.meta.<key>". Every user-supplied key in the "infisical."
// namespace is dropped and native keys are set before user metadata, which
// never overwrites a key, so metadata cannot forge a native attribute.
// Labels hold metadata only, never a value.
//
// Keys are set with the shared helpers stores.SetNative and stores.UserMeta
// (internal/stores/labels.go); the multi-valued attributes are declared in
// init with stores.DeclareMulti.

// labelPrefix is the namespace of every label this adapter derives.
const labelPrefix = Kind + "."

// multiAttrs are the multi-valued attributes: they get presence keys even
// for a single value.
var multiAttrs = []string{"tag", "encrypted-meta"}

// setBool sets a boolean native attribute to "true" or "false".
func setBool(labels map[string]string, attr string, v bool) {
	stores.SetNative(labels, Kind, attr, strconv.FormatBool(v))
}

// setTime sets a timestamp attribute in RFC 3339, UTC, when it is known.
func setTime(labels map[string]string, attr string, t time.Time) {
	if !t.IsZero() {
		stores.SetNative(labels, Kind, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

// isReserved reports whether a user-supplied label key falls in the
// adapter's namespace and must not be taken as given. The check ignores case
// and surrounding space, so "Infisical.Environment" cannot pose as a native
// key to a reader that folds case.
func isReserved(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), labelPrefix)
}

// folderKeys sets infisical.folder to the folder path as Infisical spells it
// ("/" or "/db/Primary") and one presence key per folder on the way down,
// with the folder names verbatim joined by dots: infisical.folder.db and
// infisical.folder.db.Primary. Infisical folder names are ASCII letters,
// digits, '-' and '_', so the dotted form is unambiguous.
func folderKeys(labels map[string]string, folder string) {
	folder = "/" + strings.Trim(folder, "/")
	stores.SetNative(labels, Kind, "folder", folder)
	key := stores.NativeKey(Kind, "folder")
	acc := ""
	for _, seg := range strings.Split(strings.Trim(folder, "/"), "/") {
		if seg == "" {
			continue
		}
		if acc != "" {
			acc += "."
		}
		acc += seg
		labels[key+"."+acc] = "true"
	}
}
