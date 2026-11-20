// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"regexp"
	"unicode/utf8"
)

// maxRefLen bounds a reference.
const maxRefLen = 512

// refShape accepts a store reference (scheme://path[#field]) or a catalog
// name. The store adapters parse references fully; this check keeps
// malformed input out of policy, audit and error messages.
var refShape = regexp.MustCompile(`^(?:[a-z][a-z0-9+.-]*://[^\s#]+(?:#[^\s#]+)?|[A-Za-z0-9][A-Za-z0-9_./:-]*)$`)

var storeShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func checkRef(ref string) error {
	if ref == "" {
		return Errorf(CodeInvalid, "ref is required")
	}
	if len(ref) > maxRefLen || !utf8.ValidString(ref) || !refShape.MatchString(ref) {
		return Errorf(CodeInvalid, "ref is not a store reference or catalog name")
	}
	return nil
}

func checkStore(store string) error {
	if store != "" && !storeShape.MatchString(store) {
		return Errorf(CodeInvalid, "store is not a valid store name")
	}
	return nil
}
