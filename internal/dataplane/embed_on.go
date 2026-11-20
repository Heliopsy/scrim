// SPDX-License-Identifier: AGPL-3.0-only

//go:build embed_dataplane

package dataplane

import _ "embed"

// embedded is the scrim-dataplane binary `just build` copies here.
//
//go:embed embedded/scrim-dataplane
var embedded []byte
