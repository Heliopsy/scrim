// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"

	"github.com/heliopsy/scrim/internal/localapi"
)

// redact serves the local API's POST /v1/redact through the data plane's
// Redact call: the same redactor and guard a provider request passes. The
// data plane refuses when it has no snapshot or the guard withholds, so an
// error here never comes with the text.
func (d *Daemon) redact(ctx context.Context, text []byte) (localapi.Redacted, error) {
	resp, err := d.sup.Redact(ctx, text)
	if err != nil {
		return localapi.Redacted{}, err
	}
	return localapi.Redacted{Text: resp.GetText(), Replacements: int(resp.GetReplacements()), Refs: resp.GetRefs()}, nil
}
