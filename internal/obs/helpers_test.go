// SPDX-License-Identifier: AGPL-3.0-only

package obs

import (
	"context"
	"net/http"
)

func httpHandlerFunc(fn func(ctx context.Context)) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { fn(r.Context()) })
}
