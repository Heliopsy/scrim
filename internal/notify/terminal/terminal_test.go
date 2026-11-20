// SPDX-License-Identifier: AGPL-3.0-only

package terminal

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/policy"
)

func TestLine(t *testing.T) {
	var b bytes.Buffer
	n := &Notifier{W: &b}
	err := n.Notify(context.Background(), notify.Request{ApprovalID: "abc", Agent: policy.Agent{ID: "codex"},
		Summary: policy.Request{Action: policy.ActionWrite}, Rule: "writes", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"approval abc pending", "codex: store.write", "scrim approve abc", "scrim deny abc"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in %q", want, b.String())
		}
	}
}
