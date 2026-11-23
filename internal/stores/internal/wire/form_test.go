// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"net/url"
	"testing"

	"github.com/heliopsy/scrim/internal/secret"
)

func TestAppendForm(t *testing.T) {
	v := secret.FromString("a.b-c_d~e f/+=&%é")
	b := AppendForm(nil, "grant_type", []byte("urn:x"))
	b = AppendFormValue(b, "subject_token", v)
	q, err := url.ParseQuery(string(b))
	if err != nil || q.Get("grant_type") != "urn:x" || q.Get("subject_token") != "a.b-c_d~e f/+=&%é" {
		t.Fatalf("%s: %v %v", b, q, err)
	}
}
