// SPDX-License-Identifier: AGPL-3.0-only

package status

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestInstalledServiceIsReported(t *testing.T) {
	sv := &Service{Mode: "system", System: true, Unit: "scrim.service", Active: "active", Manifest: "/etc/scrim/install.json"}
	r := Collect(context.Background(), Sources{Service: sv})
	for _, c := range r.Degraded {
		if strings.HasPrefix(c.Name, "service:") {
			t.Errorf("an active service is degraded: %+v", c)
		}
	}
	var b bytes.Buffer
	if err := WriteHuman(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "scrim.service: active (system service, manifest /etc/scrim/install.json)") {
		t.Errorf("human output:\n%s", b.String())
	}

	sv.Active = "failed"
	r = Collect(context.Background(), Sources{Service: sv})
	found := false
	for _, c := range r.Degraded {
		found = found || (c.Name == "service:scrim.service" && strings.Contains(c.Reason, "failed"))
	}
	if !found {
		t.Errorf("a failed service is not degraded: %+v", r.Degraded)
	}
}

func TestNoServiceNoSection(t *testing.T) {
	var b bytes.Buffer
	if err := WriteHuman(&b, Collect(context.Background(), Sources{})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Service\n") {
		t.Errorf("service section without an install:\n%s", b.String())
	}
}
