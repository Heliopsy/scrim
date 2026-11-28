// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"path/filepath"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

// TestOwnPathsOnlyUsedFeatures: with every setting linked into scrim at its
// default, no key-material setting is one of scrim's own files, so a
// default path of an unused feature (the pod's service account token for
// Kubernetes identity) never makes scrim run refuse inside a pod. Turning
// Kubernetes identity on lists its token file.
func TestOwnPathsOnlyUsedFeatures(t *testing.T) {
	dir := t.TempDir()
	base := []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "XDG_STATE_HOME=" + dir}
	build := func(extra ...string) *config.Config {
		t.Helper()
		c, err := config.Build(config.Options{Environ: append(append([]string{}, base...), extra...), SystemDir: filepath.Join(dir, "etc")})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, p := range build().OwnPaths() {
		if p.Origin != config.OwnOriginStateDir && p.Origin != config.OwnOriginConfigFile {
			t.Errorf("defaults list %s (%s) as scrim's own file", p.Path, p.Origin)
		}
	}

	token := filepath.Join(dir, "sa", "token")
	found := false
	for _, p := range build("SCRIM_IDENTITY_KUBERNETES_ENABLED=true", "SCRIM_IDENTITY_KUBERNETES_TOKEN_FILE="+token).OwnPaths() {
		if p.Path == token && p.Origin == "identity.kubernetes.token-file" {
			found = true
		}
	}
	if !found {
		t.Error("Kubernetes identity on: its token file is not listed")
	}
}
