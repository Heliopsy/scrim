// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/config"
)

var update = flag.Bool("update", false, "rewrite the generated route tables in docs/providers/README.md")

// The route tables in docs/providers/README.md are generated from the
// snapshot's routes: the built-in ones of a default configuration, and the
// gate provider name of each cloud provider kind. Rewrite them with
//
//	go test ./internal/daemon -run TestProviderRouteDocs -update
const (
	routeDocsBegin = "<!-- BEGIN GENERATED PROVIDER ROUTES: run `go test ./internal/daemon -run TestProviderRouteDocs -update` -->"
	routeDocsEnd   = "<!-- END GENERATED PROVIDER ROUTES -->"
)

func providerRouteTables(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("Built-in routes, served without configuration:\n\n")
	b.WriteString("| Route | Gate `provider` | Hosts (forward proxy, transparent) | Upstream setting | Default upstream |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, r := range routes(buildConfig(t, "")) {
		key := "proxy.upstream." + r.GetName()
		if _, ok := config.Default.Lookup(key); !ok {
			t.Errorf("built-in route %s has no setting %s", r.GetName(), key)
		}
		if r.GetPathPrefix() != "/"+r.GetName() {
			t.Errorf("built-in route %s is served at %s, not /%s", r.GetName(), r.GetPathPrefix(), r.GetName())
		}
		fmt.Fprintf(&b, "| `/%s` | `%s` | `%s` | `%s` | `%s` |\n", r.GetName(), r.GetProvider(),
			strings.Join(r.GetHosts(), "`, `"), key, r.GetUpstream())
	}
	b.WriteString("\nCloud provider kinds:\n\n")
	b.WriteString("| Kind | Gate `provider` |\n| --- | --- |\n")
	for _, k := range ProviderKinds {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, CloudProvider{Name: k, Kind: k}.Route().GetProvider())
	}
	return b.String()
}

func TestProviderRouteDocs(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "providers", "README.md")
	doc, err := os.ReadFile(path) // #nosec G304 -- fixed path in the repository
	if err != nil {
		t.Fatal(err)
	}
	begin := bytes.Index(doc, []byte(routeDocsBegin))
	end := bytes.Index(doc, []byte(routeDocsEnd))
	if begin < 0 || end < begin {
		t.Fatalf("%s lacks the generated provider route markers", path)
	}
	var want bytes.Buffer
	want.Write(doc[:begin+len(routeDocsBegin)])
	want.WriteString("\n\n" + providerRouteTables(t) + "\n")
	want.Write(doc[end:])
	if bytes.Equal(doc, want.Bytes()) {
		return
	}
	if *update {
		if err := os.WriteFile(path, want.Bytes(), 0o644); err != nil { // #nosec G306 -- a document in the repository
			t.Fatal(err)
		}
		return
	}
	t.Error("docs/providers/README.md route tables are out of date: run " +
		"`go test ./internal/daemon -run TestProviderRouteDocs -update`")
}
