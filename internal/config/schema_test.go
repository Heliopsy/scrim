// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/config"
)

func compileSchema(t *testing.T, r *config.Registry) *jsonschema.Schema {
	t.Helper()
	raw, err := config.Schema(r)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(config.SchemaID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(config.SchemaID)
	if err != nil {
		t.Fatalf("generated schema does not compile: %v", err)
	}
	return s
}

// yamlInstance turns a YAML document into the JSON value a schema
// validator sees.
func yamlInstance(t *testing.T, doc string) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestSchemaGolden(t *testing.T) {
	w := newWorld(t)
	raw, err := config.Schema(w.reg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "schema.json", raw)
	again, _ := config.Schema(w.reg)
	if !bytes.Equal(raw, again) {
		t.Fatal("schema output is not deterministic")
	}
}

// TestSchemaAgreesWithScrim checks the published-schema contract: a file the
// schema accepts is accepted by scrim, and the files below that scrim
// rejects for type, enum, key or version reasons are rejected by the schema
// too. Custom validators (proxy.workers >= 1) are outside the schema by
// design and not exercised here.
func TestSchemaAgreesWithScrim(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"minimal", header, true},
		{"nested", header + "approvals:\n  timeout: 90s\nlog:\n  level: debug\n", true},
		{"all kinds", header + `proxy:
  no-proxy: [a, b]
  upstream: {anthropic: "http://x"}
  workers: 3
redaction:
  entropy-threshold: 3.5
  allow-unredacted-on-error: false
stores:
  openbao:
    token: env:TOKEN
`, true},
		{"include", header + "include: [{path: x.yaml, optional: true}]\n", true},
		{"compound duration", header + "approvals:\n  timeout: 1h30m\n", true},
		{"bad version", "apiVersion: scrim.dev/v9\nkind: Config\n", false},
		{"no version", "kind: Config\n", false},
		{"wrong kind", "apiVersion: scrim.dev/v1\nkind: Policy\n", false},
		{"unknown key", header + "aprovals:\n  timeout: 60s\n", false},
		{"unknown section key", header + "log:\n  levle: info\n", false},
		{"bad enum", header + "log:\n  level: loud\n", false},
		{"bad duration", header + "approvals:\n  timeout: soon\n", false},
		{"int duration", header + "approvals:\n  timeout: 60\n", false},
		{"string for int", header + "proxy:\n  workers: lots\n", false},
		{"float for int", header + "proxy:\n  workers: 1.5\n", false},
		{"list for scalar", header + "log:\n  level: [info]\n", false},
		{"scalar for list", header + "proxy:\n  no-proxy: localhost\n", false},
		{"nested map value", header + "proxy:\n  upstream: {a: {b: c}}\n", false},
		{"literal where reference required", header + "stores:\n  openbao:\n    token: hunter2hunter2\n", false},
		{"null", header + "log:\n  level:\n", false},
		{"section as scalar", header + "log: info\n", false},
		{"bad include field", header + "include: [{path: x.yaml, required: true}]\n", false},
	}
	w := newWorld(t)
	w.setenv("TOKEN=value-from-env")
	s := compileSchema(t, w.reg)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schemaErr := s.Validate(yamlInstance(t, tc.doc))
			_, scrimErr := buildDoc(t, w, tc.doc)
			if (schemaErr == nil) != tc.ok {
				t.Errorf("schema: ok = %v, want %v (%v)", schemaErr == nil, tc.ok, schemaErr)
			}
			if (scrimErr == nil) != tc.ok {
				t.Errorf("scrim: ok = %v, want %v (%v)", scrimErr == nil, tc.ok, scrimErr)
			}
		})
	}
}

func buildDoc(t *testing.T, w *world, doc string) (*config.Config, error) {
	t.Helper()
	p := w.file("doc.yaml", doc)
	return config.Build(w.opts(p))
}

func TestSchemaOfDefaultRegistryCompiles(t *testing.T) {
	compileSchema(t, config.Default)
}
