// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// SchemaID is the $id of the generated schema for [APIVersion].
const SchemaID = "https://raw.githubusercontent.com/heliopsy/scrim/main/schema/config-v1.json"

// durationPattern accepts a subset of what time.ParseDuration accepts, so a
// file the schema accepts is also accepted by scrim.
const durationPattern = `^[-+]?(0|(([0-9]+(\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h))+)$`

// Schema returns the JSON Schema (draft 2020-12) of the config file for
// [APIVersion], generated from r. It is at least as strict as scrim: types,
// enums, unknown keys and the apiVersion are checked, while cross-setting
// checks and custom validators exist only in scrim. Settings carry
// x-scrim-env, x-scrim-flag, x-scrim-restart-required, x-scrim-weakening
// and x-scrim-secret-ref annotations. The output is deterministic.
func Schema(r *Registry) ([]byte, error) {
	root := obj{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         SchemaID,
		"title":       "scrim configuration file (" + APIVersion + ")",
		"description": "Generated from the scrim settings registry by `scrim config schema`. Do not edit.",
		"type":        "object",
		"required":    []string{keyAPIVersion, keyKind},
	}
	props := obj{
		keyAPIVersion: obj{"description": "Config file format version.", "enum": SupportedAPIVersions},
		keyKind:       obj{"description": "Document kind.", "const": FileKind},
		keyInclude:    includeSchema(),
	}
	place := func(key string, schema obj) {
		parts := strings.Split(key, ".")
		section := props
		for _, p := range parts[:len(parts)-1] {
			next, ok := section[p].(obj)
			if !ok {
				next = obj{"type": "object", "additionalProperties": false, "properties": obj{}}
				section[p] = next
			}
			section = next["properties"].(obj)
		}
		section[parts[len(parts)-1]] = schema
	}
	for _, s := range r.Settings() {
		place(s.Key, settingSchema(s))
	}
	for _, col := range r.Collections() {
		place(col.Key, collectionSchema(col))
	}
	root["properties"] = props
	root["additionalProperties"] = false

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("config: encoding schema: %w", err)
	}
	return buf.Bytes(), nil
}

type obj = map[string]any

// requiredRefPattern matches the empty string or a reference, not a literal.
const requiredRefPattern = `^$|^(env:[A-Za-z_][A-Za-z0-9_]*|file:/.*|cred:[A-Za-z0-9_@.:-]+|[a-z][a-z0-9+.-]*://[^#].*)$`

func settingSchema(s *Setting) obj {
	o := obj{
		"description":              s.Description,
		"default":                  displayValue(s.Default),
		"x-scrim-env":              s.EnvVar(),
		"x-scrim-weakening":        s.Weakening,
		"x-scrim-restart-required": s.RestartRequired,
	}
	if s.Flag {
		o["x-scrim-flag"] = "--" + s.FlagName()
	}
	if len(s.WeakeningValues) > 0 {
		vals := make([]any, len(s.WeakeningValues))
		for i, v := range s.WeakeningValues {
			vals[i] = displayValue(v)
		}
		o["x-scrim-weakening-values"] = vals
	}
	switch s.Kind {
	case KindString:
		o["type"] = "string"
		if len(s.Enum) > 0 {
			o["enum"] = s.Enum
		}
	case KindSecretRef:
		o["type"] = "string"
		o["x-scrim-secret-ref"] = true
		if s.RequireReference {
			o["pattern"] = requiredRefPattern
		}
	case KindBool:
		o["type"] = "boolean"
	case KindInt:
		o["type"] = "integer"
		o["minimum"] = math.MinInt64
		o["maximum"] = math.MaxInt64
	case KindFloat:
		o["type"] = "number"
	case KindDuration:
		o["type"] = "string"
		o["pattern"] = durationPattern
	case KindList:
		o["type"] = "array"
		o["items"] = obj{"type": "string"}
	case KindMap:
		o["type"] = "object"
		o["additionalProperties"] = obj{"type": "string"}
	}
	return o
}

func collectionSchema(col *CollectionSpec) obj {
	fields := obj{}
	for _, f := range col.SecretFields {
		fs := obj{"type": "string", "x-scrim-secret-ref": true}
		if col.RequireReference {
			fs["pattern"] = requiredRefPattern
		}
		fields[f] = fs
	}
	for f, fs := range col.FieldSchemas {
		fields[f] = fs
	}
	inst := obj{"type": "object", "properties": fields}
	if len(col.RequiredFields) > 0 {
		inst["required"] = col.RequiredFields
	}
	return obj{
		"description":              col.Description,
		"type":                     "object",
		"propertyNames":            obj{"pattern": instanceNamePattern.String()},
		"additionalProperties":     inst,
		"x-scrim-collection":       true,
		"x-scrim-env":              EnvVar(col.Key),
		"x-scrim-restart-required": col.RestartRequired,
	}
}

func includeSchema() obj {
	entry := obj{"anyOf": []any{
		obj{"type": "string", "minLength": 1},
		obj{
			"type":                 "object",
			"required":             []string{"path"},
			"additionalProperties": false,
			"properties": obj{
				"path":     obj{"type": "string", "minLength": 1},
				"optional": obj{"type": "boolean"},
			},
		},
	}}
	return obj{
		"description": "Files, globs or directories merged after this file, relative to it.",
		"anyOf":       []any{entry, obj{"type": "array", "items": entry}},
	}
}
