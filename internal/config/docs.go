// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Markers delimit the generated reference inside docs/configuration.md.
const (
	DocsBegin = "<!-- BEGIN GENERATED SETTINGS REFERENCE: edit the registry, then run `just config-docs` -->"
	DocsEnd   = "<!-- END GENERATED SETTINGS REFERENCE -->"
)

// Reference renders the settings reference in Markdown: a summary table and
// one section per setting with its type, default, environment variable,
// flag, reload behaviour, weakening status, accepted values and profile
// values. The output is deterministic.
func Reference(r *Registry) []byte {
	var b bytes.Buffer
	settings := r.Settings()

	b.WriteString("| Key | Type | Default | Reload |\n|---|---|---|---|\n")
	for _, s := range settings {
		fmt.Fprintf(&b, "| [`%s`](#%s) | %s | %s | %s |\n", s.Key, anchor(s.Key), s.Kind, code(docValue(s, s.Default)), reloadText(s))
	}

	cols := r.Collections()
	for _, col := range cols {
		fmt.Fprintf(&b, "| [`%s.<name>.*`](#%s) | collection | empty | %s |\n", col.Key, anchor(col.Key+"name"), map[bool]string{true: "restart required", false: "hot"}[col.RestartRequired])
	}

	for _, col := range cols {
		fmt.Fprintf(&b, "\n### `%s.<name>`\n\n%s\n\n", col.Key, col.Description)
		b.WriteString("| | |\n|---|---|\n")
		fmt.Fprintf(&b, "| Type | collection of named instances (names: lower-case words with dashes) |\n")
		fmt.Fprintf(&b, "| Environment | `%s` (JSON object of instances, replaces the collection); `%s_<NAME>_<FIELD>` for one field |\n", EnvVar(col.Key), EnvVar(col.Key))
		if len(col.RequiredFields) > 0 {
			fmt.Fprintf(&b, "| Required fields | %s |\n", codeList(col.RequiredFields))
		}
		if len(col.SecretFields) > 0 {
			rule := "a literal is warned about"
			if col.RequireReference {
				rule = "literals rejected"
			}
			fmt.Fprintf(&b, "| Secret fields | %s (references; %s) |\n", codeList(col.SecretFields), rule)
		}
		fmt.Fprintf(&b, "| Reload | %s |\n", map[bool]string{true: "restart required", false: "hot"}[col.RestartRequired])
	}

	section := ""
	for _, s := range settings {
		top, _, _ := strings.Cut(s.Key, ".")
		if top != section {
			section = top
			fmt.Fprintf(&b, "\n### %s\n", top)
		}
		fmt.Fprintf(&b, "\n#### `%s`\n\n%s\n\n", s.Key, s.Description)
		b.WriteString("| | |\n|---|---|\n")
		fmt.Fprintf(&b, "| Type | %s |\n", kindText(s))
		fmt.Fprintf(&b, "| Default | %s |\n", code(docValue(s, s.Default)))
		fmt.Fprintf(&b, "| Environment | `%s` |\n", s.EnvVar())
		if s.Flag {
			fmt.Fprintf(&b, "| Flag | `--%s` |\n", s.FlagName())
		} else {
			b.WriteString("| Flag | none |\n")
		}
		fmt.Fprintf(&b, "| Reload | %s |\n", reloadText(s))
		if s.Weakening {
			b.WriteString("| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |\n")
		}
		if len(s.Enum) > 0 {
			vals := make([]string, len(s.Enum))
			for i, v := range s.Enum {
				vals[i] = code(v)
			}
			fmt.Fprintf(&b, "| Values | %s |\n", strings.Join(vals, ", "))
		}
		if len(s.Profiles) > 0 {
			var ps []string
			for _, p := range Profiles {
				if v, ok := s.Profiles[p]; ok {
					ps = append(ps, fmt.Sprintf("%s: %s", p, code(docValue(s, v))))
				}
			}
			fmt.Fprintf(&b, "| Profiles | %s |\n", strings.Join(ps, ", "))
		}
	}
	return b.Bytes()
}

// SpliceReference replaces the generated part of a document (between
// [DocsBegin] and [DocsEnd]) with ref.
func SpliceReference(doc, ref []byte) ([]byte, error) {
	begin := bytes.Index(doc, []byte(DocsBegin))
	end := bytes.Index(doc, []byte(DocsEnd))
	if begin < 0 || end < begin {
		return nil, errors.New("config: document lacks the generated reference markers")
	}
	var out bytes.Buffer
	out.Write(doc[:begin+len(DocsBegin)])
	out.WriteString("\n\n")
	out.Write(ref)
	out.WriteString("\n")
	out.Write(doc[end:])
	return out.Bytes(), nil
}

func codeList(vs []string) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = code(v)
	}
	return strings.Join(out, ", ")
}

func kindText(s *Setting) string {
	switch s.Kind {
	case KindDuration:
		return "duration (`90s`, `5m`, `1h30m`)"
	case KindList:
		return "list of strings (env: JSON array or comma-separated, `\\,` for a comma)"
	case KindMap:
		return "map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`)"
	case KindSecretRef:
		if s.RequireReference {
			return "secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected)"
		}
		return "secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about)"
	case KindString, KindBool, KindInt, KindFloat:
	}
	return string(s.Kind)
}

func reloadText(s *Setting) string {
	if s.RestartRequired {
		return "restart required"
	}
	return "hot"
}

func docValue(s *Setting, v any) string {
	if s.Kind == KindSecretRef {
		if v.(SecretRef) == "" {
			return ""
		}
		return v.(SecretRef).Display()
	}
	return textValue(displayValue(v))
}

func code(v string) string {
	if v == "" {
		return "empty"
	}
	v = strings.ReplaceAll(v, "|", `\|`)
	if strings.Contains(v, "`") {
		return "``" + v + "``"
	}
	return "`" + v + "`"
}

func anchor(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '.' {
			return -1
		}
		return r
	}, key)
}
