// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// LabelRule derives one label (option `stores.<name>.labels.<label>`).
//
//	labels:
//	  team: vaultwarden.org                      # copy: from
//	  env: {value: prod}                         # constant: value
//	  prod: {from: vaultwarden.collection.Prod, value: "yes"}   # constant when from is set
//	  tier: {from: openbao.path, regex: "^prod/", value: prod}  # when from matches regex
//	  app: {from: store.path, regex: "^apps/([^/]+)/", value: "$1"}
//
// A string is shorthand for {from: <string>}. With from, the label is set
// only when the source label exists (and, with regex, matches). value
// defaults to the source value, or with regex to the matched text; with
// regex, $1 or ${name} in value expand to submatches.
type LabelRule struct {
	From  string
	Regex *regexp.Regexp
	Value string
	// hasValue distinguishes value: "" from no value.
	hasValue bool
}

// LabelMapping is an instance's derived labels by name.
type LabelMapping map[string]LabelRule

// ParseLabelMapping decodes the `labels` option of a store instance of
// kind. raw is the decoded YAML (a map of label name to string or object).
// Names must be label keys ([LabelKey] leaves them unchanged) and may not
// claim a reserved prefix: store., scrim., or any registered adapter kind's
// (a bare name such as "env" is fine: reserved keys always have a dot).
func ParseLabelMapping(kind string, raw any) (LabelMapping, error) {
	if raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("labels must be a map of label name to source")
	}
	out := LabelMapping{}
	var errs []error
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, name := range names {
		r, err := parseLabelRule(m[name])
		if err == nil {
			err = checkLabelName(kind, name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("labels.%s: %w", name, err))
			continue
		}
		out[name] = r
	}
	return out, errors.Join(errs...)
}

func checkLabelName(kind, name string) error {
	if LabelKey(name) != name {
		return fmt.Errorf("label names are lower-case letters, digits, '-' and '_' separated by dots (%q would be %q)", name, LabelKey(name))
	}
	reserved := append([]string{strings.TrimSuffix(StoreLabelPrefix, "."), strings.TrimSuffix(ScrimLabelPrefix, "."), kind},
		DefaultRegistry.Kinds()...)
	head, _, dotted := strings.Cut(name, ".")
	if dotted && slices.Contains(reserved, head) {
		return fmt.Errorf("%s. is reserved for labels scrim or a store adapter sets", head)
	}
	return nil
}

func parseLabelRule(raw any) (LabelRule, error) {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return LabelRule{}, errors.New("source label is empty")
		}
		return LabelRule{From: v}, nil
	case map[string]any:
		var r LabelRule
		for k, x := range v {
			s, ok := x.(string)
			if !ok {
				return LabelRule{}, fmt.Errorf("%s must be a string", k)
			}
			switch k {
			case "from":
				r.From = s
			case "value":
				r.Value, r.hasValue = s, true
			case "regex":
				re, err := regexp.Compile(s)
				if err != nil {
					return LabelRule{}, fmt.Errorf("regex: %w", err)
				}
				r.Regex = re
			default:
				return LabelRule{}, fmt.Errorf("unknown field %s (from, regex, value)", k)
			}
		}
		if r.From == "" && !r.hasValue {
			return LabelRule{}, errors.New("needs from, value, or both")
		}
		if r.Regex != nil && r.From == "" {
			return LabelRule{}, errors.New("regex needs from")
		}
		return r, nil
	}
	return LabelRule{}, errors.New("must be a source label name or {from, regex, value}")
}

// derive computes the rule's value from labels.
func (r LabelRule) derive(labels map[string]string) (string, bool) {
	if r.From == "" {
		return r.Value, true
	}
	src, ok := labels[r.From]
	if !ok {
		return "", false
	}
	if r.Regex == nil {
		if r.hasValue {
			return r.Value, true
		}
		return src, true
	}
	idx := r.Regex.FindStringSubmatchIndex(src)
	if idx == nil {
		return "", false
	}
	if !r.hasValue {
		return src[idx[0]:idx[1]], true
	}
	return string(r.Regex.ExpandString(nil, r.Value, src, idx)), true
}

// apply adds the derived labels to labels. Sources are read from labels as
// they were before any rule ran, so the order of rules does not matter, and
// no rule replaces a key already present.
func (m LabelMapping) apply(labels map[string]string) {
	if len(m) == 0 {
		return
	}
	derived := map[string]string{}
	for name, r := range m {
		if _, taken := labels[name]; taken {
			continue
		}
		if v, ok := r.derive(labels); ok {
			derived[name] = v
		}
	}
	for k, v := range derived {
		labels[k] = v
	}
}
