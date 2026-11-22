// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"bytes"
	"fmt"
	"strings"
)

// Field addressing.
//
// A field is named the way op:// references name it: its label, or
// "<section>/<label>" when it sits in a section that has a label. Fields in
// the unnamed default section (built-in username, password and notes, and
// custom fields added without a section) are named by label alone. A field
// without a label is named by its ID. When two fields of an item would get
// the same name, each of them is named by its field ID instead, so a
// whole-item read never drops one.
//
// A field selector (the #fragment of a reference) matches, in order:
//
//  1. a field whose name above is exactly the selector;
//  2. for "<section>/<field>": the fields whose section label or ID is
//     <section> and whose label or ID is <field>;
//  3. otherwise: the fields whose label or ID is the selector, in any
//     section.
//
// Exactly one match is required; several are refused as ambiguous rather
// than picking one.

// fieldView is one field with the names it answers to.
type fieldView struct {
	f            *apiField
	key          string
	sectionID    string
	sectionLabel string
}

// fieldViews names every field of it.
func fieldViews(it *apiItem) []fieldView {
	labels := map[string]string{}
	for _, s := range it.Sections {
		labels[s.ID] = s.Label
	}
	out := make([]fieldView, 0, len(it.Fields))
	count := map[string]int{}
	for i := range it.Fields {
		f := &it.Fields[i]
		v := fieldView{f: f}
		if f.Section != nil {
			v.sectionID = f.Section.ID
			v.sectionLabel = labels[f.Section.ID]
		}
		base := f.Label
		if base == "" {
			base = f.ID
		}
		v.key = base
		if v.sectionLabel != "" {
			v.key = v.sectionLabel + "/" + base
		}
		count[v.key]++
		out = append(out, v)
	}
	for i := range out {
		if count[out[i].key] > 1 {
			out[i].key = out[i].f.ID
		}
	}
	return out
}

// hasValue reports whether the field holds a value to return. Fields
// without one (an empty username, a field Connect lists without a value)
// are not part of the secret.
func (v fieldView) hasValue() bool {
	b := bytes.TrimSpace(v.f.Value)
	return len(b) > 0 && !bytes.Equal(b, []byte(`""`)) && !bytes.Equal(b, []byte("null"))
}

// selectField finds the one field sel names. It returns an error message
// (no value) and whether the failure is "not found" rather than ambiguous.
func selectField(views []fieldView, sel string) (*fieldView, string, bool) {
	for i := range views {
		if views[i].key == sel {
			return &views[i], "", false
		}
	}
	var hits []int
	if sec, name, ok := strings.Cut(sel, "/"); ok {
		for i, v := range views {
			if (v.sectionLabel == sec || (v.sectionID != "" && v.sectionID == sec)) && (v.f.Label == name || v.f.ID == name) {
				hits = append(hits, i)
			}
		}
	} else {
		for i, v := range views {
			if v.f.Label == sel || v.f.ID == sel {
				hits = append(hits, i)
			}
		}
	}
	switch len(hits) {
	case 0:
		return nil, "no field " + quote(sel), true
	case 1:
		return &views[hits[0]], "", false
	}
	return nil, fmt.Sprintf("%d fields match %s; name the section (<section>/<field>) or use the field ID", len(hits), quote(sel)), false
}

// splitFieldName splits a field name given to Write into its section label
// (empty for the default section) and field label.
func splitFieldName(name string) (section, label string, ok bool) {
	if name == "" {
		return "", "", false
	}
	sec, lab, cut := strings.Cut(name, "/")
	if !cut {
		return "", name, true
	}
	if sec == "" || lab == "" || strings.Contains(lab, "/") {
		return "", "", false
	}
	return sec, lab, true
}
