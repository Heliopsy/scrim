// SPDX-License-Identifier: AGPL-3.0-only

package notify

import (
	"fmt"
	"strings"
	"time"
)

// Field is one labelled line of an approval summary.
type Field struct {
	Label string
	Value string
}

// Fields returns what a notifier shows for r, in display order. It holds
// names and metadata only. The path is shown without its query string,
// which is where an API would carry an inline credential; a query only ever
// holds placeholders, but there is no reason to send even those to a phone.
func Fields(r Request) []Field {
	s := r.Summary
	var out []Field
	add := func(label, value string) {
		if value != "" {
			out = append(out, Field{label, value})
		}
	}
	add("Agent", r.Agent.ID)
	add("Action", string(s.Action))
	if !s.Ref.IsZero() {
		add("Secret", s.Ref.String())
	}
	add("Name", s.Name)
	add("Provider", s.Provider)
	if s.Host != "" {
		path, _, _ := strings.Cut(s.Path, "?")
		add("Destination", strings.TrimSpace(s.Method+" "+s.Host+path))
	}
	add("Tool", strings.TrimSpace(s.Tool+" "+s.Command))
	add("Rule", r.Rule)
	add("Reason", r.Reason)
	if !r.ExpiresAt.IsZero() {
		add("Expires", r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return out
}

// Title is a one-line headline for r.
func Title(r Request) string {
	s := r.Summary
	what := string(s.Action)
	if what == "" {
		what = "request"
	}
	switch {
	case !s.Ref.IsZero() && s.Host != "":
		return fmt.Sprintf("%s: %s %s toward %s", r.Agent.ID, what, s.Ref.String(), s.Host)
	case !s.Ref.IsZero():
		return fmt.Sprintf("%s: %s %s", r.Agent.ID, what, s.Ref.String())
	case s.Host != "":
		return fmt.Sprintf("%s: %s toward %s", r.Agent.ID, what, s.Host)
	}
	return fmt.Sprintf("%s: %s", r.Agent.ID, what)
}

// Text renders the fields as "Label: value" lines.
func Text(r Request) string {
	var b strings.Builder
	for _, f := range Fields(r) {
		fmt.Fprintf(&b, "%s: %s\n", f.Label, f.Value)
	}
	return strings.TrimRight(b.String(), "\n")
}

// Absolute reports whether a decision link is an absolute http(s) URL a
// remote device can open.
func Absolute(link string) bool {
	return strings.HasPrefix(link, "https://") || strings.HasPrefix(link, "http://")
}
