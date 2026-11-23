// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/heliopsy/scrim/internal/stores"
)

// Reference paths (docs/stores/kubernetes.md "References").
//
// A Secret's name is a DNS subdomain: DNS labels joined by dots. A reference
// writes each dot as a slash, so the name's labels are path segments and a
// folder prefix selects a dotted family of names:
//
//	namespaces mode:  <instance>://<namespace>/<label>[/<label>...][#key]
//	namespace mode:   <instance>://<label>[/<label>...][#key]
//
// `k8s://prod/db-credentials` is Secret db-credentials in namespace prod;
// `k8s://prod/tls/example/com` is Secret tls.example.com. The mapping is one
// to one, so a reference, a listed path and a watched path always agree. A
// segment that is not a DNS label (upper case, a dot, an underscore) is an
// invalid reference, never a different Secret.

// target is one Secret, or a selection of Secrets, in one namespace.
type target struct {
	ns string
	// name is the Secret name, or for a prefix the name prefix ("" is
	// every Secret in the namespace).
	name string
}

// path is the reference path of Secret name in ns.
func (a *Adapter) path(ns, name string) string {
	p := strings.ReplaceAll(name, ".", "/")
	if a.cfg.namespaced() {
		return p
	}
	return ns + "/" + p
}

// secretTarget parses the path of a reference to one Secret.
func (a *Adapter) secretTarget(op stores.Op, ref stores.Ref) (target, error) {
	ns, rest, err := a.splitNamespace(op, ref, ref.Path)
	if err != nil {
		return target{}, err
	}
	if rest == "" {
		return target{}, a.err(op, ref, stores.ErrInvalidRef, "the reference names a namespace, not a secret")
	}
	name, err := a.secretName(op, ref, rest)
	if err != nil {
		return target{}, err
	}
	return target{ns: ns, name: name}, nil
}

// splitNamespace takes the namespace off p (or uses the configured one) and
// checks it is allowed.
func (a *Adapter) splitNamespace(op stores.Op, ref stores.Ref, p string) (ns, rest string, err error) {
	if a.cfg.namespaced() {
		return a.cfg.Namespace, p, nil
	}
	ns, rest, _ = strings.Cut(p, "/")
	if len(validation.IsDNS1123Label(ns)) > 0 {
		return "", "", a.err(op, ref, stores.ErrInvalidRef, "the path must start with a namespace")
	}
	if !a.cfg.allowed(ns) {
		return "", "", a.err(op, ref, stores.ErrPermission, "namespace "+ns+" is not in this store's namespaces")
	}
	return ns, rest, nil
}

// secretName turns path segments into a Secret name.
func (a *Adapter) secretName(op stores.Op, ref stores.Ref, p string) (string, error) {
	for seg := range strings.SplitSeq(p, "/") {
		if len(validation.IsDNS1123Label(seg)) > 0 {
			return "", a.err(op, ref, stores.ErrInvalidRef,
				"each path segment must be a lower-case DNS label; write the dots of a secret name as /")
		}
	}
	name := strings.ReplaceAll(p, "/", ".")
	if len(name) > validation.DNS1123SubdomainMaxLength {
		return "", a.err(op, ref, stores.ErrInvalidRef, "secret name too long")
	}
	return name, nil
}

// selection is what a List or Watch prefix selects.
type selection struct {
	// namespaces to look in.
	namespaces []string
	// prefix is the name prefix; glob says it is a plain string prefix
	// rather than whole labels.
	prefix string
	glob   bool
}

// match reports whether Secret name is selected.
func (s selection) match(name string) bool {
	switch {
	case s.prefix == "":
		return true
	case s.glob:
		return strings.HasPrefix(name, s.prefix)
	default:
		return name == s.prefix || strings.HasPrefix(name, s.prefix+".")
	}
}

// selectionFor parses a List or Watch prefix. A trailing `/*` or `/` is a
// folder; a `*` right after part of a segment is a glob (stores.CapGlob).
// An empty path or `*` selects every configured namespace.
func (a *Adapter) selectionFor(op stores.Op, prefix stores.Ref) (selection, error) {
	if prefix.Selectors != "" {
		return selection{}, a.err(op, prefix, stores.ErrInvalidRef, "the kubernetes source has no version selectors")
	}
	p := strings.Trim(strings.TrimSuffix(strings.TrimSuffix(prefix.Path, "*"), "/"), "/")
	glob := strings.HasSuffix(prefix.Path, "*") && !strings.HasSuffix(prefix.Path, "/*") && p != ""
	if strings.Contains(p, "*") {
		return selection{}, a.err(op, prefix, stores.ErrInvalidRef, "only a trailing * is allowed")
	}
	if p == "" {
		return selection{namespaces: a.cfg.all()}, nil
	}
	if !a.cfg.namespaced() && glob && !strings.Contains(p, "/") {
		return selection{}, a.err(op, prefix, stores.ErrInvalidRef, "a glob must follow part of a secret name, not a namespace")
	}
	ns, rest, err := a.splitNamespace(op, prefix, p)
	if err != nil {
		return selection{}, err
	}
	sel := selection{namespaces: []string{ns}, glob: glob}
	if rest == "" {
		return sel, nil
	}
	if glob {
		// The last segment may be a partial label ("app-"), so check the
		// complete segments only and the partial one loosely.
		head, last := "", rest
		if i := strings.LastIndexByte(rest, '/'); i >= 0 {
			head, last = rest[:i], rest[i+1:]
		}
		if head != "" {
			if _, err := a.secretName(op, prefix, head); err != nil {
				return selection{}, err
			}
			head += "."
		}
		for _, c := range last {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return selection{}, a.err(op, prefix, stores.ErrInvalidRef, "a glob prefix must be part of a lower-case DNS label")
			}
		}
		sel.prefix = strings.ReplaceAll(head, "/", ".") + last
		return sel, nil
	}
	name, err := a.secretName(op, prefix, rest)
	if err != nil {
		return selection{}, err
	}
	sel.prefix = name
	return sel, nil
}
