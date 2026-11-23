// SPDX-License-Identifier: AGPL-3.0-only

package azkv

import (
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/azure.md, "Policy labels").
//
// Key Vault's own attributes of a secret version go into
// stores.Metadata.Labels under "azkv.<attr>". Tags, which anyone allowed to
// set a secret can edit, are copied under their own key (minus keys in the
// "azkv." namespace) and again under "azkv.meta.<key>", which never
// overwrites a key, so a tag cannot forge a native attribute. Labels hold
// metadata only, never a value.

// labelPrefix is the namespace of every label this adapter derives.
const labelPrefix = Kind + "."

// isReserved reports whether a tag key falls in the adapter's namespace.
// The check ignores case and surrounding space, so "AzKV.Enabled" cannot
// pose as a native key to a reader that folds case.
func isReserved(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), labelPrefix)
}

// labels builds the labels of a secret version (props) of name.
func (a *Adapter) labels(name string, p *props) map[string]string {
	out := map[string]string{}
	for k, v := range p.Tags {
		if !isReserved(k) {
			out[k] = v
		}
	}
	a.nativeLocation(out, name)
	if v := p.version(); v != "" {
		stores.SetNative(out, Kind, "version", v)
	}
	if p.ContentType != nil {
		stores.SetNative(out, Kind, "content-type", *p.ContentType)
	}
	at := p.Attributes
	if at.Enabled != nil {
		stores.SetNative(out, Kind, "enabled", strconv.FormatBool(*at.Enabled))
	}
	setTime(out, "created", at.Created)
	setTime(out, "updated", at.Updated)
	setTime(out, "expires", at.Expires)
	setTime(out, "not-before", at.NotBefore)
	if at.RecoveryLevel != "" {
		stores.SetNative(out, Kind, "recovery-level", at.RecoveryLevel)
	}
	if at.RecoverableDays != nil {
		stores.SetNative(out, Kind, "recoverable-days", strconv.Itoa(*at.RecoverableDays))
	}
	stores.SetNative(out, Kind, "managed", strconv.FormatBool(p.Managed))
	for k, v := range p.Tags {
		stores.UserMeta(out, Kind, k, v)
	}
	return out
}

// nativeLocation sets the labels that follow from where a secret is: the
// vault and the secret's name.
func (a *Adapter) nativeLocation(out map[string]string, name string) {
	host := strings.ToLower(a.s.vault.Hostname())
	vault, _, _ := strings.Cut(host, ".")
	stores.SetNative(out, Kind, "vault", vault)
	stores.SetNative(out, Kind, "vault-host", host)
	stores.SetNative(out, Kind, "name", name)
}

func setTime(labels map[string]string, attr string, unix *int64) {
	if unix != nil {
		stores.SetNative(labels, Kind, attr, time.Unix(*unix, 0).UTC().Format(time.RFC3339))
	}
}

// WriteLabels implements stores.WriteLabeler: the labels a secret written
// at ref would get, from the reference alone.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	name, err := a.names.Name(ref.Path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	a.nativeLocation(out, name)
	stores.SetNative(out, Kind, "enabled", "true")
	stores.SetNative(out, Kind, "managed", "false")
	if a.s.format == formatJSON {
		stores.SetNative(out, Kind, "content-type", jsonContentType)
	}
	return out
}
