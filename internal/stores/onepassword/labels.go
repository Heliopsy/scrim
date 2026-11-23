// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/onepassword.md, "Policy labels").
//
// Every label comes from the vault and the item summary, the part of an item
// Connect returns without fields. So List, ReadMetadata and Read report the
// same labels, and labels never need a value to be fetched. Field values,
// notes, section and field contents and the TOTP code are never labels.
//
//	onepassword.vault          = "Prod"                 (vault name)
//	onepassword.vault-id       = <vault ID>
//	onepassword.vault-type     = "USER_CREATED"
//	onepassword.item           = "GitHub/deploy"        (item title)
//	onepassword.item-id        = <item ID>
//	onepassword.category       = "API_CREDENTIAL"
//	onepassword.tag            = "ci,team/payments"     (multi-valued)
//	onepassword.tag.ci         = "true"
//	onepassword.tag.team       = "true"                 (nested tags: each ancestor)
//	onepassword.tag.team/payments = "true"
//	onepassword.url-host       = "github.com"           (multi-valued)
//	onepassword.favorite       = "false"
//	onepassword.version        = "3"
//	onepassword.created, onepassword.updated (RFC 3339, UTC)
//	onepassword.last-edited-by = user ID
//
// Tags are the only attribute an item editor chooses freely. They are a
// native 1Password attribute and are reported as such, under their own
// multi-valued key, so a tag can never stand in for another native key.
// 1Password has no other user-defined item metadata, so the adapter writes
// no onepassword.meta.* keys.

// multiAttrs get presence keys even for a single value.
var multiAttrs = []string{"tag", "url-host"}

func labelsFor(v apiVault, s apiSummary) map[string]string {
	l := map[string]string{}
	set := func(attr, value string) { stores.SetNative(l, Kind, attr, value) }
	set("vault", v.Name)
	set("vault-id", v.ID)
	set("vault-type", v.Type)
	set("item", s.Title)
	set("item-id", s.ID)
	set("category", s.Category)
	set("favorite", strconv.FormatBool(s.Favorite))
	if s.Version > 0 {
		set("version", strconv.Itoa(s.Version))
	}
	if s.LastEditedBy != "" {
		set("last-edited-by", s.LastEditedBy)
	}
	setTime(l, "created", s.CreatedAt)
	setTime(l, "updated", s.UpdatedAt)
	tags := slices.Clone(s.Tags)
	slices.Sort(tags)
	stores.SetNative(l, Kind, "tag", tags...)
	key := stores.NativeKey(Kind, "tag")
	for _, t := range tags {
		for i := 1; i < len(t); i++ {
			if t[i] == '/' {
				l[key+"."+t[:i]] = "true"
			}
		}
	}
	stores.SetNative(l, Kind, "url-host", urlHosts(s.URLs)...)
	return l
}

func setTime(l map[string]string, attr string, t time.Time) {
	if !t.IsZero() {
		stores.SetNative(l, Kind, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

// urlHosts returns the host names of an item's URLs, without scheme, port,
// path, query or user info, sorted.
func urlHosts(us []apiURL) []string {
	var out []string
	for _, u := range us {
		h := strings.TrimSpace(u.Href)
		if h == "" {
			continue
		}
		if !strings.Contains(h, "://") {
			h = "https://" + h
		}
		p, err := url.Parse(h)
		if err != nil || p.Hostname() == "" {
			continue
		}
		out = append(out, strings.ToLower(p.Hostname()))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
