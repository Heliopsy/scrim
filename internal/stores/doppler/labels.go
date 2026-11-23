// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"context"
	"strconv"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/doppler.md, "Policy labels").
//
// Doppler's own attributes of a secret go into stores.Metadata.Labels under
// "doppler.<attr>", set with stores.SetNative. Doppler has no user-editable
// metadata on a secret except its note, which is free text that may quote a
// value and is never read, so there are no doppler.meta.* keys and nothing a
// store user can write lands in a label. Labels hold metadata only, never a
// value.

// managedNames are the secrets Doppler generates in every config.
var managedNames = map[string]bool{"DOPPLER_PROJECT": true, "DOPPLER_CONFIG": true, "DOPPLER_ENVIRONMENT": true}

// setBool sets a boolean native attribute when it is known.
func setBool(labels map[string]string, attr string, v *bool) {
	if v != nil {
		stores.SetNative(labels, Kind, attr, strconv.FormatBool(*v))
	}
}

// setLocation sets the labels that follow from where a secret is: workplace,
// project, config and what Doppler says about the config, and the name.
func setLocation(out map[string]string, me meInfo, ci configInfo, ciOK bool, l location) {
	stores.SetNative(out, Kind, "workplace", me.Workplace.Slug)
	stores.SetNative(out, Kind, "workplace.name", me.Workplace.Name)
	stores.SetNative(out, Kind, "project", l.project)
	stores.SetNative(out, Kind, "config", l.config)
	if ciOK {
		stores.SetNative(out, Kind, "environment", ci.Environment)
		setBool(out, "config.root", ci.Root)
		setBool(out, "config.locked", ci.Locked)
		setBool(out, "config.inheritable", ci.Inheritable)
	}
	stores.SetNative(out, Kind, "secret", l.name)
	stores.SetNative(out, Kind, "managed", strconv.FormatBool(managedNames[l.name]))
}

// locationLabels are the location labels of l, looking the workplace and
// the config details up once each.
func (a *Adapter) locationLabels(ctx context.Context, l location) map[string]string {
	out := map[string]string{}
	ci, ok := a.c.configDetails(ctx, l.project, l.config)
	setLocation(out, a.c.workplace(ctx), ci, ok, l)
	return out
}

// WriteLabels returns the native labels a secret written at ref would get,
// without contacting Doppler, so store.write rules can match on project,
// config and environment before the secret exists. Workplace and config
// details come from what earlier calls cached; until then only the
// reference's own project, config and name are known.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	l, ok := splitSecret(ref.Path)
	if !ok {
		return nil
	}
	out := map[string]string{}
	ci, ciOK := a.c.cachedConfig(l.project, l.config)
	setLocation(out, a.c.cachedWorkplace(), ci, ciOK, l)
	return out
}
