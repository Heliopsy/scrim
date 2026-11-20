// SPDX-License-Identifier: AGPL-3.0-only

package refresh

import (
	"github.com/heliopsy/scrim/internal/stores/internal/options"
)

// Option keys, relative to `stores.<instance>.`, that belong to the refresher
// rather than to the adapter. The loader passes these to ParseConfig and the
// rest to the adapter's factory. docs/stores/README.md documents them.
const (
	KeyRedact            = "redact"
	KeyRefreshInterval   = "refresh.interval"
	KeyRefreshRetention  = "refresh.retention"
	KeyRefreshStaleness  = "refresh.staleness"
	KeyRefreshMaxBackoff = "refresh.max-backoff"
)

// Keys lists the refresher's option keys.
var Keys = []string{KeyRedact, KeyRefreshInterval, KeyRefreshRetention, KeyRefreshStaleness, KeyRefreshMaxBackoff}

// ParseConfig decodes the refresher's options for one store instance. raw
// holds only the keys in [Keys]; anything else is reported as unknown.
func ParseConfig(store string, raw map[string]any) (Config, error) {
	d := options.New(store, raw)
	c := Config{
		Interval:   d.Duration(KeyRefreshInterval, DefaultInterval),
		Retention:  d.Duration(KeyRefreshRetention, DefaultRetention),
		Staleness:  d.Duration(KeyRefreshStaleness, DefaultStaleness),
		MaxBackoff: d.Duration(KeyRefreshMaxBackoff, DefaultMaxBackoff),
	}
	for _, s := range d.Strings(KeyRedact) {
		t, err := ParseTarget(s)
		if err != nil {
			d.Errorf("option %s: %v", KeyRedact, err)
			continue
		}
		if t.Ref.Scheme != store {
			d.Errorf("option %s: %s names another store", KeyRedact, t)
			continue
		}
		c.Targets = append(c.Targets, t)
	}
	for k, v := range map[string]int64{KeyRefreshInterval: int64(c.Interval), KeyRefreshRetention: int64(c.Retention), KeyRefreshStaleness: int64(c.Staleness), KeyRefreshMaxBackoff: int64(c.MaxBackoff)} {
		if v <= 0 {
			d.Errorf("option %s must be positive", k)
		}
	}
	return c, d.Finish()
}
