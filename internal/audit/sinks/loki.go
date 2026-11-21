// SPDX-License-Identifier: AGPL-3.0-only

package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Loki settings.
var (
	LokiURL = config.Register(config.Spec[string]{
		Key:             "audit.loki.url",
		Description:     "Base URL of Loki (or a compatible push endpoint) for the loki audit sink; entries are pushed to <url>/loki/api/v1/push.",
		RestartRequired: true,
	})
	LokiTenant = config.Register(config.Spec[string]{
		Key:             "audit.loki.tenant",
		Description:     "Loki tenant (X-Scope-OrgID) for the loki audit sink; empty for a single-tenant Loki.",
		RestartRequired: true,
	})
	LokiUsername = config.Register(config.Spec[string]{
		Key:             "audit.loki.username",
		Description:     "Basic auth user for the loki audit sink; empty for none.",
		RestartRequired: true,
	})
	LokiPassword = config.Register(config.Spec[config.SecretRef]{
		Key:              "audit.loki.password",
		Description:      "Reference to the basic auth password (or bearer token with an empty audit.loki.username) of the loki audit sink.",
		RequireReference: true,
		RestartRequired:  true,
	})
	LokiLabels = config.Register(config.Spec[map[string]string]{
		Key: "audit.loki.labels",
		Description: "Extra static stream labels for audit entries in Loki, added to service_name=scrim and source=audit. Keep them low-cardinality; " +
			"per-entry fields are in the JSON line.",
		RestartRequired: true,
	})
)

// LokiSink pushes audit entries to Loki's push API as JSON lines of one
// stream.
type LokiSink struct {
	push     string
	tenant   string
	user     string
	password secret.Value
	labels   map[string]string
	hc       *http.Client
}

// LokiOptions configure a [LokiSink].
type LokiOptions struct {
	URL      string
	Tenant   string
	Username string
	Password secret.Value
	Labels   map[string]string
	Client   *http.Client
}

// NewLoki returns a Loki sink.
func NewLoki(o LokiOptions) (*LokiSink, error) {
	u, err := url.Parse(strings.TrimRight(o.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("audit.loki.url must be an http or https URL")
	}
	if u.User != nil {
		return nil, errors.New("audit.loki.url must not hold credentials; use audit.loki.username and audit.loki.password")
	}
	labels := map[string]string{"service_name": "scrim", "source": "audit"}
	for k, v := range o.Labels {
		labels[k] = v
	}
	hc := o.Client
	if hc == nil {
		hc = &http.Client{}
	}
	return &LokiSink{push: u.String() + "/loki/api/v1/push", tenant: o.Tenant, user: o.Username,
		password: o.Password, labels: labels, hc: hc}, nil
}

func lokiFromConfig(cfg *config.Config) (audit.Sink, error) {
	o := LokiOptions{URL: LokiURL.Get(cfg), Tenant: LokiTenant.Get(cfg), Username: LokiUsername.Get(cfg), Labels: LokiLabels.Get(cfg)}
	if o.URL == "" {
		return nil, errors.New("audit.loki.url is not set")
	}
	if pw, ok := cfg.Secret(LokiPassword); ok {
		o.Password = pw
	} else if LokiPassword.Get(cfg) != "" {
		return nil, errors.New("audit.loki.password is set but did not resolve")
	}
	return NewLoki(o)
}

// Name implements [audit.Sink].
func (*LokiSink) Name() string { return Loki }

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// Write implements [audit.Sink]. 400, 413 and 422 reject the batch for
// good (too old, too large, malformed); everything else, authentication
// failures included, is retried until it is fixed.
func (l *LokiSink) Write(ctx context.Context, batch []audit.Entry) error {
	sorted := append([]audit.Entry(nil), batch...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Time.Before(sorted[j].Time) })
	st := lokiStream{Stream: l.labels, Values: make([][2]string, 0, len(sorted))}
	for _, e := range sorted {
		line, err := encode(e)
		if err != nil {
			return audit.Permanent(err)
		}
		t := e.Time
		if t.IsZero() {
			t = time.Now()
		}
		st.Values = append(st.Values, [2]string{strconv.FormatInt(t.UnixNano(), 10), string(line)})
	}
	body, err := json.Marshal(lokiPush{Streams: []lokiStream{st}})
	if err != nil {
		return audit.Permanent(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.push, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.tenant != "" {
		req.Header.Set("X-Scope-OrgID", l.tenant)
	}
	if !l.password.IsZero() {
		_ = l.password.Expose(func(b []byte) error {
			if l.user != "" {
				req.SetBasicAuth(l.user, string(b))
			} else {
				req.Header.Set("Authorization", "Bearer "+string(b))
			}
			return nil
		})
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		return fmt.Errorf("loki push: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusBadRequest, resp.StatusCode == http.StatusRequestEntityTooLarge,
		resp.StatusCode == http.StatusUnprocessableEntity:
		// The response body is not passed on: it may quote the request.
		return audit.Permanent(fmt.Errorf("loki push rejected: %s", resp.Status))
	default:
		return fmt.Errorf("loki push: %s", resp.Status)
	}
}
