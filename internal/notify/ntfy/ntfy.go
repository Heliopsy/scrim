// SPDX-License-Identifier: AGPL-3.0-only

// Package ntfy delivers approval requests to an ntfy server
// (https://ntfy.sh, or a self-hosted one) with Approve and Deny action
// buttons. The buttons are HTTP actions that POST to scrim's single-use
// signed decision links, so the phone talks to scrim directly and ntfy never
// sees a decision. A message carries names and metadata only.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/notify"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/version"
)

// Settings.
var (
	URL = config.Register(config.Spec[string]{
		Key:         "notify.ntfy.url",
		Default:     "",
		Description: "Base URL of the ntfy server, for example https://ntfy.sh. Empty disables the ntfy notifier.",
	})
	Topic = config.Register(config.Spec[string]{
		Key:         "notify.ntfy.topic",
		Default:     "",
		Description: "ntfy topic approval requests are published to. Anyone who can read the topic sees approval metadata, so use an access-controlled topic or a long random name.",
	})
	Token = config.Register(config.Spec[config.SecretRef]{
		Key:         "notify.ntfy.token",
		Default:     "",
		Description: "Reference to an ntfy access token for publishing. Empty publishes anonymously.",
	})
	Priority = config.Register(config.Spec[int]{
		Key:         "notify.ntfy.priority",
		Default:     4,
		Description: "ntfy message priority, 1 (min) to 5 (max).",
		Validate: func(p int) error {
			if p < 1 || p > 5 {
				return errors.New("must be 1 to 5")
			}
			return nil
		},
	})
)

var topicPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Notifier publishes to one ntfy topic.
type Notifier struct {
	name     string
	base     string
	topic    string
	token    secret.Value
	priority int
	hc       *http.Client
}

// Options configure a Notifier.
type Options struct {
	// Name is the notifier name rules refer to; default "ntfy".
	Name     string
	URL      string
	Topic    string
	Token    secret.Value
	Priority int
	// Client is the HTTP client; nil means a client with a 10s timeout.
	Client *http.Client
}

// New validates o and returns a notifier.
func New(o Options) (*Notifier, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("ntfy: url %q must be an absolute http or https URL", o.URL)
	}
	if !topicPattern.MatchString(o.Topic) {
		return nil, errors.New("ntfy: topic must be 1-64 letters, digits, '-' or '_'")
	}
	if o.Name == "" {
		o.Name = "ntfy"
	}
	if o.Priority == 0 {
		o.Priority = 4
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Notifier{name: o.Name, base: strings.TrimRight(o.URL, "/"), topic: o.Topic, token: o.Token, priority: o.Priority, hc: o.Client}, nil
}

// FromConfig builds the notifier from settings; ok is false when
// notify.ntfy.url is empty. resolve turns a secret reference into a value.
func FromConfig(cfg *config.Config, resolve func(config.SecretRef) (secret.Value, error)) (n *Notifier, ok bool, err error) {
	if URL.Get(cfg) == "" {
		return nil, false, nil
	}
	o := Options{URL: URL.Get(cfg), Topic: Topic.Get(cfg), Priority: Priority.Get(cfg)}
	if ref := Token.Get(cfg); ref != "" {
		if resolve == nil {
			return nil, false, errors.New("ntfy: notify.ntfy.token is set but no resolver is available")
		}
		if o.Token, err = resolve(ref); err != nil {
			return nil, false, fmt.Errorf("ntfy: resolving notify.ntfy.token: %w", err)
		}
	}
	n, err = New(o)
	return n, err == nil, err
}

// Name implements notify.Notifier.
func (n *Notifier) Name() string { return n.name }

// Message is the JSON ntfy publishes (https://docs.ntfy.sh/publish/#publish-as-json).
type Message struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Tags     []string `json:"tags,omitempty"`
	Priority int      `json:"priority,omitempty"`
	Actions  []Action `json:"actions,omitempty"`
}

// Action is an ntfy action button.
type Action struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Method string `json:"method,omitempty"`
	Clear  bool   `json:"clear,omitempty"`
}

// Build returns the message for r.
func (n *Notifier) Build(r notify.Request) Message {
	m := Message{
		Topic:    n.topic,
		Title:    "scrim approval: " + notify.Title(r),
		Message:  notify.Text(r),
		Tags:     []string{"lock", "scrim"},
		Priority: n.priority,
	}
	if notify.Absolute(r.ApproveURL) && notify.Absolute(r.DenyURL) {
		m.Actions = []Action{
			{Action: "http", Label: "Approve", URL: r.ApproveURL, Method: http.MethodPost, Clear: true},
			{Action: "http", Label: "Deny", URL: r.DenyURL, Method: http.MethodPost, Clear: true},
			{Action: "view", Label: "Details", URL: r.ApproveURL},
		}
	} else {
		m.Message += "\n\nDecide with: scrim approve " + r.ApprovalID + " (or scrim deny " + r.ApprovalID + ")"
	}
	return m
}

// Notify implements notify.Notifier.
func (n *Notifier) Notify(ctx context.Context, r notify.Request) error {
	body, err := json.Marshal(n.Build(r))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scrim/"+version.Version)
	if n.token.Len() > 0 {
		_ = n.token.Expose(func(b []byte) error {
			req.Header.Set("Authorization", "Bearer "+string(b))
			return nil
		})
	}
	resp, err := n.hc.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: publish: %w", scrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ntfy: publish answered %s", resp.Status)
	}
	return nil
}

// scrubURL drops the URL from a transport error; it carries no secret, but
// errors are logged and audited and need not repeat configuration.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
