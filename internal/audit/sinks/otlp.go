// SPDX-License-Identifier: AGPL-3.0-only

package sinks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/version"
)

// OTLP settings.
var (
	OTLPEndpoint = config.Register(config.Spec[string]{
		Key: "audit.otlp.endpoint",
		Description: "OTLP/HTTP logs endpoint of the otlp audit sink, a collector or a backend that takes OTLP logs: " +
			"http(s)://host:4318 (the /v1/logs path is added unless the URL has a path).",
		RestartRequired: true,
	})
	OTLPToken = config.Register(config.Spec[config.SecretRef]{
		Key:              "audit.otlp.token",
		Description:      "Reference to a bearer token sent to the otlp audit sink; empty for none.",
		RequireReference: true,
		RestartRequired:  true,
	})
)

// OTLPSink exports audit entries as OTLP log records, one per entry: the
// JSON audit record as the body, the main fields as attributes, severity
// INFO, event name scrim.audit, resource service.name=scrim. Each Write is
// one synchronous export, so a failure reaches the fanout, which retries.
type OTLPSink struct {
	exp    *otlploghttp.Exporter
	logger log.Logger
	lp     *sdklog.LoggerProvider
	col    *collector
}

// OTLPOptions configure an [OTLPSink].
type OTLPOptions struct {
	Endpoint string
	Token    secret.Value
	// Extra exporter options (tests).
	Options []otlploghttp.Option
}

// collector is a synchronous processor: the records one Write emits are
// appended to the slice in its context, so the SDK builds each record (with
// the provider's resource) and the sink exports them itself.
type collector struct{}

type collectKey struct{}

type collected struct {
	mu   sync.Mutex
	recs []sdklog.Record
}

func (collector) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (collector) OnEmit(ctx context.Context, r *sdklog.Record) error {
	if c, ok := ctx.Value(collectKey{}).(*collected); ok {
		c.mu.Lock()
		c.recs = append(c.recs, r.Clone())
		c.mu.Unlock()
	}
	return nil
}
func (collector) Shutdown(context.Context) error   { return nil }
func (collector) ForceFlush(context.Context) error { return nil }

// otlpTimeout bounds one export, the exporter's own default.
const otlpTimeout = 10 * time.Second

// bearerTransport sets Authorization from token on a copy of each request
// and drops it once the request is sent, so the header string exists for
// one request only.
type bearerTransport struct {
	base  http.RoundTripper
	token secret.Value
}

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	err := b.token.Expose(func(t []byte) error {
		v := make([]byte, 0, len("Bearer ")+len(t))
		v = append(append(v, "Bearer "...), t...)
		r.Header["Authorization"] = []string{string(v)}
		secret.WipeBytes(v)
		return nil
	})
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("audit.otlp.token is no longer available")
	}
	resp, err := b.base.RoundTrip(r)
	delete(r.Header, "Authorization")
	return resp, err
}

// NewOTLP returns an OTLP sink.
func NewOTLP(ctx context.Context, o OTLPOptions) (*OTLPSink, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("audit.otlp.endpoint must be an http or https URL")
	}
	if u.User != nil {
		return nil, errors.New("audit.otlp.endpoint must not hold credentials; use audit.otlp.token")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/logs"
	}
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpointURL(u.String()),
		// The fanout retries with its own backoff and bound.
		otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: false}),
		otlploghttp.WithCompression(otlploghttp.GzipCompression),
	}
	// scrim's own transport (it follows network.upstream-proxy), and the
	// token set on each request from the secret value rather than handed to
	// the exporter as a header string it would keep for the sink's life.
	var rt http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	if !o.Token.IsZero() {
		rt = bearerTransport{base: rt, token: o.Token}
	}
	opts = append(opts, otlploghttp.WithHTTPClient(&http.Client{Transport: rt, Timeout: otlpTimeout}))
	opts = append(opts, o.Options...)
	exp, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res := resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName("scrim"), semconv.ServiceVersion(version.Version))
	col := &collector{}
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(col))
	return &OTLPSink{exp: exp, lp: lp, col: col, logger: lp.Logger("github.com/heliopsy/scrim/internal/audit")}, nil
}

func otlpFromConfig(cfg *config.Config) (audit.Sink, error) {
	o := OTLPOptions{Endpoint: OTLPEndpoint.Get(cfg)}
	if o.Endpoint == "" {
		return nil, errors.New("audit.otlp.endpoint is not set")
	}
	if tok, ok := cfg.Secret(OTLPToken); ok {
		o.Token = tok
	} else if OTLPToken.Get(cfg) != "" {
		return nil, errors.New("audit.otlp.token is set but did not resolve")
	}
	return NewOTLP(context.Background(), o)
}

// Name implements [audit.Sink].
func (*OTLPSink) Name() string { return OTLP }

// Write implements [audit.Sink].
func (s *OTLPSink) Write(ctx context.Context, batch []audit.Entry) error {
	c := &collected{}
	ectx := context.WithValue(ctx, collectKey{}, c)
	for _, e := range batch {
		line, err := encode(e)
		if err != nil {
			return audit.Permanent(err)
		}
		var r log.Record
		r.SetTimestamp(e.Time)
		r.SetSeverity(log.SeverityInfo)
		r.SetSeverityText("INFO")
		r.SetEventName("scrim.audit")
		r.SetBody(attribute.StringValue(string(line)))
		r.AddAttributes(
			attribute.String("scrim.audit.action", e.Action),
			attribute.String("scrim.audit.id", strconv.FormatInt(e.ID, 10)),
			attribute.String("scrim.audit.outcome", e.Outcome),
			attribute.String("scrim.audit.decision", e.Effect.String()),
			attribute.String("scrim.agent.id", e.Agent.ID),
		)
		s.logger.Emit(ectx, r)
	}
	if err := s.exp.Export(ctx, c.recs); err != nil {
		return fmt.Errorf("otlp export: %w", err)
	}
	return nil
}

// Close shuts the exporter down.
func (s *OTLPSink) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), audit.DefaultWriteTimeout)
	defer cancel()
	_ = s.lp.Shutdown(ctx)
	return s.exp.Shutdown(ctx)
}
