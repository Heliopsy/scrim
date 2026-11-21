// SPDX-License-Identifier: AGPL-3.0-only

package sinks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Kafka settings.
var (
	KafkaBrokers = config.Register(config.Spec[[]string]{
		Key:             "audit.kafka.brokers",
		Description:     "Seed brokers (host:port) of the Kafka (or Redpanda) cluster of the kafka audit sink.",
		RestartRequired: true,
	})
	KafkaTopic = config.Register(config.Spec[string]{
		Key:             "audit.kafka.topic",
		Default:         "scrim-audit",
		Description:     "Topic the kafka audit sink produces to. Records are keyed by agent, so one agent's entries stay in order on one partition.",
		RestartRequired: true,
	})
	KafkaTLS = config.Register(config.Spec[bool]{
		Key:             "audit.kafka.tls",
		Description:     "Connect to the Kafka brokers over TLS, verified against the system roots or audit.kafka.tls-ca-file.",
		RestartRequired: true,
	})
	KafkaTLSCAFile = config.Register(config.Spec[string]{
		Key:             "audit.kafka.tls-ca-file",
		Description:     "PEM file of the certificate authorities that sign the Kafka broker certificates; empty uses the system roots.",
		RestartRequired: true,
	})
	KafkaSASL = config.Register(config.Spec[string]{
		Key:             "audit.kafka.sasl-mechanism",
		Default:         "none",
		Enum:            []string{"none", "plain", "scram-sha-256", "scram-sha-512"},
		Description:     "SASL mechanism of the kafka audit sink; plain needs audit.kafka.tls.",
		RestartRequired: true,
	})
	KafkaUsername = config.Register(config.Spec[string]{
		Key:             "audit.kafka.username",
		Description:     "SASL user of the kafka audit sink.",
		RestartRequired: true,
	})
	KafkaPassword = config.Register(config.Spec[config.SecretRef]{
		Key:              "audit.kafka.password",
		Description:      "Reference to the SASL password of the kafka audit sink.",
		RequireReference: true,
		RestartRequired:  true,
	})
)

// KafkaSink produces one record per audit entry: the JSON audit record,
// keyed by agent, acknowledged by every in-sync replica, idempotent.
type KafkaSink struct {
	cl *kgo.Client
}

// KafkaOptions configure a [KafkaSink].
type KafkaOptions struct {
	Brokers  []string
	Topic    string
	TLS      *tls.Config
	SASL     string
	Username string
	Password secret.Value
	// Extra client options (tests).
	Options []kgo.Opt
}

// NewKafka returns a Kafka sink. It connects lazily.
func NewKafka(o KafkaOptions) (*KafkaSink, error) {
	if len(o.Brokers) == 0 {
		return nil, errors.New("audit.kafka.brokers is empty")
	}
	if o.Topic == "" {
		return nil, errors.New("audit.kafka.topic is empty")
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(o.Brokers...),
		kgo.DefaultProduceTopic(o.Topic),
		kgo.ClientID("scrim-audit"),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.ZstdCompression(), kgo.NoCompression()),
		kgo.DialTimeout(5 * time.Second),
		// The fanout's write timeout bounds a produce; the client's own
		// retries stay within it.
		kgo.RecordDeliveryTimeout(audit.DefaultWriteTimeout),
	}
	if o.TLS != nil {
		opts = append(opts, kgo.DialTLSConfig(o.TLS))
	}
	switch o.SASL {
	case "", "none":
	case "plain", "scram-sha-256", "scram-sha-512":
		if o.Username == "" || o.Password.IsZero() {
			return nil, fmt.Errorf("audit.kafka.sasl-mechanism %s needs audit.kafka.username and audit.kafka.password", o.SASL)
		}
		if o.SASL == "plain" && o.TLS == nil {
			return nil, errors.New("audit.kafka.sasl-mechanism plain sends the password in the clear; set audit.kafka.tls")
		}
		// The client keeps the password for reconnects; this is the
		// narrowest scope that can hand it over.
		_ = o.Password.Expose(func(b []byte) error {
			pw := string(b)
			switch o.SASL {
			case "plain":
				opts = append(opts, kgo.SASL(plain.Auth{User: o.Username, Pass: pw}.AsMechanism()))
			case "scram-sha-256":
				opts = append(opts, kgo.SASL(scram.Auth{User: o.Username, Pass: pw}.AsSha256Mechanism()))
			default:
				opts = append(opts, kgo.SASL(scram.Auth{User: o.Username, Pass: pw}.AsSha512Mechanism()))
			}
			return nil
		})
	default:
		return nil, fmt.Errorf("audit.kafka.sasl-mechanism %q is not supported", o.SASL)
	}
	opts = append(opts, o.Options...)
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("kafka client: %w", err)
	}
	return &KafkaSink{cl: cl}, nil
}

func kafkaFromConfig(cfg *config.Config) (audit.Sink, error) {
	o := KafkaOptions{Brokers: KafkaBrokers.Get(cfg), Topic: KafkaTopic.Get(cfg), SASL: KafkaSASL.Get(cfg), Username: KafkaUsername.Get(cfg)}
	if pw, ok := cfg.Secret(KafkaPassword); ok {
		o.Password = pw
	} else if KafkaPassword.Get(cfg) != "" {
		return nil, errors.New("audit.kafka.password is set but did not resolve")
	}
	if KafkaTLS.Get(cfg) {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if f := KafkaTLSCAFile.Get(cfg); f != "" {
			pem, err := os.ReadFile(f) //nolint:gosec // operator-configured path
			if err != nil {
				return nil, fmt.Errorf("audit.kafka.tls-ca-file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("audit.kafka.tls-ca-file %s holds no PEM certificate", f)
			}
			tc.RootCAs = pool
		}
		o.TLS = tc
	}
	return NewKafka(o)
}

// Name implements [audit.Sink].
func (*KafkaSink) Name() string { return Kafka }

// Write implements [audit.Sink]: every record of the batch must be
// acknowledged. A record the broker refuses as too large is a permanent
// rejection.
func (k *KafkaSink) Write(ctx context.Context, batch []audit.Entry) error {
	recs := make([]*kgo.Record, 0, len(batch))
	for _, e := range batch {
		v, err := encode(e)
		if err != nil {
			return audit.Permanent(err)
		}
		recs = append(recs, &kgo.Record{Key: []byte(e.Agent.ID), Value: v, Timestamp: e.Time})
	}
	// Produce asynchronously and wait for every acknowledgement or ctx:
	// a stalled broker holds produced records past any context, and the
	// fanout must get its answer within the write timeout. Records still in
	// flight then may arrive later, a duplicate of the retry: Kafka
	// delivery is at least once.
	var (
		wg    sync.WaitGroup
		errMu sync.Mutex
		first error
	)
	for _, r := range recs {
		wg.Add(1)
		k.cl.Produce(ctx, r, func(_ *kgo.Record, err error) {
			if err != nil {
				errMu.Lock()
				if first == nil {
					first = err
				}
				errMu.Unlock()
			}
			wg.Done()
		})
	}
	acked := make(chan struct{})
	go func() { wg.Wait(); close(acked) }()
	select {
	case <-acked:
	case <-ctx.Done():
		return fmt.Errorf("kafka produce: %w", ctx.Err())
	}
	errMu.Lock()
	err := first
	errMu.Unlock()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, kerr.MessageTooLarge), errors.Is(err, kerr.InvalidRecord):
		return audit.Permanent(fmt.Errorf("kafka produce rejected: %w", err))
	default:
		return fmt.Errorf("kafka produce: %w", err)
	}
}

// Close closes the client.
func (k *KafkaSink) Close() error {
	k.cl.Close()
	return nil
}
