// SPDX-License-Identifier: AGPL-3.0-only

package podtest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Images started when the matching *_IMAGE variable is unset.
const (
	ValkeyImage    = "docker.io/valkey/valkey:9.2.0-alpine3.24"
	NATSImage      = "docker.io/library/nats:2.15.3-alpine3.22"
	LokiImage      = "docker.io/grafana/loki:3.6.22"
	CollectorImage = "docker.io/otel/opentelemetry-collector-contrib:0.165.0"
	RedpandaImage  = "docker.io/redpandadata/redpanda:v26.3.1"
)

// Valkey is a Valkey server; SCRIM_TEST_VALKEY_ADDR (host:port) points at
// an existing one.
func Valkey() *Service {
	return &Service{
		Name: "valkey", Env: "SCRIM_TEST_VALKEY_ADDR", Image: ValkeyImage, ImageEnv: "SCRIM_TEST_VALKEY_IMAGE",
		Port: "6379/tcp", Memory: "256m",
		Args:  []string{"valkey-server", "--save", "", "--appendonly", "no", "--maxmemory", "128mb"},
		Ready: lineReady("PING\r\n", "+PONG"),
	}
}

// NATS is a NATS server; SCRIM_TEST_NATS_URL (nats://host:port) points at
// an existing one, and Addr then returns that URL.
func NATS() *Service {
	return &Service{
		Name: "nats", Env: "SCRIM_TEST_NATS_URL", Image: NATSImage, ImageEnv: "SCRIM_TEST_NATS_IMAGE",
		Port: "4222/tcp", Memory: "128m",
		Ready: lineReady("", "INFO "),
	}
}

// Loki is a single-binary Loki; SCRIM_TEST_LOKI_URL (http://host:port)
// points at an existing one.
func Loki() *Service {
	return &Service{
		Name: "loki", Env: "SCRIM_TEST_LOKI_URL", Image: LokiImage, ImageEnv: "SCRIM_TEST_LOKI_IMAGE",
		Port: "3100/tcp", Memory: "512m",
		Args:  []string{"-config.file=/etc/loki/local-config.yaml"},
		Ready: httpReady("/ready"),
	}
}

// collectorConfig receives OTLP over HTTP and prints every log record it
// receives, so a test reads what arrived from the container's output.
const collectorConfig = `yaml:{receivers: {otlp: {protocols: {http: {endpoint: "0.0.0.0:4318"}}}}, ` +
	`exporters: {debug: {verbosity: detailed}}, extensions: {health_check: {endpoint: "0.0.0.0:13133"}}, ` +
	`service: {extensions: [health_check], pipelines: {logs: {receivers: [otlp], exporters: [debug]}}}}`

// Collector is an OpenTelemetry collector with an OTLP/HTTP receiver that
// logs every record it receives (podman logs). SCRIM_TEST_OTLP_ENDPOINT
// (http://host:port) points at an existing one.
func Collector() *Service {
	s := &Service{
		Name: "otelcol", Env: "SCRIM_TEST_OTLP_ENDPOINT", Image: CollectorImage, ImageEnv: "SCRIM_TEST_COLLECTOR_IMAGE",
		Port: "4318/tcp", Extra: []string{"13133/tcp"}, Memory: "256m",
		Args: []string{"--config=" + collectorConfig},
	}
	s.Ready = func(ctx context.Context, _ string) error {
		return httpReady("/")(ctx, s.ports["13133/tcp"])
	}
	return s
}

// Redpanda is a one-core Redpanda in dev-container mode, its Kafka API
// published on a fixed loopback port it advertises; SCRIM_TEST_KAFKA_BROKERS
// (host:port) points at an existing broker.
func Redpanda() *Service {
	return &Service{
		Name: "redpanda", Env: "SCRIM_TEST_KAFKA_BROKERS", Image: RedpandaImage, ImageEnv: "SCRIM_TEST_REDPANDA_IMAGE",
		Port: "9092/tcp", HostPorts: true, Memory: "1g",
		Args: []string{"redpanda", "start", "--mode", "dev-container", "--smp", "1", "--memory", "512M",
			"--overprovisioned", "--kafka-addr", "PLAINTEXT://0.0.0.0:9092",
			"--advertise-kafka-addr", "PLAINTEXT://127.0.0.1:{port}"},
		Ready: lineReady("", ""),
	}
}

// lineReady dials addr, writes send, and wants a first line starting with
// want; an empty want only needs the connection.
func lineReady(send, want string) func(context.Context, string) error {
	return func(ctx context.Context, addr string) error {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		if want == "" {
			return nil
		}
		if send != "" {
			if _, err := c.Write([]byte(send)); err != nil {
				return err
			}
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, want) {
			return fmt.Errorf("answered %q", strings.TrimSpace(line))
		}
		return nil
	}
}

func httpReady(path string) func(context.Context, string) error {
	return func(ctx context.Context, addr string) error {
		if addr == "" {
			return errors.New("no address")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s answered %s", path, resp.Status)
		}
		return nil
	}
}
