{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{- /*
Large deployments: the events backend between replicas, Valkey and NATS
connections, the rate-limit backend and the external audit sinks
(docs/state-and-observability.md). Credentials are Secret slots mounted
under /run/secrets/scrim/<slot>/<key>, referenced with file:.
*/ -}}

{{/* Whether Valkey is in use: events.backend valkey or ratelimit.backend valkey. */}}
{{- define "scrim.usesValkey" -}}
{{- $v := .Values -}}
{{- if or (and $v.postgres.enabled (eq $v.events.backend "valkey")) (eq $v.rateLimit.backend "valkey") -}}true{{- end -}}
{{- end -}}

{{- define "scrim.usesNats" -}}
{{- if and .Values.postgres.enabled (eq .Values.events.backend "nats") -}}true{{- end -}}
{{- end -}}

{{/*
The Secret slots these settings need, as a JSON list of [slot, key].
*/}}
{{- define "scrim.scaleSlots" -}}
{{- $v := .Values -}}
{{- $out := list -}}
{{- if and (include "scrim.usesValkey" .) $v.valkey.auth -}}{{- $out = append $out (list "valkey" "password") -}}{{- end -}}
{{- if include "scrim.usesNats" . -}}
{{- if eq $v.nats.auth "token" -}}{{- $out = append $out (list "nats" "token") -}}{{- end -}}
{{- if eq $v.nats.auth "password" -}}{{- $out = append $out (list "nats" "password") -}}{{- end -}}
{{- end -}}
{{- $s := $v.auditSinks -}}
{{- if and $s.otlp.enabled $s.otlp.auth -}}{{- $out = append $out (list "otlp" "token") -}}{{- end -}}
{{- if and $s.loki.enabled $s.loki.auth -}}{{- $out = append $out (list "loki" "password") -}}{{- end -}}
{{- if and $s.kafka.enabled (ne $s.kafka.saslMechanism "none") -}}{{- $out = append $out (list "kafka" "password") -}}{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{- define "scrim.secretRef" -}}
file:/run/secrets/scrim/{{ index . 1 }}/{{ include "chart.secretKey" (list (index . 0) (index . 1) (index . 2)) }}
{{- end -}}

{{- define "scrim.sinkCommon" -}}
policy: {{ .policy }}
timeout: {{ .timeout }}
queue-size: {{ int .queueSize }}
{{- end -}}

{{/* Settings for events, Valkey, NATS, rate limits and audit sinks. */}}
{{- define "scrim.scaleSettings" -}}
{{- $v := .Values -}}
{{- if include "scrim.usesValkey" . }}
valkey:
  addresses: {{ toJson $v.valkey.addresses }}
  {{- with $v.valkey.username }}
  username: {{ . | quote }}
  {{- end }}
  {{- if $v.valkey.auth }}
  password: {{ include "scrim.secretRef" (list . "valkey" "password") }}
  {{- end }}
  db: {{ int $v.valkey.db }}
  tls: {{ $v.valkey.tls }}
{{- end }}
{{- if include "scrim.usesNats" . }}
nats:
  servers: {{ toJson $v.nats.servers }}
  {{- if eq $v.nats.auth "token" }}
  token: {{ include "scrim.secretRef" (list . "nats" "token") }}
  {{- else if eq $v.nats.auth "password" }}
  username: {{ $v.nats.username | quote }}
  password: {{ include "scrim.secretRef" (list . "nats" "password") }}
  {{- end }}
{{- end }}
{{- if ne $v.rateLimit.backend "local" }}
ratelimit:
  backend: {{ $v.rateLimit.backend }}
{{- end }}
{{- $s := $v.auditSinks }}
{{- if or $s.otlp.enabled $s.loki.enabled $s.kafka.enabled }}
audit:
  sinks:
    - db
    {{- if $s.otlp.enabled }}
    - otlp
    {{- end }}
    {{- if $s.loki.enabled }}
    - loki
    {{- end }}
    {{- if $s.kafka.enabled }}
    - kafka
    {{- end }}
  {{- if $s.otlp.enabled }}
  otlp:
    endpoint: {{ $s.otlp.endpoint | quote }}
    {{- if $s.otlp.auth }}
    token: {{ include "scrim.secretRef" (list . "otlp" "token") }}
    {{- end }}
    {{- include "scrim.sinkCommon" $s.otlp | nindent 4 }}
  {{- end }}
  {{- if $s.loki.enabled }}
  loki:
    url: {{ $s.loki.url | quote }}
    {{- with $s.loki.tenant }}
    tenant: {{ . | quote }}
    {{- end }}
    {{- with $s.loki.username }}
    username: {{ . | quote }}
    {{- end }}
    {{- if $s.loki.auth }}
    password: {{ include "scrim.secretRef" (list . "loki" "password") }}
    {{- end }}
    {{- with $s.loki.labels }}
    labels:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    {{- include "scrim.sinkCommon" $s.loki | nindent 4 }}
  {{- end }}
  {{- if $s.kafka.enabled }}
  kafka:
    brokers: {{ toJson $s.kafka.brokers }}
    topic: {{ $s.kafka.topic | quote }}
    tls: {{ $s.kafka.tls }}
    sasl-mechanism: {{ $s.kafka.saslMechanism }}
    {{- if ne $s.kafka.saslMechanism "none" }}
    username: {{ $s.kafka.username | quote }}
    password: {{ include "scrim.secretRef" (list . "kafka" "password") }}
    {{- end }}
    {{- include "scrim.sinkCommon" $s.kafka | nindent 4 }}
  {{- end }}
{{- end }}
{{- end -}}

{{/* Refusals for these values; validate.yaml includes it. */}}
{{- define "scrim.checkScale" -}}
{{- $v := .Values -}}
{{- $cfg := default dict $v.config -}}
{{- if hasKey (default dict $cfg.ratelimit) "backend" -}}
{{- fail "config.ratelimit.backend is set by the chart; use rateLimit.backend (the limits stay in config.ratelimit)" -}}
{{- end -}}
{{- range $k := list "sinks" "otlp" "loki" "kafka" -}}
{{- if hasKey (default dict $cfg.audit) $k -}}
{{- fail (printf "config.audit.%s is set by the chart; use the auditSinks values" $k) -}}
{{- end -}}
{{- end -}}
{{- if and $v.postgres.enabled (not (has $v.events.backend (list "postgres" "valkey" "nats"))) -}}
{{- fail (printf "events.backend %q: use postgres, valkey or nats" $v.events.backend) -}}
{{- end -}}
{{- if and (include "scrim.usesValkey" .) (not $v.valkey.addresses) -}}
{{- fail "events.backend or rateLimit.backend valkey needs valkey.addresses" -}}
{{- end -}}
{{- if and (include "scrim.usesNats" .) (not $v.nats.servers) -}}
{{- fail "events.backend nats needs nats.servers" -}}
{{- end -}}
{{- if and (include "scrim.usesNats" .) (eq $v.nats.auth "password") (not $v.nats.username) -}}
{{- fail "nats.auth password needs nats.username" -}}
{{- end -}}
{{- $s := $v.auditSinks -}}
{{- if and $s.otlp.enabled (not $s.otlp.endpoint) -}}{{- fail "auditSinks.otlp.enabled needs auditSinks.otlp.endpoint" -}}{{- end -}}
{{- if and $s.loki.enabled (not $s.loki.url) -}}{{- fail "auditSinks.loki.enabled needs auditSinks.loki.url" -}}{{- end -}}
{{- if and $s.kafka.enabled (not $s.kafka.brokers) -}}{{- fail "auditSinks.kafka.enabled needs auditSinks.kafka.brokers" -}}{{- end -}}
{{- if and $s.kafka.enabled (ne $s.kafka.saslMechanism "none") (not $s.kafka.username) -}}{{- fail "auditSinks.kafka.saslMechanism needs auditSinks.kafka.username" -}}{{- end -}}
{{- if and $s.kafka.enabled (eq $s.kafka.saslMechanism "plain") (not $s.kafka.tls) -}}{{- fail "auditSinks.kafka.saslMechanism plain sends the password in the clear: set auditSinks.kafka.tls" -}}{{- end -}}
{{- range (include "scrim.scaleSlots" . | fromJsonArray) -}}
{{- if not (include "scrim.slotSupplied" (list $ (index . 0))) -}}
{{- fail (printf "the %s credential needs the Secret slot %s: secrets.existing.%s or secrets.externalSecrets.data.%s (key %s)" (index . 0) (index . 0) (index . 0) (index . 0) (index . 1)) -}}
{{- end -}}
{{- end -}}
{{- end -}}
