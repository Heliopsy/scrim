{{/* SPDX-License-Identifier: AGPL-3.0-only */}}

{{- define "scrim.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "scrim.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "scrim.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "scrim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "scrim.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scrim.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "scrim.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "scrim.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "scrim.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Host name of the central Service as agents use it. */}}
{{- define "scrim.serviceHost" -}}
{{- printf "%s.%s.svc.%s" (include "scrim.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- end -}}

{{- define "scrim.caSecretName" -}}
{{- default (printf "%s-ca" (include "scrim.fullname" .)) .Values.ca.existingSecret -}}
{{- end -}}

{{- define "scrim.keysSecretName" -}}
{{- default (printf "%s-placeholder-keys" (include "scrim.fullname" .)) .Values.placeholderKeys.existingSecret -}}
{{- end -}}

{{/*
The generated CA, created once and then read back with lookup so upgrades keep it.
Returns a dict with "crt" and "key" (PEM). Cached in .Values so every template that
needs it in one render sees the same CA.
*/}}
{{- define "scrim.generatedCA" -}}
{{- if not (hasKey .Values "__scrimCA") -}}
{{- $name := printf "%s-ca" (include "scrim.fullname" .) -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- if and $existing (index $existing "data") (index $existing.data "tls.key") -}}
{{- $_ := set .Values "__scrimCA" (dict "crt" (index $existing.data "tls.crt" | b64dec) "key" (index $existing.data "tls.key" | b64dec)) -}}
{{- else -}}
{{- $key := genPrivateKey "ed25519" -}}
{{- $ca := genCAWithKey (printf "scrim interception CA %s" .Release.Name) (int .Values.ca.validityDays) $key -}}
{{- $_ := set .Values "__scrimCA" (dict "crt" $ca.Cert "key" $ca.Key) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Public PEM of the CA, whatever its source. */}}
{{- define "scrim.caCert" -}}
{{- if .Values.ca.existingSecret -}}
{{- if .Values.ca.certificate -}}
{{- .Values.ca.certificate -}}
{{- else -}}
{{- $s := lookup "v1" "Secret" .Release.Namespace .Values.ca.existingSecret -}}
{{- if and $s (index $s "data") (index $s.data "tls.crt") -}}
{{- index $s.data "tls.crt" | b64dec -}}
{{- else -}}
{{- fail (printf "ca.existingSecret %q: its certificate cannot be read here (helm template, or the Secret does not exist yet); set ca.certificate to the public PEM" .Values.ca.existingSecret) -}}
{{- end -}}
{{- end -}}
{{- else if .Values.ca.create -}}
{{- include "scrim.generatedCA" . -}}
{{- index .Values.__scrimCA "crt" -}}
{{- else -}}
{{- fail "set ca.create=true or ca.existingSecret: scrim needs one interception CA shared by every replica" -}}
{{- end -}}
{{- end -}}

{{/* The generated placeholder key, created once and read back with lookup. */}}
{{- define "scrim.generatedKey" -}}
{{- if not (hasKey .Values "__scrimKey") -}}
{{- $name := printf "%s-placeholder-keys" (include "scrim.fullname" .) -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- if and $existing (index $existing "data") (index $existing.data "k1") -}}
{{- $_ := set .Values "__scrimKey" (index $existing.data "k1" | b64dec) -}}
{{- else -}}
{{- $_ := set .Values "__scrimKey" (randAlphaNum 64) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The placeholder keys as scrim configuration, for a mount at $path. */}}
{{- define "scrim.placeholderKeysConfig" -}}
{{- $path := .path -}}
{{- $root := .root -}}
{{- if $root.Values.placeholderKeys.existingSecret }}
{{- range $root.Values.placeholderKeys.keys }}
{{ .name }}:
  version: {{ .version }}
  key: file:{{ $path }}/{{ .key }}
{{- end }}
{{- else }}
k1:
  version: 1
  key: file:{{ $path }}/k1
{{- end }}
{{- end -}}

{{/* A store or setting reference, never a literal. */}}
{{- define "scrim.isRef" -}}
{{- if regexMatch "^((env|file|cred):.+|[a-z][a-z0-9+.-]*://.+)$" (toString .) -}}true{{- end -}}
{{- end -}}

{{/*
Refuse literals where scrim takes a credential. scrim itself warns about literals; the chart
refuses them so a values file never carries a secret.
*/}}
{{- define "scrim.checkConfig" -}}
{{- $cfg := .Values.config -}}
{{- $credFields := list "token" "secret-id" "role-id" "client-id" "client-secret" "password" "api-key" "access-token" "master-password" -}}
{{- range $store, $inst := (default dict (index $cfg "stores")) -}}
{{- if kindIs "map" $inst -}}
{{- range $field, $v := $inst -}}
{{- if and (has $field $credFields) (kindIs "string" $v) (not (include "scrim.isRef" $v)) -}}
{{- fail (printf "config.stores.%s.%s holds a literal; use a reference (file:/run/secrets/scrim/<mount>/<key>, env:NAME or a store reference)" $store $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with (index $cfg "admin") -}}
{{- if and (kindIs "map" .) (hasKey . "token") (not (include "scrim.isRef" (index . "token"))) -}}
{{- fail "config.admin.token holds a literal; use admin.tcp.tokenSecret" -}}
{{- end -}}
{{- end -}}
{{- with (index $cfg "state") -}}
{{- if and (kindIs "map" .) (hasKey . "postgres") (kindIs "map" .postgres) (hasKey .postgres "dsn") -}}
{{- fail "config.state.postgres.dsn is set by the chart; use state.postgres.dsnSecret" -}}
{{- end -}}
{{- end -}}
{{- if or (gt (int .Values.central.replicaCount) 1) .Values.central.autoscaling.enabled -}}
{{- if ne .Values.state.backend "postgres" -}}
{{- fail "several replicas need shared state: set state.backend=postgres and state.postgres.dsnSecret" -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.state.backend "postgres") (not .Values.state.postgres.dsnSecret.name) -}}
{{- fail "state.backend=postgres needs state.postgres.dsnSecret.name" -}}
{{- end -}}
{{- if not (has .Values.state.backend (list "memory" "postgres")) -}}
{{- fail "state.backend must be memory or postgres (sqlite needs a volume per pod and refuses a second process)" -}}
{{- end -}}
{{- if and .Values.admin.tcp.enabled (not .Values.admin.tcp.tokenSecret.name) -}}
{{- fail "admin.tcp.enabled needs admin.tcp.tokenSecret.name: scrim refuses a TCP admin listener without a token" -}}
{{- end -}}
{{- if and .Values.sidecar.enabled .Values.sidecar.egressGuard.enabled (not .Values.sidecar.egressGuard.image) -}}
{{- fail "sidecar.egressGuard.image is required (an image with nft and sh), or set sidecar.egressGuard.enabled=false to accept that agent containers can reach what the pod's NetworkPolicy allows without scrim" -}}
{{- end -}}
{{- if and .Values.sidecar.enabled (not .Values.ca.create) (not .Values.ca.existingSecret) -}}
{{- fail "sidecar mode needs a CA: ca.create or ca.existingSecret" -}}
{{- end -}}
{{- end -}}

{{/* Settings the chart owns, shared by central and sidecar. */}}
{{- define "scrim.commonSettings" -}}
log:
  level: {{ .Values.log.level }}
  format: {{ .Values.log.format }}
api:
  socket: /run/scrim/api.sock
entry:
  listen: 127.0.0.1:0
tool-proxy:
  ca:
    cert-file: /etc/scrim/ca/tls.crt
    key: file:/etc/scrim/ca/tls.key
{{- if .Values.policyRules }}
policy:
  rules-file: /etc/scrim/config/policy.yaml
{{- end }}
{{- end -}}

{{- define "scrim.metricsSettings" -}}
metrics:
  listen: {{ .listen }}
{{- if .root.Values.metrics.enabled }}
  enabled: true
{{- if ne .root.Values.metrics.path "/metrics" }}
  path: {{ .root.Values.metrics.path }}
{{- end }}
{{- if .root.Values.metrics.authSecret.name }}
  auth: file:/run/secrets/scrim/metrics/{{ .root.Values.metrics.authSecret.key }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Agent environment, as a list of {name, value}. .base is the LLM base URL, .proxy the forward proxy. */}}
{{- define "scrim.agentEnv" -}}
{{- $root := .root -}}
{{- $trust := $root.Values.agents.trustPath -}}
{{- $noProxy := concat (list "localhost" "127.0.0.1" "::1") .noProxy $root.Values.agents.noProxy | uniq | join "," -}}
- name: ANTHROPIC_BASE_URL
  value: {{ printf "%s/anthropic" .base | quote }}
- name: OPENAI_BASE_URL
  value: {{ printf "%s/openai/v1" .base | quote }}
{{- range list "HTTPS_PROXY" "https_proxy" "HTTP_PROXY" "http_proxy" }}
- name: {{ . }}
  value: {{ $.proxy | quote }}
{{- end }}
{{- range list "NO_PROXY" "no_proxy" }}
- name: {{ . }}
  value: {{ $noProxy | quote }}
{{- end }}
- name: NODE_EXTRA_CA_CERTS
  value: {{ printf "%s/scrim-ca.pem" $trust | quote }}
{{- range list "SSL_CERT_FILE" "REQUESTS_CA_BUNDLE" "CURL_CA_BUNDLE" "GIT_SSL_CAINFO" "AWS_CA_BUNDLE" "PIP_CERT" "NPM_CONFIG_CAFILE" "CARGO_HTTP_CAINFO" "DENO_CERT" "CODEX_CA_CERTIFICATE" }}
- name: {{ . }}
  value: {{ printf "%s/ca-bundle.pem" $trust | quote }}
{{- end }}
{{- with $root.Values.agents.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "scrim.centralAgentEnv" -}}
{{- $host := include "scrim.serviceHost" . -}}
{{- $short := include "scrim.fullname" . -}}
{{- include "scrim.agentEnv" (dict "root" . "base" (printf "http://%s:%v" $host .Values.central.service.llmPort) "proxy" (printf "http://%s:%v" $host .Values.central.service.forwardPort) "noProxy" (list $host $short (printf "%s.%s" $short .Release.Namespace) (printf "%s.%s.svc" $short .Release.Namespace))) -}}
{{- end -}}

{{- define "scrim.sidecarAgentEnv" -}}
{{- include "scrim.agentEnv" (dict "root" . "base" "http://127.0.0.1:9790" "proxy" "http://127.0.0.1:9791" "noProxy" (list)) -}}
{{- end -}}

{{/* nftables rules of the sidecar egress guard. */}}
{{- define "scrim.egressGuardScript" -}}
set -eu
nft -f - <<'NFT'
table inet scrim_guard {
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    ct state established,related accept
    meta skuid 65532 accept
    udp dport 53 accept
    tcp dport 53 accept
    meta l4proto tcp reject with tcp reset
    reject with icmpx admin-prohibited
  }
}
NFT
nft list table inet scrim_guard
{{- end -}}

{{/* Egress to the cluster DNS. */}}
{{- define "scrim.dnsEgress" -}}
- to:
    - namespaceSelector:
        {{- toYaml .namespaceSelector | nindent 8 }}
      podSelector:
        {{- toYaml .podSelector | nindent 8 }}
  ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
{{- end -}}

{{/* Volumes and mounts every agent container gets. */}}
{{- define "scrim.agentMounts" -}}
- name: scrim-trust
  mountPath: {{ .Values.agents.trustPath }}
  readOnly: true
{{- if .Values.identity.kubernetes.enabled }}
- name: scrim-identity
  mountPath: {{ dir .Values.identity.kubernetes.tokenPath }}
  readOnly: true
{{- end }}
{{- end -}}

{{- define "scrim.agentVolumes" -}}
- name: scrim-trust
  configMap:
    name: {{ .Values.ca.configMapName }}
{{- if .Values.identity.kubernetes.enabled }}
- name: scrim-identity
  projected:
    sources:
      - serviceAccountToken:
          audience: {{ .Values.identity.kubernetes.audience }}
          expirationSeconds: {{ .Values.identity.kubernetes.expirationSeconds }}
          path: {{ base .Values.identity.kubernetes.tokenPath }}
{{- end }}
{{- end -}}

{{/* Bearer auth of a Prometheus Operator scrape endpoint. */}}
{{- define "scrim.scrapeAuth" -}}
{{- if .Values.metrics.authSecret.name }}
authorization:
  type: Bearer
  credentials:
    name: {{ .Values.metrics.authSecret.name }}
    key: {{ .Values.metrics.authSecret.key }}
{{- end }}
{{- end -}}
