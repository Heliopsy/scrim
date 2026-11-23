{{/* SPDX-License-Identifier: AGPL-3.0-only */}}

{{/*
scrim's own helpers. Names, labels and images come from the shared helpers in
_helpers.tpl (chart.*); these wrap them for scrim's component, "proxy".
*/}}
{{- define "scrim.fullname" -}}
{{- include "chart.fullname" . -}}
{{- end -}}

{{- define "scrim.labels" -}}
{{- include "chart.labels" . -}}
{{- end -}}

{{/* Labels of central scrim's objects and pods. */}}
{{- define "scrim.componentLabels" -}}
{{- include "chart.componentLabels" (list . "proxy") -}}
{{- end -}}

{{- define "scrim.selectorLabels" -}}
{{- include "chart.selectorLabels" (list . "proxy") -}}
{{- end -}}

{{- define "scrim.namespace" -}}
{{- include "chart.namespace" . -}}
{{- end -}}

{{/*
central's values with the global.ha preset merged in, as JSON. Every template
that reads the replica count, the PDB or the scheduling of central scrim
reads this.
*/}}
{{- define "scrim.central" -}}
{{- $v := deepCopy .Values.central -}}
{{- toJson (mustMergeOverwrite $v (include "chart.ha.delta" (dict "root" . "comp" "proxy" "values" .Values.central) | fromJson)) -}}
{{- end -}}

{{/* Replicas central scrim may run: the HPA maximum, else the replica count. */}}
{{- define "scrim.maxReplicas" -}}
{{- $c := include "scrim.central" . | fromJson -}}
{{- if $c.autoscaling.enabled }}{{ int $c.autoscaling.maxReplicas }}{{ else }}{{ int $c.replicaCount }}{{ end -}}
{{- end -}}

{{- define "scrim.serviceAccountName" -}}
{{- include "chart.serviceAccountName" (list . "proxy" .Values.central) -}}
{{- end -}}

{{- define "scrim.image" -}}
{{- include "chart.image" (dict "root" . "image" .Values.image) -}}
{{- end -}}

{{/* Host name of the central Service as agents use it. */}}
{{- define "scrim.serviceHost" -}}
{{- printf "%s.%s.svc.%s" (include "scrim.fullname" .) (include "scrim.namespace" .) .Values.global.clusterDomain -}}
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
{{- $existing := lookup "v1" "Secret" (include "scrim.namespace" .) $name -}}
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
{{- $s := lookup "v1" "Secret" (include "scrim.namespace" .) .Values.ca.existingSecret -}}
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
{{- $existing := lookup "v1" "Secret" (include "scrim.namespace" .) $name -}}
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
{{- fail "config.admin.token holds a literal; use admin.tcp with the Secret slot admin (secrets.existing.admin)" -}}
{{- end -}}
{{- end -}}
{{- with (index $cfg "identity") -}}
{{- if kindIs "map" . -}}
{{- range $k, $v := (default dict (index . "store-credentials")) -}}
{{- if and (kindIs "string" $v) (not (include "scrim.isRef" $v)) -}}
{{- fail (printf "config.identity.store-credentials.%s holds a literal; use a reference (file:/run/secrets/scrim/<mount>/<key>, env:NAME or a store reference)" $k) -}}
{{- end -}}
{{- end -}}
{{- if hasKey . "kubernetes" -}}
{{- fail "config.identity.kubernetes is set by the chart; use the identity.kubernetes values" -}}
{{- end -}}
{{- if hasKey . "issuer" -}}
{{- fail "config.identity.issuer is set by the chart; use the identity.issuer values" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- include "scrim.checkIssuer" . -}}
{{- range $section := list "state" "events" "deployment" "valkey" "nats" -}}
{{- if hasKey $cfg $section -}}
{{- fail (printf "config.%s is set by the chart; use the postgres, events, valkey and nats values and central.replicaCount" $section) -}}
{{- end -}}
{{- end -}}
{{- if hasKey $cfg "metrics" -}}
{{- fail "config.metrics is set by the chart; use the metrics values" -}}
{{- end -}}
{{- $c := include "scrim.central" . | fromJson -}}
{{- if and .Values.central.enabled (or (gt (int (include "scrim.maxReplicas" .)) 1) $c.autoscaling.enabled) -}}
{{- if not .Values.postgres.enabled -}}
{{- fail "several replicas need shared state and events: set postgres.enabled=true and the Secret slot postgres (state.backend and events.backend postgres)" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.postgres.enabled (not (include "scrim.slotSupplied" (list . "postgres"))) -}}
{{- fail "postgres.enabled needs the DSN in the Secret slot postgres: secrets.existing.postgres or secrets.externalSecrets.data.postgres (key dsn)" -}}
{{- end -}}
{{- if and .Values.sidecar.enabled .Values.metrics.enabled (not .Values.metrics.allowUnauthenticatedRemote) (not (index (default dict .Values.secrets.existing) "metrics")) -}}
{{- fail "sidecar mode with metrics needs secrets.existing.metrics: a token Secret that exists in every agent namespace (the generated one lives in the release namespace only), or metrics.allowUnauthenticatedRemote=true" -}}
{{- end -}}
{{- if and .Values.central.autoscaling.enabled .Values.central.autoscaling.connections.enabled (not .Values.metrics.enabled) -}}
{{- fail "central.autoscaling.connections needs metrics.enabled: the adapter reads scrim_dataplane_connections_active from scrim's metrics" -}}
{{- end -}}
{{- if and .Values.admin.tcp.enabled (not (include "scrim.slotSupplied" (list . "admin"))) -}}
{{- fail "admin.tcp.enabled needs the token in the Secret slot admin: secrets.existing.admin or secrets.externalSecrets.data.admin (key token); scrim refuses a TCP admin listener without one" -}}
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

{{/* "true" when a Secret slot that is never generated has a source: an existing Secret or an ExternalSecret. */}}
{{- define "scrim.slotSupplied" -}}
{{- $root := index . 0 -}}
{{- $slot := index . 1 -}}
{{- $es := $root.Values.secrets.externalSecrets -}}
{{- if or (index (default dict $root.Values.secrets.existing) $slot) (and $es.enabled (index (default dict $es.data) $slot)) -}}true{{- end -}}
{{- end -}}

{{/* metrics.*: the listener always serves /livez and /readyz for the probes. */}}
{{- define "scrim.metricsSettings" -}}
{{- $m := .root.Values.metrics -}}
metrics:
  listen: {{ .listen }}
  enabled: {{ $m.enabled }}
{{- if $m.enabled }}
  path: {{ $m.path }}
{{- if $m.allowUnauthenticatedRemote }}
  allow-unauthenticated-remote: true
{{- else }}
  auth:
    token: file:/run/secrets/scrim/metrics/{{ include "chart.secretKey" (list .root "metrics" "token") }}
{{- end }}
{{- end }}
{{- end -}}

{{/* identity.kubernetes.*, and identity.issuer.* with .issuer (central). .tokenFile and .caFile override scrim's own API credentials. */}}
{{- define "scrim.identitySettings" -}}
{{- $k := .root.Values.identity.kubernetes -}}
identity:
  kubernetes:
    enabled: {{ $k.enabled }}
{{- if $k.enabled }}
    audience: {{ $k.audience }}
    unmapped: {{ $k.unmapped }}
{{- with .tokenFile }}
    token-file: {{ . }}
{{- end }}
{{- with .caFile }}
    ca-file: {{ . }}
{{- end }}
{{- with $k.agents }}
    agents:
      {{- toYaml . | nindent 6 }}
{{- end }}
{{- end }}
{{- if and .issuer .root.Values.identity.issuer.enabled }}
  {{- include "scrim.issuerSettings" .root | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
identity.issuer.*, central scrim only. The listener serves discovery and the
JWKS on the pod IP; generated keys go in a directory scrim creates with mode
0700 inside the key volume (emptyDir or PVC roots are group-writable, which
scrim refuses), operator keys come from a Secret mount.
*/}}
{{- define "scrim.issuerSettings" -}}
{{- $i := .Values.identity.issuer -}}
issuer:
  url: {{ $i.url | quote }}
  listen: 0.0.0.0:{{ $i.port }}
  token-ttl: {{ $i.tokenTTL }}
{{- if $i.insecureHTTP }}
  insecure-http: true
{{- end }}
{{- if $i.signingKeys.existingSecret }}
  signing-keys: file:/run/secrets/scrim/issuer-keys/{{ $i.signingKeys.key }}
{{- else }}
  key-dir: {{ include "scrim.issuerKeyDir" . }}
  rotate-every: {{ $i.rotateEvery }}
{{- end }}
{{- end -}}

{{- define "scrim.issuerKeyMount" -}}/var/lib/scrim-issuer{{- end -}}
{{- define "scrim.issuerKeyDir" -}}{{ include "scrim.issuerKeyMount" . }}/keys{{- end -}}

{{- define "scrim.issuerClaimName" -}}
{{- default (printf "%s-issuer-keys" (include "scrim.fullname" .)) .Values.identity.issuer.keyStore.existingClaim -}}
{{- end -}}

{{/* Path of the issuer URL, under which the listener serves its two documents. */}}
{{- define "scrim.issuerPath" -}}
{{- (urlParse .Values.identity.issuer.url).path | trimSuffix "/" -}}
{{- end -}}

{{/* identity.issuer values the schema cannot check. */}}
{{- define "scrim.checkIssuer" -}}
{{- $i := .Values.identity.issuer -}}
{{- if $i.enabled -}}
{{- if not .Values.central.enabled -}}
{{- fail "identity.issuer.enabled runs in central scrim, which central.enabled=false does not deploy" -}}
{{- end -}}
{{- if not $i.url -}}
{{- fail "identity.issuer.enabled needs identity.issuer.url: the https URL stores fetch the discovery document from (an Ingress or Gateway in front of the Service <fullname>-issuer)" -}}
{{- end -}}
{{- $u := urlParse $i.url -}}
{{- if or (not (has $u.scheme (list "https" "http"))) (not $u.host) $u.query $u.fragment $u.userinfo (hasSuffix "/" $i.url) -}}
{{- fail (printf "identity.issuer.url %q must be an absolute https URL without query, fragment, user info or trailing slash" $i.url) -}}
{{- end -}}
{{- if and (eq $u.scheme "http") (not $i.insecureHTTP) -}}
{{- fail (printf "identity.issuer.url %q is plain http: use https (terminate TLS in front of the issuer Service), or set identity.issuer.insecureHTTP=true and accept that anyone between a store and scrim can substitute the signing keys" $i.url) -}}
{{- end -}}
{{- $c := include "scrim.central" . | fromJson -}}
{{- $several := or (gt (int (include "scrim.maxReplicas" .)) 1) $c.autoscaling.enabled -}}
{{- if and $several (not $i.signingKeys.existingSecret) -}}
{{- fail "identity.issuer with more than one replica needs identity.issuer.signingKeys.existingSecret: replicas behind one issuer URL must publish the same keys, and generated keys are per pod" -}}
{{- end -}}
{{- if and (not $i.signingKeys.existingSecret) (eq $i.keyStore.type "pvc") (ne (toString (dig "strategy" "type" "" $c)) "Recreate") -}}
{{- fail "identity.issuer.keyStore.type pvc needs central.strategy.type=Recreate: two pods must not rotate keys in one directory, and a rolling update runs the old and the new pod together" -}}
{{- end -}}
{{- $taken := list 9790 9791 (int .Values.metrics.port) -}}
{{- if .Values.admin.tcp.enabled }}{{ $taken = append $taken (int .Values.admin.tcp.port) }}{{ end -}}
{{- if .Values.edge.enabled }}{{ $taken = append $taken (int .Values.edge.port) }}{{ end -}}
{{- if has (int $i.port) $taken -}}
{{- fail (printf "identity.issuer.port %v is taken by another scrim listener" $i.port) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Where the sidecar's own API token and the API server CA are mounted (TokenReview). */}}
{{- define "scrim.sidecarAPIPath" -}}/var/run/secrets/scrim/kube-api{{- end -}}

{{/*
scrim-exec: runs a command with the pod's identity (design D14). It reads the projected token
when the command starts and sends it where scrim expects a caller's token: the password of the
proxy user k8s in the proxy variables, and x-scrim-session in ANTHROPIC_CUSTOM_HEADERS for the
base URL. Plain POSIX sh with no other tools, for a read-only root filesystem.
*/}}
{{- define "scrim.execScript" -}}
#!/bin/sh
# scrim-exec COMMAND [ARGS...]: run COMMAND identified to scrim by this pod's service account
# (docs/kubernetes.md, "Identity"). Generated by the scrim Helm chart.
set -eu
f="${SCRIM_K8S_TOKEN_FILE:?scrim-exec: SCRIM_K8S_TOKEN_FILE is not set}"
[ "$#" -gt 0 ] || { echo "scrim-exec: no command" >&2; exit 2; }
tok=
IFS= read -r tok < "$f" || true
[ -n "$tok" ] || { echo "scrim-exec: $f is empty" >&2; exit 1; }
for v in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy; do
  eval "u=\${$v:-}"
  case $u in
    http://*@*) ;;
    http://*) export "$v=http://k8s:$tok@${u#http://}" ;;
  esac
done
# git sends proxy credentials only after a 407, which scrim never sends.
export GIT_HTTP_PROXY_AUTHMETHOD=basic
nl='
'
hdrs=
old_ifs=$IFS
IFS=$nl
set -f
for line in ${ANTHROPIC_CUSTOM_HEADERS:-}; do
  case $line in
    [Xx]-[Ss][Cc][Rr][Ii][Mm]-[Ss][Ee][Ss][Ss][Ii][Oo][Nn]:*) ;;
    *) hdrs="$hdrs$line$nl" ;;
  esac
done
set +f
IFS=$old_ifs
export ANTHROPIC_CUSTOM_HEADERS="${hdrs}x-scrim-session: $tok"
unset f tok u v hdrs line nl old_ifs
exec "$@"
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
{{- if $root.Values.identity.kubernetes.enabled }}
- name: SCRIM_K8S_TOKEN_FILE
  value: {{ $root.Values.identity.kubernetes.tokenPath | quote }}
{{- end }}
{{- with $root.Values.agents.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "scrim.centralAgentEnv" -}}
{{- $host := include "scrim.serviceHost" . -}}
{{- $short := include "scrim.fullname" . -}}
{{- include "scrim.agentEnv" (dict "root" . "base" (printf "http://%s:%v" $host .Values.central.service.llmPort) "proxy" (printf "http://%s:%v" $host .Values.central.service.forwardPort) "noProxy" (list $host $short (printf "%s.%s" $short (include "scrim.namespace" .)) (printf "%s.%s.svc" $short (include "scrim.namespace" .)))) -}}
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
    items:
      - key: scrim-ca.pem
        path: scrim-ca.pem
      - key: ca-bundle.pem
        path: ca-bundle.pem
      {{- if .Values.identity.kubernetes.enabled }}
      - key: scrim-exec
        path: scrim-exec
        mode: 0555
      {{- end }}
{{- if .Values.identity.kubernetes.enabled }}
- name: scrim-identity
  projected:
    # Readable by whatever user the agent runs as; only agent containers mount it.
    defaultMode: 0444
    sources:
      - serviceAccountToken:
          audience: {{ .Values.identity.kubernetes.audience }}
          expirationSeconds: {{ .Values.identity.kubernetes.expirationSeconds }}
          path: {{ base .Values.identity.kubernetes.tokenPath }}
{{- end }}
{{- end -}}

{{/* Bearer auth of a Prometheus Operator scrape endpoint: the Secret slot metrics. */}}
{{- define "scrim.scrapeAuth" -}}
{{- if not .Values.metrics.allowUnauthenticatedRemote }}
authorization:
  type: Bearer
  credentials:
    name: {{ include "chart.secretName" (list . "metrics") }}
    key: {{ include "chart.secretKey" (list . "metrics" "token") }}
{{- end }}
{{- end -}}
