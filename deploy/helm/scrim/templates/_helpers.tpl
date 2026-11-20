{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{/*
=============================================================================
 Names
=============================================================================
Ported from toc-helm-chart-template (templates/_helpers.tpl). The generic
helpers keep the "chart.*" names; scrim's own are "scrim.*" in _scrim.tpl.
Left out: the docker-registry pull Secret and extraSecrets (both put
credentials in values, which this chart refuses) and secrets.values (a slot
is an existing Secret, an ExternalSecret or a generated value, never a
value from values.yaml).
*/}}

{{/* Domain of the chart's own label and annotation keys (helm-test, secret-slot). */}}
{{- define "chart.labelDomain" -}}
scrim.dev
{{- end -}}

{{/* Chart name, truncated to the DNS label limit. */}}
{{- define "chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Release-wide prefix of every object name. A release whose name contains the
chart name keeps the release name alone.
*/}}
{{- define "chart.fullname" -}}
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

{{/* Namespace every object is created in. */}}
{{- define "chart.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Name of one component's objects: "<fullname>-<component>".
Usage: include "chart.componentName" (list $ "app")
*/}}
{{- define "chart.componentName" -}}
{{- $root := index . 0 -}}
{{- $comp := index . 1 -}}
{{- printf "%s-%s" (include "chart.fullname" $root) $comp | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* In-cluster DNS name of a component's Service. Usage: (list $ "kv") */}}
{{- define "chart.serviceHost" -}}
{{- $root := index . 0 -}}
{{- printf "%s.%s.svc.%s" (include "chart.componentName" .) (include "chart.namespace" $root) $root.Values.global.clusterDomain -}}
{{- end -}}

{{- define "chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
=============================================================================
 Labels
=============================================================================
*/}}

{{/* Labels on every object. */}}
{{- define "chart.labels" -}}
helm.sh/chart: {{ include "chart.chart" . }}
app.kubernetes.io/part-of: {{ include "chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- with .Values.global.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- with include "chart.omitKeys" (list (default dict .Values.commonLabels) (default dict .Values.global.commonLabels)) | fromJson }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Selector labels of one component. app.kubernetes.io/name is the component's
object name (<fullname>-app, ...), which is what the network policies select
on. Never add a label that changes between releases: selectors are immutable.
Usage: include "chart.selectorLabels" (list $ "app")
*/}}
{{- define "chart.selectorLabels" -}}
{{- $root := index . 0 -}}
app.kubernetes.io/name: {{ include "chart.componentName" . }}
app.kubernetes.io/instance: {{ $root.Release.Name }}
{{- with include "chart.extraSelectorLabels" $root }}
{{ . }}
{{- end }}
{{- end -}}

{{/*
global.extraSelectorLabels as YAML, minus the chart's own selector keys.
Selectors are immutable: set it on a fresh install only. Changing it on an
existing release fails the upgrade (Deployment/StatefulSet selectors) and
re-selects Services and NetworkPolicies.
*/}}
{{- define "chart.extraSelectorLabels" -}}
{{- with omit (default dict .Values.global.extraSelectorLabels) "app.kubernetes.io/name" "app.kubernetes.io/instance" "app.kubernetes.io/component" "app.kubernetes.io/part-of" "app.kubernetes.io/managed-by" "app.kubernetes.io/version" "helm.sh/chart" -}}
{{- toYaml . -}}
{{- end -}}
{{- end -}}

{{/* Full label set of one component. Usage: (list $ "app") */}}
{{- define "chart.componentLabels" -}}
{{- $root := index . 0 -}}
{{ include "chart.labels" $root }}
app.kubernetes.io/name: {{ include "chart.componentName" . }}
app.kubernetes.io/component: {{ index . 1 }}
{{- with include "chart.extraSelectorLabels" $root }}
{{ . }}
{{- end }}
{{- end -}}

{{/* Annotations on every workload (global.commonAnnotations, commonAnnotations), may be empty. */}}
{{- define "chart.commonAnnotations" -}}
{{- with mustMergeOverwrite (deepCopy (default dict .Values.global.commonAnnotations)) (deepCopy (default dict .Values.commonAnnotations)) }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{/* Entries of a map whose keys another map lacks, as JSON. Usage: (list $m $without) */}}
{{- define "chart.omitKeys" -}}
{{- $out := dict -}}
{{- $without := index . 1 -}}
{{- range $k, $v := index . 0 -}}
{{- if not (hasKey $without $k) -}}{{- $_ := set $out $k $v -}}{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/*
A values "labels" map for one object, minus the keys the chart's own labels
already set (a selector or chart label is never overridden), tpl-rendered.
Prints nothing when empty. Params: root, labels, comp (component, optional).
*/}}
{{- define "chart.extraLabels" -}}
{{- $base := dict -}}
{{- if .comp -}}
{{- $base = include "chart.componentLabels" (list .root .comp) | fromYaml -}}
{{- else -}}
{{- $base = include "chart.labels" .root | fromYaml -}}
{{- end -}}
{{- $extra := include "chart.omitKeys" (list (default dict .labels) $base) | fromJson -}}
{{- with $extra -}}
{{- tpl (toYaml .) $.root -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
 Values helpers
=============================================================================
*/}}

{{/*
Render a value that may contain template syntax.
Usage: include "chart.tpl" (dict "value" .Values.x "context" $)
*/}}
{{- define "chart.tpl" -}}
{{- if kindIs "string" .value -}}
{{- tpl .value .context -}}
{{- else -}}
{{- tpl (.value | toYaml) .context -}}
{{- end -}}
{{- end -}}

{{/*
Image reference. A digest wins over a tag; "tag@digest" keeps the tag readable
while pinning. global.imageRegistry replaces the registry of every image.
useAppVersion: true takes the tag from Chart.appVersion when tag is empty.
Usage: include "chart.image" (dict "root" $ "image" .Values.app.image)
*/}}
{{- define "chart.image" -}}
{{- $img := .image -}}
{{- $registry := default $img.registry .root.Values.global.imageRegistry -}}
{{- $repo := $img.repository -}}
{{- $ref := $repo -}}
{{- if $registry -}}
{{- $ref = printf "%s/%s" $registry $repo -}}
{{- end -}}
{{- $tag := toString (default "" $img.tag) -}}
{{- if and (not $tag) $img.useAppVersion -}}
{{- $tag = .root.Chart.AppVersion -}}
{{- end -}}
{{- if $img.digest -}}
{{- if $tag -}}
{{- printf "%s:%s@%s" $ref $tag $img.digest -}}
{{- else -}}
{{- printf "%s@%s" $ref $img.digest -}}
{{- end -}}
{{- else -}}
{{- printf "%s:%s" $ref (required (printf "image %s needs a tag or a digest" $repo) $tag) -}}
{{- end -}}
{{- end -}}

{{/*
Boolean with a default that survives an explicit false ("default" treats false
as unset). Prints "true" or nothing. Usage: include "chart.flag" (list $map "key" true)
*/}}
{{- define "chart.flag" -}}
{{- $m := index . 0 | default dict -}}
{{- $k := index . 1 -}}
{{- $d := index . 2 -}}
{{- $v := $d -}}
{{- if and (kindIs "map" $m) (hasKey $m $k) -}}{{- $v = index $m $k -}}{{- end -}}
{{- if and $v (ne (toString $v) "false") -}}true{{- end -}}
{{- end -}}

{{/* pullPolicy of an image, defaulting to IfNotPresent. */}}
{{- define "chart.imagePullPolicy" -}}
{{- default "IfNotPresent" .pullPolicy -}}
{{- end -}}

{{/*
imagePullSecrets for a pod: global.imagePullSecrets plus the component's own.
Accepts names as strings or {name: x}.
Usage: include "chart.imagePullSecrets" (dict "root" $ "values" .Values.app)
*/}}
{{- define "chart.imagePullSecrets" -}}
{{- $names := list -}}
{{- range (concat (default list .root.Values.global.imagePullSecrets) (default list .values.imagePullSecrets)) -}}
{{- if kindIs "string" . -}}
{{- $names = append $names . -}}
{{- else -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- end -}}
{{- if $names }}
imagePullSecrets:
{{- range ($names | uniq) }}
  - name: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Container securityContext: the hardened defaults from global, overlaid by the
component's own. Usage: (dict "root" $ "values" .Values.app)
*/}}
{{- define "chart.containerSecurityContext" -}}
{{- $base := deepCopy (default dict .root.Values.global.containerSecurityContext) -}}
{{- $sc := mustMergeOverwrite $base (deepCopy (default dict .values.securityContext)) -}}
{{- toYaml $sc -}}
{{- end -}}

{{/* Pod securityContext: global defaults overlaid by the component's own. */}}
{{- define "chart.podSecurityContext" -}}
{{- $base := deepCopy (default dict .root.Values.global.podSecurityContext) -}}
{{- $sc := mustMergeOverwrite $base (deepCopy (default dict .values.podSecurityContext)) -}}
{{- toYaml $sc -}}
{{- end -}}

{{/*
Probes of the main container. Each probe is {enabled: bool, ...probe spec}.
Usage: include "chart.probes" .Values.app
*/}}
{{- define "chart.probes" -}}
{{- range $kind := list "startupProbe" "livenessProbe" "readinessProbe" -}}
{{- $p := index $ $kind -}}
{{- if and $p (include "chart.flag" (list $p "enabled" true)) }}
{{ $kind }}:
{{- toYaml (omit $p "enabled") | nindent 2 }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
 Secrets
=============================================================================
Every credential lives in a Secret "slot". A slot's Secret is, in order:
  1. secrets.existing.<slot>                a Secret you manage (nothing rendered)
  2. secrets.externalSecrets.data.<slot>    an ExternalSecret the chart renders
  3. a chart-rendered Secret with the value already in the cluster (lookup),
     else a random one for generated keys. There is no secrets.values: a
     credential never comes from values.yaml.
*/}}

{{/* Name of a slot's Secret. Usage: include "chart.secretName" (list $ "kv") */}}
{{- define "chart.secretName" -}}
{{- $root := index . 0 -}}
{{- $slot := index . 1 -}}
{{- $existing := index (default dict $root.Values.secrets.existing) $slot -}}
{{- if $existing -}}
{{- tpl $existing $root -}}
{{- else -}}
{{- include "chart.componentName" (list $root $slot) -}}
{{- end -}}
{{- end -}}

{{/* Key a slot uses for a logical key (secrets.keys.<slot>.<key> renames it). */}}
{{- define "chart.secretKey" -}}
{{- $root := index . 0 -}}
{{- $slot := index . 1 -}}
{{- $key := index . 2 -}}
{{- $map := index (default dict $root.Values.secrets.keys) $slot | default dict -}}
{{- default $key (index $map $key) -}}
{{- end -}}

{{/*
Render a slot: an ExternalSecret, a Secret, or nothing.
Optional param values: the owning component's values block (its
secretLabels / secretAnnotations / replication).
Usage:
  include "chart.secret" (dict "root" $ "slot" "kv" "keys" (list
    (dict "name" "password" "generate" true "length" 48)
    (dict "name" "token" "required" true)     # input, no generation
  ))
Generated values are hex (URL-safe), persisted across upgrades by lookup and
kept on uninstall.
*/}}
{{- define "chart.secret" -}}
{{- $root := .root -}}
{{- $slot := .slot -}}
{{- $domain := include "chart.labelDomain" $root -}}
{{- $existing := index (default dict $root.Values.secrets.existing) $slot -}}
{{- if not $existing -}}
{{- $name := include "chart.componentName" (list $root $slot) -}}
{{- $es := $root.Values.secrets.externalSecrets -}}
{{- $esData := index (default dict $es.data) $slot -}}
{{- if and $es.enabled $esData }}
---
apiVersion: {{ $es.apiVersion }}
kind: ExternalSecret
metadata:
  name: {{ $name }}
  namespace: {{ include "chart.namespace" $root }}
  {{- $esMeta := dict "root" $root "kind" "ExternalSecret" "name" $name }}
  labels:
    {{- include "chart.labels" $root | nindent 4 }}
    {{ $domain }}/secret-slot: {{ $slot }}
    {{- with include "chart.metaLabels" $esMeta }}
    {{- . | nindent 4 }}
    {{- end }}
  {{- with include "chart.metaAnnotations" $esMeta }}
  annotations:
    {{- . | nindent 4 }}
  {{- end }}
spec:
  refreshInterval: {{ $es.refreshInterval }}
  {{- $_ := required "secrets.externalSecrets.secretStoreRef.name is required" $es.secretStoreRef.name }}
  secretStoreRef:
    {{- toYaml $es.secretStoreRef | nindent 4 }}
  target:
    name: {{ $name }}
    creationPolicy: Owner
    {{- /* The Secret external-secrets writes gets the same metadata hooks as a chart-rendered one. */ -}}
    {{- $tm := include "chart.meta" (dict "root" $root "kind" "Secret" "name" $name "values" .values) | fromJson }}
    {{- if or $tm.labels $tm.annotations }}
    template:
      mergePolicy: Merge
      metadata:
        {{- with $tm.labels }}
        labels:
          {{- tpl (toYaml .) $root | nindent 10 }}
        {{- end }}
        {{- with $tm.annotations }}
        annotations:
          {{- tpl (toYaml .) $root | nindent 10 }}
        {{- end }}
    {{- end }}
  data:
    {{- range $k, $ref := $esData }}
    - secretKey: {{ include "chart.secretKey" (list $root $slot $k) }}
      remoteRef:
        {{- if kindIs "string" $ref }}
        key: {{ $ref }}
        {{- else }}
        {{- toYaml $ref | nindent 8 }}
        {{- end }}
    {{- end }}
{{- else }}
{{- $current := dict -}}
{{- $found := lookup "v1" "Secret" (include "chart.namespace" $root) $name -}}
{{- if $found -}}{{- $current = default dict $found.data -}}{{- end -}}
{{- $data := dict -}}
{{- range .keys -}}
{{- $k := include "chart.secretKey" (list $root $slot .name) -}}
{{- if index $current $k -}}
{{- $_ := set $data $k (index $current $k) -}}
{{- else if .generate -}}
{{- $_ := set $data $k (randAlphaNum (int (default 48 .length)) | lower | sha256sum | trunc (int (default 48 .length)) | b64enc) -}}
{{- else if .required -}}
{{- fail (printf "secret %s key %s has no value: set secrets.existing.%s to a Secret you manage, or map it in secrets.externalSecrets.data.%s" $slot .name $slot $slot) -}}
{{- end -}}
{{- end }}
---
apiVersion: v1
kind: Secret
metadata:
  name: {{ $name }}
  namespace: {{ include "chart.namespace" $root }}
  {{- $sMeta := dict "root" $root "kind" "Secret" "name" $name "values" .values "skipAnnotations" (list "helm.sh/resource-policy") }}
  labels:
    {{- include "chart.labels" $root | nindent 4 }}
    {{ $domain }}/secret-slot: {{ $slot }}
    {{- with include "chart.metaLabels" $sMeta }}
    {{- . | nindent 4 }}
    {{- end }}
  annotations:
    # Generated values must survive an uninstall/reinstall (a data store
    # keeps the old password).
    helm.sh/resource-policy: keep
    {{- with include "chart.metaAnnotations" $sMeta }}
    {{- . | nindent 4 }}
    {{- end }}
type: Opaque
{{- with $data }}
data:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
=============================================================================
 Extra ConfigMaps and Secrets
=============================================================================
extraConfigMaps: a map of key -> spec, rendered as "<fullname>-<key>" (or
spec.name), or not rendered at all when the spec names an existingConfigMap. Reference them from extraVolumes,
extraEnv or extraEnvFrom by this helper so a values file can switch between
an inline object and an existing one without touching the mounts:
  {{ include "chart.extraConfigMapName" (list $ "ca-bundle") }}
*/}}
{{- define "chart.extraConfigMapName" -}}
{{- $root := index . 0 -}}
{{- $key := index . 1 -}}
{{- $c := index (default dict $root.Values.extraConfigMaps) $key | default dict -}}
{{- if $c.existingConfigMap -}}
{{- tpl $c.existingConfigMap $root -}}
{{- else if $c.name -}}
{{- tpl $c.name $root -}}
{{- else -}}
{{- include "chart.componentName" (list $root $key) -}}
{{- end -}}
{{- end -}}

{{/*
Checksum of the chart-rendered extraConfigMaps a pod
references (volumes, projected sources, envFrom, env valueFrom), so the pod
rolls when one changes. Empty when it references none.
Params: root, volumes (list), containers (list, init containers included).
*/}}
{{- define "chart.extraObjects.checksum" -}}
{{- $root := .root -}}
{{- $known := dict -}}
{{- range $k, $c := (default dict $root.Values.extraConfigMaps) -}}
{{- if and $c (not $c.existingConfigMap) -}}{{- $_ := set $known (printf "cm/%s" (include "chart.extraConfigMapName" (list $root $k))) $c -}}{{- end -}}
{{- end -}}
{{- if $known -}}
{{- $refs := list -}}
{{- range (tpl (toYaml (default list .volumes)) $root | fromYamlArray) -}}
{{- with .configMap }}{{ $refs = append $refs (printf "cm/%s" .name) }}{{ end -}}
{{- with .secret }}{{ $refs = append $refs (printf "secret/%s" .secretName) }}{{ end -}}
{{- with .projected -}}
{{- range .sources -}}
{{- with .configMap }}{{ $refs = append $refs (printf "cm/%s" .name) }}{{ end -}}
{{- with .secret }}{{ $refs = append $refs (printf "secret/%s" .name) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range (tpl (toYaml (default list .containers)) $root | fromYamlArray) -}}
{{- range .envFrom -}}
{{- with .configMapRef }}{{ $refs = append $refs (printf "cm/%s" .name) }}{{ end -}}
{{- with .secretRef }}{{ $refs = append $refs (printf "secret/%s" .name) }}{{ end -}}
{{- end -}}
{{- range .env -}}
{{- with .valueFrom -}}
{{- with .configMapKeyRef }}{{ $refs = append $refs (printf "cm/%s" .name) }}{{ end -}}
{{- with .secretKeyRef }}{{ $refs = append $refs (printf "secret/%s" .name) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $hit := dict -}}
{{- range $r := ($refs | uniq) -}}
{{- with index $known $r -}}{{- $_ := set $hit $r (tpl (toJson .) $root) -}}{{- end -}}
{{- end -}}
{{- with $hit -}}{{- toJson . | sha256sum -}}{{- end -}}
{{- end -}}
{{- end -}}

{{/*
=============================================================================
 Object metadata hooks
=============================================================================
Extra labels and annotations of one object, on top of what its template
prints. Params:
  root
  kind        object kind; Secret and ConfigMap pick up global and component
              secretLabels/secretAnnotations/configMapLabels/
              configMapAnnotations and the replication annotations,
              NetworkPolicy networkPolicy.labels/annotations
  name        rendered object name (objectMetadata lookup)
  comp        component whose labels the object carries (keys never overridden)
  values      component values block (secretLabels, ... , replication), optional
  labels, annotations   object-specific maps from values, optional
  replication           object-specific replication override, optional
  skipAnnotations       list of annotation keys the template already prints
Precedence, later wins: commonAnnotations, global kind maps, component kind
maps, replication, object maps, objectMetadata["<Kind>/<name>"].
Returns JSON {labels, annotations}.
*/}}
{{- define "chart.meta" -}}
{{- $root := .root -}}
{{- $g := $root.Values.global -}}
{{- $v := .values | default dict -}}
{{- $labels := dict -}}
{{- $ann := include "chart.commonAnnotations" $root | fromYaml | default dict -}}
{{- $repl := deepCopy (default dict $g.replication) -}}
{{- if eq .kind "Secret" -}}
{{- $labels = mustMergeOverwrite $labels (deepCopy (default dict $g.secretLabels)) (deepCopy (default dict $v.secretLabels)) -}}
{{- $ann = mustMergeOverwrite $ann (deepCopy (default dict $g.secretAnnotations)) (deepCopy (default dict $v.secretAnnotations)) -}}
{{- else if eq .kind "ConfigMap" -}}
{{- $labels = mustMergeOverwrite $labels (deepCopy (default dict $g.configMapLabels)) (deepCopy (default dict $v.configMapLabels)) -}}
{{- $ann = mustMergeOverwrite $ann (deepCopy (default dict $g.configMapAnnotations)) (deepCopy (default dict $v.configMapAnnotations)) -}}
{{- else if eq .kind "NetworkPolicy" -}}
{{- $labels = mustMergeOverwrite $labels (deepCopy (default dict $root.Values.networkPolicy.labels)) -}}
{{- $ann = mustMergeOverwrite $ann (deepCopy (default dict $root.Values.networkPolicy.annotations)) -}}
{{- end -}}
{{- $labels = mustMergeOverwrite $labels (deepCopy (default dict .labels)) -}}
{{- $ann = mustMergeOverwrite $ann (deepCopy (default dict .annotations)) -}}
{{- $om := dict -}}
{{- with .name -}}
{{- $short := trimPrefix (printf "%s-" (include "chart.fullname" $root)) . -}}
{{- $all := default dict $root.Values.objectMetadata -}}
{{- $om = mustMergeOverwrite (deepCopy (default dict (index $all (printf "%s/%s" $.kind $short)))) (deepCopy (default dict (index $all (printf "%s/%s" $.kind .)))) -}}
{{- end -}}
{{- if has .kind (list "Secret" "ConfigMap") -}}
{{- $repl = mustMergeOverwrite $repl (deepCopy (default dict $v.replication)) (deepCopy (default dict .replication)) (deepCopy (default dict $om.replication)) -}}
{{- $ann = mustMergeOverwrite $ann (include "chart.replicationAnnotations" $repl | fromJson) -}}
{{- end -}}
{{- $labels = mustMergeOverwrite $labels (deepCopy (default dict $om.labels)) -}}
{{- $ann = mustMergeOverwrite $ann (deepCopy (default dict $om.annotations)) -}}
{{- $base := dict -}}
{{- if .comp -}}
{{- $base = include "chart.componentLabels" (list $root .comp) | fromYaml -}}
{{- else -}}
{{- $base = include "chart.labels" $root | fromYaml -}}
{{- end -}}
{{- $labels = include "chart.omitKeys" (list $labels $base) | fromJson -}}
{{- $skip := dict -}}
{{- range (default list .skipAnnotations) -}}{{- $_ := set $skip . true -}}{{- end -}}
{{- $ann = include "chart.omitKeys" (list $ann $skip) | fromJson -}}
{{- toJson (dict "labels" $labels "annotations" $ann) -}}
{{- end -}}

{{/* Extra labels of one object as YAML lines (chart.meta params), or nothing. */}}
{{- define "chart.metaLabels" -}}
{{- with (include "chart.meta" . | fromJson).labels -}}
{{- tpl (toYaml .) $.root -}}
{{- end -}}
{{- end -}}

{{/* Extra annotations of one object as YAML lines (chart.meta params), or nothing. */}}
{{- define "chart.metaAnnotations" -}}
{{- with (include "chart.meta" . | fromJson).annotations -}}
{{- tpl (toYaml .) $.root -}}
{{- end -}}
{{- end -}}

{{/*
The metadata block of one object: name, namespace, labels (component or
release labels plus chart.meta's) and annotations. Params as chart.meta.
*/}}
{{- define "chart.objectMeta" -}}
name: {{ .name }}
namespace: {{ include "chart.namespace" .root }}
labels:
  {{- if .comp }}
  {{- include "chart.componentLabels" (list .root .comp) | nindent 2 }}
  {{- else }}
  {{- include "chart.labels" .root | nindent 2 }}
  {{- end }}
  {{- with include "chart.metaLabels" . }}
  {{- . | nindent 2 }}
  {{- end }}
{{- with include "chart.metaAnnotations" . }}
annotations:
  {{- . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Replication annotations for a Secret or ConfigMap, as JSON.
  mode: none | reflector (emberstack Reflector) | replicator (mittwald
  kubernetes-replicator)
  allowedNamespaces: namespaces (regex allowed) that may copy the object
  autoNamespaces:    namespaces the object is pushed into
  replicateFrom:     replicator only, "<namespace>/<name>" this object is filled from
*/}}
{{- define "chart.replicationAnnotations" -}}
{{- $r := . | default dict -}}
{{- $mode := default "none" $r.mode -}}
{{- $allowed := default list $r.allowedNamespaces -}}
{{- $auto := default list $r.autoNamespaces -}}
{{- $out := dict -}}
{{- if eq $mode "reflector" -}}
{{- $p := "reflector.v1.k8s.emberstack.com" -}}
{{- $_ := set $out (printf "%s/reflection-allowed" $p) "true" -}}
{{- with $allowed -}}{{- $_ := set $out (printf "%s/reflection-allowed-namespaces" $p) (join "," .) -}}{{- end -}}
{{- if $auto -}}
{{- $_ := set $out (printf "%s/reflection-auto-enabled" $p) "true" -}}
{{- $_ := set $out (printf "%s/reflection-auto-namespaces" $p) (join "," $auto) -}}
{{- end -}}
{{- else if eq $mode "replicator" -}}
{{- $p := "replicator.v1.mittwald.de" -}}
{{- if or $allowed (not $auto) -}}
{{- $_ := set $out (printf "%s/replication-allowed" $p) "true" -}}
{{- with $allowed -}}{{- $_ := set $out (printf "%s/replication-allowed-namespaces" $p) (join "," .) -}}{{- end -}}
{{- end -}}
{{- with $auto -}}{{- $_ := set $out (printf "%s/replicate-to" $p) (join "," .) -}}{{- end -}}
{{- with $r.replicateFrom -}}{{- $_ := set $out (printf "%s/replicate-from" $p) . -}}{{- end -}}
{{- else if ne $mode "none" -}}
{{- fail (printf "replication.mode must be none, reflector or replicator, not %q" $mode) -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}
