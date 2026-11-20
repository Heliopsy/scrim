{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{/*
=============================================================================
 Standard component library (chart.std.*)
=============================================================================
Ported from toc-helm-chart-template (templates/_component.tpl); README.md,
"Differences from the chart template", lists what changed. Every pod the
chart renders itself (central scrim, helm test pods) is built from these
named templates, so it gets the same scheduling knobs, security defaults,
extra* hooks and labels. The in-pod scrim of sidecar mode is a Kyverno patch
(templates/kyverno.yaml), not a pod the chart renders.

A component's values block follows one shape (values.yaml, central):

  enabled, image{registry,repository,tag,digest,useAppVersion,pullPolicy},
  replicaCount, strategy (updateStrategy for a StatefulSet), resources,
  nodeSelector, tolerations, affinity, topologySpreadConstraints,
  priorityClassName, terminationGracePeriodSeconds, imagePullSecrets,
  podAnnotations, podLabels, annotations, labels, podSecurityContext,
  securityContext, serviceAccount{create,name,annotations,labels,automount},
  service{type,port,annotations,labels}, startupProbe, livenessProbe,
  readinessProbe, pdb{enabled,minAvailable,maxUnavailable,labels,annotations},
  autoscaling{enabled,minReplicas,maxReplicas,targetCPUUtilizationPercentage,
  targetMemoryUtilizationPercentage,labels,annotations}, extraArgs, extraEnv,
  extraEnvFrom, extraVolumes, extraVolumeMounts, extraContainers,
  extraInitContainers, networkPolicy{extraFrom,extraIngress,extraEgress,
  labels,annotations}, secretLabels, secretAnnotations, configMapLabels,
  configMapAnnotations, replication, lifecycle, dnsPolicy, dnsConfig,
  hostAliases, runtimeClassName, shareProcessNamespace, enableServiceLinks

Scrim's changes: chart.std.workload takes a name (central scrim keeps the
release's full name, which agents use as its Service address), chart.std.hpa
takes extraMetrics and behavior, the NetworkPolicy switch is
networkPolicy.enabled, and the PVC and internet-egress helpers are left out.

global.extraVolumes, global.podAnnotations, global.podLabels, global.affinity,
global.topologySpreadConstraints, global.dnsPolicy, global.dnsConfig,
global.hostAliases, global.runtimeClassName, global.shareProcessNamespace and
global.enableServiceLinks reach every pod; global.extraEnv,
global.extraEnvFrom, global.extraVolumeMounts and global.lifecycle every main
container. A component's own value wins over the global one.

Missing keys are treated as empty, so a component only declares what applies.
*/}}

{{/* ServiceAccount name of a component. Usage: (list $ "app" .Values.app) */}}
{{- define "chart.serviceAccountName" -}}
{{- $root := index . 0 -}}
{{- $comp := index . 1 -}}
{{- $sa := (index . 2).serviceAccount | default dict -}}
{{- if include "chart.flag" (list $sa "create" true) -}}
{{- default (include "chart.componentName" (list $root $comp)) $sa.name -}}
{{- else -}}
{{- default "default" $sa.name -}}
{{- end -}}
{{- end -}}

{{/*
ServiceAccount. automountServiceAccountToken is false unless the component
needs the token (serviceAccount.automount=true).
Usage: include "chart.std.serviceAccount" (dict "root" $ "comp" "app" "values" .Values.app)
*/}}
{{- define "chart.std.serviceAccount" -}}
{{- $sa := .values.serviceAccount | default dict -}}
{{- if include "chart.flag" (list $sa "create" true) }}
{{- $name := include "chart.serviceAccountName" (list .root .comp .values) }}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  {{- include "chart.objectMeta" (dict "root" .root "kind" "ServiceAccount" "comp" .comp "name" $name "labels" $sa.labels "annotations" $sa.annotations) | nindent 2 }}
automountServiceAccountToken: {{ $sa.automount | default false }}
{{- end }}
{{- end -}}

{{/*
One container with the component's standard settings.
Params: root, values, name, image (defaults to values.image), command, args,
env, envFrom, ports, volumeMounts, probes (true to render values' probes),
resources (defaults to values.resources), securityContext (overrides values),
main (true by default: append the component's extraArgs/extraEnv/extraEnvFrom/
extraVolumeMounts and global.extraEnv/extraEnvFrom/extraVolumeMounts),
extraValues (a sidecar's own values block: its extraEnv, extraEnvFrom and
extraVolumeMounts are appended whatever main says), lifecycle (a lifecycle
block for a container that is not main; a main container takes
values.lifecycle, else global.lifecycle).
Global entries never replace the container's own: a global env var or mount
whose name or mountPath the container already has is skipped.
*/}}
{{- define "chart.std.container" -}}
{{- $v := .values -}}
{{- $img := default $v.image .image -}}
{{- $main := include "chart.flag" (list . "main" true) -}}
{{- $xv := .extraValues | default dict -}}
{{- $g := .root.Values.global -}}
name: {{ .name }}
image: {{ include "chart.image" (dict "root" .root "image" $img) | quote }}
imagePullPolicy: {{ include "chart.imagePullPolicy" $img }}
{{- with .command }}
command:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $args := default list .args -}}
{{- if $main -}}{{- $args = concat $args (default list $v.extraArgs) -}}{{- end -}}
{{- with $args }}
args:
  {{- tpl (toYaml .) $.root | nindent 2 }}
{{- end }}
{{- with .ports }}
ports:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- $env := default list .env -}}
{{- $own := default list $xv.extraEnv -}}
{{- if $main -}}{{- $own = concat (default list $v.extraEnv) $own -}}{{- end -}}
{{- if $main -}}{{- $env = concat $env (include "chart.globalExtras" (dict "global" $g.extraEnv "have" (concat $env $own) "key" "name") | fromJsonArray) -}}{{- end -}}
{{- $env = concat $env $own -}}
{{- with $env }}
env:
  {{- tpl (toYaml .) $.root | nindent 2 }}
{{- end }}
{{- $envFrom := default list .envFrom -}}
{{- if $main -}}{{- $envFrom = concat $envFrom (default list $g.extraEnvFrom) (default list $v.extraEnvFrom) -}}{{- end -}}
{{- $envFrom = concat $envFrom (default list $xv.extraEnvFrom) -}}
{{- with $envFrom }}
envFrom:
  {{- tpl (toYaml .) $.root | nindent 2 }}
{{- end }}
securityContext:
  {{- include "chart.containerSecurityContext" (dict "root" .root "values" (dict "securityContext" (default $v.securityContext .securityContext))) | nindent 2 }}
{{- $res := default $v.resources .resources -}}
{{- with $res }}
resources:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if .probes }}
{{- include "chart.probes" $v }}
{{- end }}
{{- $lc := .lifecycle -}}
{{- if and (not $lc) $main -}}{{- $lc = default $g.lifecycle $v.lifecycle -}}{{- end -}}
{{- with $lc }}
lifecycle:
  {{- tpl (toYaml .) $.root | nindent 2 }}
{{- end }}
{{- $mounts := default list .volumeMounts -}}
{{- $ownMounts := default list $xv.extraVolumeMounts -}}
{{- if $main -}}{{- $ownMounts = concat (default list $v.extraVolumeMounts) $ownMounts -}}{{- end -}}
{{- if $main -}}{{- $mounts = concat $mounts (include "chart.globalExtras" (dict "global" $g.extraVolumeMounts "have" (concat $mounts $ownMounts) "key" "mountPath") | fromJsonArray) -}}{{- end -}}
{{- $mounts = concat $mounts $ownMounts -}}
{{- with $mounts }}
volumeMounts:
  {{- tpl (toYaml .) $.root | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Global list entries a component does not already have, as a JSON list:
entries of global whose <key> (name, mountPath) is absent from have.
Usage: include "chart.globalExtras" (dict "global" $g.extraVolumes "have" $vols "key" "name")
*/}}
{{- define "chart.globalExtras" -}}
{{- $seen := list -}}
{{- range (default list .have) -}}{{- if kindIs "map" . -}}{{- $seen = append $seen (toString (index . $.key)) -}}{{- end -}}{{- end -}}
{{- $out := list -}}
{{- range (default list .global) -}}
{{- if not (and (kindIs "map" .) (has (toString (index . $.key)) $seen)) -}}{{- $out = append $out . -}}{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/*
Pod-level options with a global default: dnsPolicy, dnsConfig, hostAliases,
runtimeClassName, shareProcessNamespace, enableServiceLinks. The
component's value wins; a boolean left null (or absent) falls back to the
global one and renders nothing when both are null. Keys listed in skip are
left out (the caller sets them itself).
Usage: include "chart.std.podOptions" (dict "root" $ "values" .Values.app "skip" (list))
*/}}
{{- define "chart.std.podOptions" -}}
{{- $v := .values | default dict -}}
{{- $g := .root.Values.global -}}
{{- $skip := default list .skip -}}
{{- $out := dict -}}
{{- range $k := list "dnsPolicy" "runtimeClassName" "dnsConfig" "hostAliases" -}}
{{- with (default (index $g $k) (index $v $k)) -}}{{- $_ := set $out $k . -}}{{- end -}}
{{- end -}}
{{- range $k := list "shareProcessNamespace" "enableServiceLinks" -}}
{{- $b := index $g $k -}}
{{- if and (hasKey $v $k) (not (kindIs "invalid" (index $v $k))) -}}{{- $b = index $v $k -}}{{- end -}}
{{- if not (kindIs "invalid" $b) -}}{{- $_ := set $out $k $b -}}{{- end -}}
{{- end -}}
{{- range $k := $skip -}}{{- $_ := unset $out $k -}}{{- end -}}
{{- range $k := list "dnsPolicy" "dnsConfig" "hostAliases" "runtimeClassName" "shareProcessNamespace" "enableServiceLinks" -}}
{{- if hasKey $out $k }}
{{ $k }}:
{{- if has $k (list "dnsConfig" "hostAliases") }}
  {{- tpl (toYaml (index $out $k)) $.root | nindent 2 }}
{{- else }} {{ index $out $k }}
{{- end }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Pod template (metadata + spec).
Params: root, comp, values, containers (list), initContainers (list),
volumes (list), podAnnotations (dict, e.g. checksums), automount (bool,
overrides serviceAccount.automount for the pod), podSpec (dict merged into
the spec, e.g. restartPolicy), labels (extra pod labels).
*/}}
{{- define "chart.std.podTemplate" -}}
{{- $v := .values -}}
{{- $g := .root.Values.global -}}
{{- $sa := $v.serviceAccount | default dict -}}
{{- $automount := $sa.automount | default false -}}
{{- if hasKey . "automount" -}}{{- $automount = .automount -}}{{- end -}}
{{- $inits := concat (default list .initContainers) (default list $v.extraInitContainers) -}}
{{- $vols := concat (default list .volumes) (include "chart.globalExtras" (dict "global" $g.extraVolumes "have" (concat (default list .volumes) (default list $v.extraVolumes)) "key" "name") | fromJsonArray) (default list $v.extraVolumes) -}}
{{- $ann := mustMergeOverwrite (deepCopy (default dict .podAnnotations)) (deepCopy (default dict $g.podAnnotations)) (deepCopy (default dict $v.podAnnotations)) -}}
{{- with include "chart.extraObjects.checksum" (dict "root" .root "volumes" $vols "containers" (concat .containers (default list $v.extraContainers) $inits)) -}}
{{- $_ := set $ann "checksum/extra-objects" . -}}
{{- end -}}
{{- $podLabels := include "chart.omitKeys" (list (mustMergeOverwrite (deepCopy (default dict $g.podLabels)) (deepCopy (default dict $v.podLabels))) (include "chart.componentLabels" (list .root .comp) | fromYaml)) | fromJson -}}
metadata:
  labels:
    {{- include "chart.componentLabels" (list .root .comp) | nindent 4 }}
    {{- with .labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
    {{- with $podLabels }}
    {{- tpl (toYaml .) $.root | nindent 4 }}
    {{- end }}
  {{- with $ann }}
  annotations:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
spec:
  serviceAccountName: {{ include "chart.serviceAccountName" (list .root .comp $v) }}
  automountServiceAccountToken: {{ $automount }}
  {{- with include "chart.imagePullSecrets" (dict "root" .root "values" $v) }}
  {{- . | nindent 2 }}
  {{- end }}
  securityContext:
    {{- include "chart.podSecurityContext" (dict "root" .root "values" $v) | nindent 4 }}
  {{- with (default $g.priorityClassName $v.priorityClassName) }}
  priorityClassName: {{ . }}
  {{- end }}
  {{- with $v.terminationGracePeriodSeconds }}
  terminationGracePeriodSeconds: {{ . }}
  {{- end }}
  {{- with (default $g.nodeSelector $v.nodeSelector) }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with (default $g.tolerations $v.tolerations) }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with (default $g.affinity $v.affinity) }}
  affinity:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
  {{- with (default $g.topologySpreadConstraints $v.topologySpreadConstraints) }}
  topologySpreadConstraints:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
  {{- with include "chart.std.podOptions" (dict "root" .root "values" $v "skip" (keys (default dict .podSpec))) }}
  {{- . | trim | nindent 2 }}
  {{- end }}
  {{- with .podSpec }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
  {{- with $inits }}
  initContainers:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
  containers:
    {{- toYaml .containers | nindent 4 }}
    {{- with $v.extraContainers }}
    {{- tpl (toYaml .) $.root | nindent 4 }}
    {{- end }}
  {{- with $vols }}
  volumes:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
{{- end -}}

{{/*
Deployment or StatefulSet around chart.std.podTemplate.
Extra params: kind (Deployment|StatefulSet), serviceName and
volumeClaimTemplates (StatefulSet), replicas (overrides values.replicaCount).
*/}}
{{- define "chart.std.workload" -}}
{{- $v := .values -}}
{{- $kind := default "Deployment" .kind }}
{{- $name := default (include "chart.componentName" (list .root .comp)) .name }}
---
apiVersion: apps/v1
kind: {{ $kind }}
metadata:
  name: {{ $name }}
  namespace: {{ include "chart.namespace" .root }}
  labels:
    {{- include "chart.componentLabels" (list .root .comp) | nindent 4 }}
    {{- with include "chart.extraLabels" (dict "root" .root "labels" $v.labels "comp" .comp) }}
    {{- . | nindent 4 }}
    {{- end }}
  {{- $ann := mustMergeOverwrite (dict) (include "chart.commonAnnotations" .root | fromYaml) (deepCopy (default dict $v.annotations)) }}
  {{- $ann = mustMergeOverwrite $ann (include "chart.meta" (dict "root" .root "kind" $kind "comp" .comp "name" $name) | fromJson).annotations }}
  {{- with $ann }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- $auto := $v.autoscaling | default dict }}
  {{- if not $auto.enabled }}
  replicas: {{ default (default 1 $v.replicaCount) .replicas }}
  {{- end }}
  revisionHistoryLimit: {{ .root.Values.global.revisionHistoryLimit }}
  selector:
    matchLabels:
      {{- include "chart.selectorLabels" (list .root .comp) | nindent 6 }}
  {{- if eq $kind "StatefulSet" }}
  serviceName: {{ default $name .serviceName }}
  {{- with $v.updateStrategy }}
  updateStrategy:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .volumeClaimTemplates }}
  volumeClaimTemplates:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- else }}
  {{- with $v.strategy }}
  strategy:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- end }}
  template:
    {{- include "chart.std.podTemplate" . | nindent 4 }}
{{- end -}}

{{/*
Service. Params: root, comp, values, ports (list), headless (bool),
name (overrides the component name), selectorComp (select another
component's pods), labels (extra labels the template sets).
*/}}
{{- define "chart.std.service" -}}
{{- $svc := .values.service | default dict }}
{{- $name := default (include "chart.componentName" (list .root .comp)) .name }}
---
apiVersion: v1
kind: Service
metadata:
  {{- include "chart.objectMeta" (dict "root" .root "kind" "Service" "comp" .comp "name" $name "labels" (mustMergeOverwrite (deepCopy (default dict $svc.labels)) (default dict .labels)) "annotations" $svc.annotations) | nindent 2 }}
spec:
  {{- if .headless }}
  clusterIP: None
  publishNotReadyAddresses: true
  {{- else }}
  type: {{ default "ClusterIP" $svc.type }}
  {{- end }}
  selector:
    {{- include "chart.selectorLabels" (list .root (default .comp .selectorComp)) | nindent 4 }}
  ports:
    {{- toYaml .ports | nindent 4 }}
{{- end -}}

{{/* PodDisruptionBudget when values.pdb.enabled. Params: root, comp, values. */}}
{{- define "chart.std.pdb" -}}
{{- $pdb := .values.pdb | default dict -}}
{{- if $pdb.enabled }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  {{- include "chart.objectMeta" (dict "root" .root "kind" "PodDisruptionBudget" "comp" .comp "name" (default (include "chart.componentName" (list .root .comp)) .name) "labels" $pdb.labels "annotations" $pdb.annotations) | nindent 2 }}
spec:
  {{- if $pdb.maxUnavailable }}
  maxUnavailable: {{ $pdb.maxUnavailable }}
  {{- else }}
  minAvailable: {{ default 1 $pdb.minAvailable }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "chart.selectorLabels" (list .root .comp) | nindent 6 }}
{{- end }}
{{- end -}}

{{/*
HorizontalPodAutoscaler when values.autoscaling.enabled. minReplicas below 2
fails the render: with one replica a rollout or a node drain takes the
component down, and a PDB would block the drain. Params: root, comp, values,
kind (scale target kind, default Deployment), name (object and scale target
name, default the component name), extraMetrics (more metrics entries, such
as a Pods metric from an adapter).
*/}}
{{- define "chart.std.hpa" -}}
{{- $a := .values.autoscaling | default dict -}}
{{- if $a.enabled }}
{{- $min := int (ternary $a.minReplicas 2 (hasKey $a "minReplicas")) -}}
{{- if lt $min 2 -}}
{{- fail (printf "%s.autoscaling.minReplicas is %d: an HPA needs at least 2 (one replica is down on every rollout and node drain)" .comp $min) -}}
{{- end }}
{{- if lt (int (default 3 $a.maxReplicas)) $min -}}
{{- fail (printf "%s.autoscaling.maxReplicas is below minReplicas" .comp) -}}
{{- end }}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  {{- $name := default (include "chart.componentName" (list .root .comp)) .name }}
  {{- include "chart.objectMeta" (dict "root" .root "kind" "HorizontalPodAutoscaler" "comp" .comp "name" $name "labels" $a.labels "annotations" $a.annotations) | nindent 2 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: {{ default "Deployment" .kind }}
    name: {{ $name }}
  minReplicas: {{ $min }}
  maxReplicas: {{ default 3 $a.maxReplicas }}
  {{- if not (or $a.targetCPUUtilizationPercentage $a.targetMemoryUtilizationPercentage .extraMetrics) }}
  {{- fail (printf "%s.autoscaling needs targetCPUUtilizationPercentage, targetMemoryUtilizationPercentage or another metric" .comp) }}
  {{- end }}
  metrics:
    {{- with $a.targetCPUUtilizationPercentage }}
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ . }}
    {{- end }}
    {{- with $a.targetMemoryUtilizationPercentage }}
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: {{ . }}
    {{- end }}
    {{- with .extraMetrics }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with $a.behavior }}
  behavior:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}
{{- end -}}

{{/*
NetworkPolicy of one component. Params: root, comp, ingress (list of rules),
egress (list of rules), extra (the component's networkPolicy values: its
extraIngress / extraEgress rules are appended, tpl-rendered; extraFrom peers
are admitted on every port the chart's own ingress rules open; labels /
annotations go on the policy). Rendered only when networkPolicy.enabled.
A nil list leaves that direction out of policyTypes (not restricted by this
policy, so extra rules for it are ignored); an empty list denies it.
*/}}
{{- define "chart.std.networkPolicy" -}}
{{- if .root.Values.networkPolicy.enabled }}
{{- $x := .extra | default dict -}}
{{- $ingress := .ingress -}}
{{- $egress := .egress -}}
{{- $ports := list -}}
{{- $allPorts := false -}}
{{- range (default list .ingress) -}}
{{- if .ports -}}{{- range .ports -}}{{- if not (has . $ports) -}}{{- $ports = append $ports . -}}{{- end -}}{{- end -}}{{- else -}}{{- $allPorts = true -}}{{- end -}}
{{- end -}}
{{- if and (kindIs "slice" $ingress) $x.extraFrom .ingress -}}
{{- $rule := dict "from" (tpl (toYaml $x.extraFrom) .root | fromYamlArray) -}}
{{- if and $ports (not $allPorts) -}}{{- $_ := set $rule "ports" $ports -}}{{- end -}}
{{- $ingress = append $ingress $rule -}}
{{- end -}}
{{- if and (kindIs "slice" $ingress) $x.extraIngress -}}{{- $ingress = concat $ingress (tpl (toYaml $x.extraIngress) .root | fromYamlArray) -}}{{- end -}}
{{- if and (kindIs "slice" $egress) $x.extraEgress -}}{{- $egress = concat $egress (tpl (toYaml $x.extraEgress) .root | fromYamlArray) -}}{{- end -}}
{{- $name := default (include "chart.componentName" (list .root .comp)) .name }}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  {{- include "chart.objectMeta" (dict "root" .root "kind" "NetworkPolicy" "comp" .comp "name" $name "labels" $x.labels "annotations" $x.annotations) | nindent 2 }}
spec:
  podSelector:
    matchLabels:
      {{- include "chart.selectorLabels" (list .root .comp) | nindent 6 }}
  policyTypes:
    {{- if kindIs "slice" $ingress }}
    - Ingress
    {{- end }}
    {{- if kindIs "slice" $egress }}
    - Egress
    {{- end }}
  {{- if kindIs "slice" $ingress }}
  ingress:
    {{- if $ingress }}
    {{- toYaml $ingress | nindent 4 }}
    {{- else }} []
    {{- end }}
  {{- end }}
  {{- if kindIs "slice" $egress }}
  egress:
    {{- if $egress }}
    {{- toYaml $egress | nindent 4 }}
    {{- else }} []
    {{- end }}
  {{- end }}
{{- end }}
{{- end -}}

{{/* Peer selecting one component's pods in the release namespace. Usage: (list $ "kv") */}}
{{- define "chart.netpolPeer" -}}
podSelector:
  matchLabels:
    {{- include "chart.selectorLabels" . | nindent 4 }}
{{- end -}}

{{/*
DNS egress rule (networkPolicy.dns), as a list item body. Every policy that
restricts egress includes it.
Usage: (include "chart.netpolDNSEgress" $ | fromYaml)
*/}}
{{- define "chart.netpolDNSEgress" -}}
to:
  - {{ toYaml .Values.networkPolicy.dns | indent 4 | trim }}
ports:
  - protocol: UDP
    port: 53
  - protocol: TCP
    port: 53
{{- end -}}

{{/* Peer selecting the helm test pods. */}}
{{- define "chart.netpolTestPeer" -}}
podSelector:
  matchLabels:
    {{ include "chart.labelDomain" . }}/helm-test: "true"
{{- end -}}

{{/*
The whole "standard component": ServiceAccount, Deployment, Service, PDB,
HPA, in one call. Params as chart.std.workload plus ports (Service ports; no
Service when empty).
*/}}
{{- define "chart.std.component" -}}
{{- include "chart.std.serviceAccount" . }}
{{- include "chart.std.workload" . }}
{{- if .ports }}
{{- include "chart.std.service" . }}
{{- end }}
{{- include "chart.std.pdb" . }}
{{- include "chart.std.hpa" . }}
{{- end -}}
