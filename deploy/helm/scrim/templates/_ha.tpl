{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{/*
=============================================================================
 High availability preset (global.ha)
=============================================================================
With global.ha.enabled, a component that can scale gets, unless it sets
them itself:

  replicaCount   raised to global.ha.replicas (a higher one wins; ignored
                 under autoscaling, whose minReplicas is already >= 2)
  pdb            enabled with minAvailable 1
  affinity       preferred pod anti-affinity on kubernetes.io/hostname, added
                 to global.affinity (its nodeAffinity is kept) unless that has
                 a podAntiAffinity of its own
  topologySpreadConstraints
                 one zone spread (maxSkew 1, ScheduleAnyway) with
                 global.ha.zoneSpread, unless global sets its own

A component's template merges chart.ha.delta over its values block. With
global.ha off, or the component in global.ha.exclude, the delta is {} and the
render does not change. Ported from toc-helm-chart-template. For scrim the
component is central scrim ("proxy"); more than one replica needs
postgres.enabled, which validate.yaml enforces on the merged values.
*/}}

{{/* "true" when global.ha applies to a component. Usage: (list $ "app") */}}
{{- define "chart.ha.raises" -}}
{{- $ha := (index . 0).Values.global.ha | default dict -}}
{{- if and $ha.enabled (not (has (index . 1) (default list $ha.exclude))) -}}true{{- end -}}
{{- end -}}

{{/*
What the preset adds to a component's values, as JSON.
Usage: mustMergeOverwrite (deepCopy $v) (include "chart.ha.delta" (dict "root" $ "comp" "app" "values" $v) | fromJson)
*/}}
{{- define "chart.ha.delta" -}}
{{- $root := .root -}}
{{- $v := .values | default dict -}}
{{- $out := dict -}}
{{- if include "chart.ha.raises" (list $root .comp) -}}
  {{- $ha := $root.Values.global.ha -}}
  {{- $g := $root.Values.global -}}
  {{- $auto := $v.autoscaling | default dict -}}
  {{- if and (not $auto.enabled) (lt (int (default 1 $v.replicaCount)) (int $ha.replicas)) -}}
    {{- $_ := set $out "replicaCount" (int $ha.replicas) -}}
  {{- end -}}
  {{- if not (dig "enabled" false (default dict $v.pdb)) -}}
    {{- $_ := set $out "pdb" (dict "enabled" true "minAvailable" 1) -}}
  {{- end -}}
  {{- $sel := dict "matchLabels" (include "chart.selectorLabels" (list $root .comp) | fromYaml) -}}
  {{- $gAff := default dict $g.affinity -}}
  {{- if and (not $v.affinity) (not $gAff.podAntiAffinity) -}}
    {{- $anti := dict "preferredDuringSchedulingIgnoredDuringExecution" (list (dict "weight" 100 "podAffinityTerm" (dict "labelSelector" $sel "topologyKey" "kubernetes.io/hostname"))) -}}
    {{- $_ := set $out "affinity" (mustMergeOverwrite (deepCopy $gAff) (dict "podAntiAffinity" $anti)) -}}
  {{- end -}}
  {{- if and $ha.zoneSpread (not $v.topologySpreadConstraints) (not $g.topologySpreadConstraints) -}}
    {{- $_ := set $out "topologySpreadConstraints" (list (dict "maxSkew" 1 "topologyKey" "topology.kubernetes.io/zone" "whenUnsatisfiable" "ScheduleAnyway" "labelSelector" $sel)) -}}
  {{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}
