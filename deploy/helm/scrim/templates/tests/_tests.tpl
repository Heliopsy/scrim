{{- /* SPDX-License-Identifier: AGPL-3.0-only */ -}}
{{/*
One helm test pod that runs a curl check until it passes (ported from
toc-helm-chart-template). Params: root, name, check (a shell command that
exits 0 when the check passes), what (shown in the result).
*/}}
{{- define "chart.test.pod" -}}
{{- $t := .root.Values.tests }}
{{- $g := .root.Values.global }}
{{- $name := include "chart.componentName" (list .root (printf "test-%s" .name)) }}
{{- $domain := include "chart.labelDomain" .root }}
---
apiVersion: v1
kind: Pod
metadata:
  name: {{ $name }}
  namespace: {{ include "chart.namespace" .root }}
  labels:
    {{- include "chart.componentLabels" (list .root "test") | nindent 4 }}
    {{ $domain }}/helm-test: "true"
    {{- with mustMergeOverwrite (deepCopy (default dict $g.podLabels)) (deepCopy (default dict $t.podLabels)) }}
    {{- with include "chart.omitKeys" (list . (include "chart.componentLabels" (list $.root "test") | fromYaml)) | fromJson }}
    {{- tpl (toYaml (omit . (printf "%s/helm-test" $domain))) $.root | nindent 4 }}
    {{- end }}
    {{- end }}
  annotations:
    helm.sh/hook: test
    helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
    {{- with omit (mustMergeOverwrite (include "chart.commonAnnotations" .root | fromYaml) (deepCopy (default dict $g.podAnnotations)) (deepCopy (default dict $t.podAnnotations))) "helm.sh/hook" "helm.sh/hook-delete-policy" }}
    {{- tpl (toYaml .) $.root | nindent 4 }}
    {{- end }}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  {{- with include "chart.imagePullSecrets" (dict "root" .root "values" $t) }}
  {{- . | nindent 2 }}
  {{- end }}
  securityContext:
    {{- include "chart.podSecurityContext" (dict "root" .root "values" (dict "podSecurityContext" (mustMergeOverwrite (dict "runAsUser" 100 "runAsGroup" 101) (deepCopy (default dict $t.podSecurityContext))))) | nindent 4 }}
  {{- with (default $g.priorityClassName $t.priorityClassName) }}
  priorityClassName: {{ . }}
  {{- end }}
  {{- with (default $g.nodeSelector $t.nodeSelector) }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with (default $g.tolerations $t.tolerations) }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with (default $g.affinity $t.affinity) }}
  affinity:
    {{- tpl (toYaml .) $.root | nindent 4 }}
  {{- end }}
  {{- with include "chart.std.podOptions" (dict "root" .root "values" $t) }}
  {{- . | trim | nindent 2 }}
  {{- end }}
  containers:
    - name: curl
      image: {{ include "chart.image" (dict "root" .root "image" $t.image) | quote }}
      imagePullPolicy: {{ include "chart.imagePullPolicy" $t.image }}
      command: ["sh", "-c"]
      args:
        - |
          set -eu
          for i in $(seq 1 {{ $t.retries }}); do
            if {{ .check }}; then
              echo "ok {{ .what }}"; exit 0
            fi
            sleep 5
          done
          echo "{{ .what }}: no answer"; exit 1
      securityContext:
        {{- include "chart.containerSecurityContext" (dict "root" .root "values" (dict "securityContext" $t.securityContext)) | nindent 8 }}
      resources:
        {{- toYaml $t.resources | nindent 8 }}
      {{- with (default $g.lifecycle $t.lifecycle) }}
      lifecycle:
        {{- tpl (toYaml .) $.root | nindent 8 }}
      {{- end }}
{{- end -}}
