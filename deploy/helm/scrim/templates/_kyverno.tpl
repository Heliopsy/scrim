{{/* SPDX-License-Identifier: AGPL-3.0-only */}}

{{/*
The containers and volumes the Kyverno MutatingPolicy of sidecar mode adds to
a labelled pod (templates/kyverno.yaml). Written as YAML here and handed to
the policy as JSON.
*/}}
{{- define "scrim.sidecarInitContainers" -}}
{{- if .Values.sidecar.egressGuard.enabled }}
- name: scrim-egress-guard
  image: {{ .Values.sidecar.egressGuard.image }}
  imagePullPolicy: {{ .Values.sidecar.egressGuard.pullPolicy }}
  command: [sh, -c]
  args:
    - |
      {{- include "scrim.egressGuardScript" . | nindent 6 }}
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
      add: [NET_ADMIN]
    seccompProfile:
      type: RuntimeDefault
  resources:
    requests:
      cpu: 10m
      memory: 16Mi
    limits:
      memory: 32Mi
{{- end }}
- name: scrim
  image: {{ include "scrim.image" . }}
  imagePullPolicy: {{ include "chart.imagePullPolicy" .Values.image }}
  # A native sidecar: it starts, and passes its startup probe, before the agent.
  restartPolicy: Always
  args: [proxy]
  env:
    - name: SCRIM_CONFIG
      value: /etc/scrim/config/config.yaml:/etc/scrim/config/chart.yaml
    - name: XDG_RUNTIME_DIR
      value: /run/scrim
  ports:
    - name: scrim-health
      containerPort: {{ .Values.metrics.port }}
      protocol: TCP
  startupProbe:
    httpGet:
      path: /readyz
      port: {{ .Values.metrics.port }}
    periodSeconds: 1
    failureThreshold: 120
  readinessProbe:
    httpGet:
      path: /readyz
      port: {{ .Values.metrics.port }}
    periodSeconds: 5
  livenessProbe:
    httpGet:
      path: /livez
      port: {{ .Values.metrics.port }}
    periodSeconds: 10
  resources:
    {{- toYaml .Values.sidecar.resources | nindent 4 }}
  securityContext:
    {{- toYaml .Values.sidecar.securityContext | nindent 4 }}
  volumeMounts:
    - name: scrim-sidecar-config
      mountPath: /etc/scrim/config
      readOnly: true
    - name: scrim-sidecar-ca
      mountPath: /etc/scrim/ca
      readOnly: true
    - name: scrim-sidecar-keys
      mountPath: /etc/scrim/placeholder
      readOnly: true
    {{- if .Values.upstreamCA.configMap }}
    - name: scrim-upstream-ca
      mountPath: /etc/scrim/upstream-ca
      readOnly: true
    {{- end }}
    - name: scrim-state
      mountPath: /var/lib/scrim
    - name: scrim-run
      mountPath: /run/scrim
    - name: scrim-tmp
      mountPath: /tmp
    {{- if .Values.identity.kubernetes.enabled }}
    # The pod's own API token, for TokenReview; only this container sees it.
    - name: scrim-kube-api
      mountPath: {{ include "scrim.sidecarAPIPath" . }}
      readOnly: true
    {{- end }}
    {{- if .Values.storeAuth.serviceAccountToken.enabled }}
    - name: scrim-store-token
      mountPath: {{ dir .Values.storeAuth.serviceAccountToken.path }}
      readOnly: true
    {{- end }}
    {{- if and .Values.metrics.enabled (not .Values.metrics.allowUnauthenticatedRemote) }}
    - name: scrim-metrics-token
      mountPath: /run/secrets/scrim/metrics
      readOnly: true
    {{- end }}
    {{- range .Values.sidecar.secretMounts }}
    - name: scrim-secret-{{ .name }}
      mountPath: /run/secrets/scrim/{{ .name }}
      readOnly: true
    {{- end }}
{{- end -}}

{{- define "scrim.sidecarVolumes" -}}
# Mounted only into the scrim container. The agent pod has no fsGroup to rely
# on, so the files are world-readable inside that one mount.
- name: scrim-sidecar-config
  configMap:
    name: {{ include "scrim.fullname" . }}-sidecar-config
- name: scrim-sidecar-ca
  secret:
    secretName: {{ .Values.sidecar.caSecretName }}
    defaultMode: 0444
    items:
      - key: tls.crt
        path: tls.crt
      - key: tls.key
        path: tls.key
- name: scrim-sidecar-keys
  secret:
    secretName: {{ .Values.sidecar.keysSecretName }}
    defaultMode: 0444
{{- if .Values.upstreamCA.configMap }}
- name: scrim-upstream-ca
  configMap:
    name: {{ .Values.upstreamCA.configMap }}
{{- end }}
{{- if .Values.identity.kubernetes.enabled }}
- name: scrim-kube-api
  projected:
    defaultMode: 0444
    sources:
      - serviceAccountToken:
          expirationSeconds: 3600
          path: token
      - configMap:
          name: kube-root-ca.crt
          items:
            - key: ca.crt
              path: ca.crt
{{- end }}
{{- if .Values.storeAuth.serviceAccountToken.enabled }}
- name: scrim-store-token
  projected:
    defaultMode: 0444
    sources:
      - serviceAccountToken:
          audience: {{ .Values.storeAuth.serviceAccountToken.audience }}
          expirationSeconds: {{ .Values.storeAuth.serviceAccountToken.expirationSeconds }}
          path: {{ base .Values.storeAuth.serviceAccountToken.path }}
{{- end }}
{{- if and .Values.metrics.enabled (not .Values.metrics.allowUnauthenticatedRemote) }}
# secrets.existing.metrics: must exist in every agent namespace.
- name: scrim-metrics-token
  secret:
    secretName: {{ include "chart.secretName" (list . "metrics") }}
    defaultMode: 0444
    items:
      - key: {{ include "chart.secretKey" (list . "metrics" "token") }}
        path: {{ include "chart.secretKey" (list . "metrics" "token") }}
{{- end }}
- name: scrim-state
  emptyDir: {}
- name: scrim-run
  emptyDir:
    medium: Memory
    sizeLimit: 64Mi
- name: scrim-tmp
  emptyDir:
    sizeLimit: 64Mi
{{- range .Values.sidecar.secretMounts }}
- name: scrim-secret-{{ .name }}
  secret:
    secretName: {{ .secretName }}
    defaultMode: 0444
    {{- with .items }}
    items:
      {{- toYaml . | nindent 6 }}
    {{- end }}
{{- end }}
{{- end -}}

{{/*
The spec of an injection MutatingPolicy. dict: root, mode (the label value),
env, volumes and initContainers (lists). Every container of the pod gets env
and the agent mounts; the volumes are added to the pod; initContainers go in
front of the pod's own, so the egress guard and the in-pod scrim run before
any init container of the agent.
*/}}
{{- define "scrim.kyverno.injectSpec" -}}
{{- $root := .root -}}
failurePolicy: {{ $root.Values.kyverno.failurePolicy }}
matchConstraints:
  resourceRules:
    - apiGroups: [""]
      apiVersions: [v1]
      operations: [CREATE]
      resources: [pods]
  objectSelector:
    matchLabels:
      {{ $root.Values.agents.label }}: {{ .mode }}
variables:
  - name: env
    expression: |
      json.unmarshal(r'''
      {{- toPrettyJson .env | nindent 6 }}
      ''')
  - name: envNames
    expression: variables.env.map(e, e.name)
  - name: mounts
    expression: |
      json.unmarshal(r'''
      {{- include "scrim.agentMounts" $root | fromYamlArray | toPrettyJson | nindent 6 }}
      ''')
  - name: mountPaths
    expression: variables.mounts.map(m, m.mountPath)
  - name: volumes
    expression: |
      json.unmarshal(r'''
      {{- toPrettyJson .volumes | nindent 6 }}
      ''')
  - name: volumeNames
    expression: variables.volumes.map(v, v.name)
  {{- with .initContainers }}
  # The scrim container is a native sidecar (restartPolicy Always): it starts, and passes its
  # startup probe, before the agent.
  - name: initContainers
    expression: |
      json.unmarshal(r'''
      {{- toPrettyJson . | nindent 6 }}
      ''')
  - name: initContainerNames
    expression: variables.initContainers.map(c, c.name)
  {{- end }}
mutations:
  - patchType: JSONPatch
    jsonPatch:
      expression: >-
        object.spec.containers.map(c, JSONPatch{
          op: "add",
          path: "/spec/containers/" + string(object.spec.containers.indexOf(c)) + "/env",
          value: c.?env.orValue([]).filter(e, !(e.name in variables.envNames)) + variables.env
        }) +
        object.spec.containers.map(c, JSONPatch{
          op: "add",
          path: "/spec/containers/" + string(object.spec.containers.indexOf(c)) + "/volumeMounts",
          value: c.?volumeMounts.orValue([]).filter(m, !(m.mountPath in variables.mountPaths)) + variables.mounts
        }) +
        {{- if .initContainers }}
        [JSONPatch{
          op: "add",
          path: "/spec/initContainers",
          value: variables.initContainers +
            object.spec.?initContainers.orValue([]).filter(c, !(c.name in variables.initContainerNames))
        }] +
        {{- end }}
        [JSONPatch{
          op: "add",
          path: "/spec/volumes",
          value: object.spec.?volumes.orValue([]).filter(v, !(v.name in variables.volumeNames)) + variables.volumes
        }]
{{- end -}}
