#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Assertions on the render of ci/all-features-values.yaml: every hook and
toggle reaches the object it is meant for. Usage: assert-all-features.py RENDER.yaml"""
import sys

import yaml

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
fails = []


def one(kind, name=None):
    hits = [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    if len(hits) != 1:
        fails.append(f"want one {kind} {name or ''}, got {len(hits)}")
        return {}
    return hits[0]


def want(cond, what):
    if not cond:
        fails.append(what)


dep = one("Deployment", "ci-scrim")
pod = dep.get("spec", {}).get("template", {})
spec = pod.get("spec", {})
main = next((c for c in spec.get("containers", []) if c["name"] == "scrim"), {})
env = {e["name"]: e.get("value") for e in main.get("env", [])}
want(main.get("image", "").startswith("registry.example.com/heliopsy/scrim:"), "global.imageRegistry and image.digest on the scrim image")
want(main.get("image", "").endswith("@sha256:" + "0" * 64), "image.digest pins the image")
want(main.get("args") == ["proxy", "--log-level=debug"], "central.extraArgs after proxy")
want(env.get("TZ") == "Europe/Sofia", "central.extraEnv wins over global.extraEnv")
want({"configMapRef": {"name": "scrim-env"}} in main.get("envFrom", []), "central.extraEnvFrom")
want(any(m["mountPath"] == "/shared" for m in main.get("volumeMounts", [])), "global.extraVolumeMounts")
want(any(m["mountPath"] == "/etc/notes" for m in main.get("volumeMounts", [])), "central.extraVolumeMounts")
want(main.get("lifecycle") == {"preStop": {"sleep": {"seconds": 5}}}, "central.lifecycle")
want([c["name"] for c in spec.get("containers", [])] == ["scrim", "logs"], "central.extraContainers")
want([c["name"] for c in spec.get("initContainers", [])] == ["wait"], "central.extraInitContainers")
want(spec.get("runtimeClassName") == "gvisor", "central.runtimeClassName")
want(spec.get("hostAliases"), "central.hostAliases")
want(spec.get("dnsConfig"), "global.dnsConfig")
want(spec.get("priorityClassName") == "scrim-critical", "global.priorityClassName")
want(spec.get("enableServiceLinks") is False, "central.enableServiceLinks stays false")
want({"name": "mirror-pull"} in spec.get("imagePullSecrets", []), "global.imagePullSecrets")
want(pod.get("metadata", {}).get("labels", {}).get("mesh") == "off", "global.podLabels")
want("checksum/extra-objects" in pod.get("metadata", {}).get("annotations", {}), "extraConfigMaps checksum on the pod")
want((spec.get("affinity") or {}).get("podAntiAffinity"), "global.ha anti-affinity")
want(spec.get("topologySpreadConstraints"), "global.ha zone spread")
want(any(v["name"] == "store-token" for v in spec.get("volumes", [])), "storeAuth token volume")

hpa = one("HorizontalPodAutoscaler", "ci-scrim")
metrics = hpa.get("spec", {}).get("metrics", [])
want(any(m.get("type") == "Pods" and m["pods"]["metric"]["name"] == "scrim_dataplane_connections_active" for m in metrics),
     "HPA connections metric")
want(hpa.get("spec", {}).get("minReplicas") == 3, "HPA minReplicas")
want(one("PodDisruptionBudget", "ci-scrim").get("spec", {}).get("minAvailable") == 2, "PDB minAvailable")

np = one("NetworkPolicy", "ci-scrim")
want(any(any(p.get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name") == "ci"
             for p in r.get("from", [])) for r in np.get("spec", {}).get("ingress", [])), "central.networkPolicy.extraFrom")
want(any(any("ipBlock" in p for p in r.get("to", [])) for r in np.get("spec", {}).get("egress", [])), "central.networkPolicy.extraEgress")

es = one("ExternalSecret", "ci-scrim-metrics")
want(es.get("spec", {}).get("secretStoreRef", {}).get("name") == "vault", "ExternalSecret for the metrics slot")
want(not [d for d in docs if d["kind"] == "Secret" and d["metadata"]["name"] in ("ci-scrim-admin", "ci-scrim-postgres")],
     "existing slots render no Secret")
cm = one("ConfigMap", "ci-scrim-notes")
want(cm.get("data", {}).get("README") == "release ci", "extraConfigMaps data is tpl-rendered")
want(cm.get("metadata", {}).get("annotations", {}).get("reflector.v1.k8s.emberstack.com/reflection-allowed") == "true",
     "global.replication on chart ConfigMaps")
one("ConfigMap", "ci-extra")
svc = one("Service", "ci-scrim")
want(svc.get("metadata", {}).get("annotations", {}).get("example.com/expose") == "false", "objectMetadata on the Service")
want(svc.get("metadata", {}).get("labels", {}).get("team") == "platform", "commonLabels")
for kind in ("ClusterPolicy", "ServiceMonitor", "PrometheusRule", "ClusterRole", "ClusterRoleBinding"):
    want([d for d in docs if d["kind"] == kind], f"{kind} rendered")
cfg = yaml.safe_load(one("ConfigMap", "ci-scrim-config").get("data", {}).get("chart.yaml", "{}"))
want(cfg["deployment"]["replicas"] == 8, "deployment.replicas follows the HPA maximum")
want(cfg["state"]["backend"] == "postgres" and cfg["events"]["backend"] == "postgres", "postgres state and events")
want(cfg["identity"]["kubernetes"]["agents"] == {"reviewer": "sa:agents/reviewer"}, "identity.kubernetes.agents")
want(cfg["metrics"]["auth"]["token"].startswith("file:/run/secrets/scrim/metrics/"), "metrics.auth.token")

for f in fails:
    print(f"FAIL: all-features: {f}", file=sys.stderr)
print(f"all-features: {len(fails)} failed assertion(s)")
sys.exit(1 if fails else 0)
