#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Assertions on the render of ci/ha-values.yaml: global.ha gives central scrim
two replicas, a PDB that keeps one, anti-affinity and a zone spread, and
scrim is told it runs two replicas on PostgreSQL. Usage: assert-ha.py RENDER.yaml"""
import sys

import yaml

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
fails = []
dep = by.get(("Deployment", "ci-scrim"), {})
spec = dep.get("spec", {})
pod = spec.get("template", {}).get("spec", {})
if spec.get("replicas") != 2:
    fails.append(f"replicas {spec.get('replicas')}, want 2")
anti = (pod.get("affinity") or {}).get("podAntiAffinity", {}).get("preferredDuringSchedulingIgnoredDuringExecution", [])
if not anti or anti[0]["podAffinityTerm"]["topologyKey"] != "kubernetes.io/hostname":
    fails.append("no preferred anti-affinity on kubernetes.io/hostname")
tsc = pod.get("topologySpreadConstraints") or []
if not tsc or tsc[0]["topologyKey"] != "topology.kubernetes.io/zone" or tsc[0]["whenUnsatisfiable"] != "ScheduleAnyway":
    fails.append("no ScheduleAnyway zone spread")
pdb = by.get(("PodDisruptionBudget", "ci-scrim"), {}).get("spec", {})
if pdb.get("maxUnavailable") != 1 and pdb.get("minAvailable") != 1:
    fails.append(f"PDB {pdb}, want one replica kept")
cfg = yaml.safe_load(by.get(("ConfigMap", "ci-scrim-config"), {}).get("data", {}).get("chart.yaml", "{}"))
if cfg.get("deployment", {}).get("replicas") != 2 or cfg.get("events", {}).get("backend") != "postgres":
    fails.append("scrim's configuration does not say 2 replicas on postgres events")
for f in fails:
    print(f"FAIL: ha: {f}", file=sys.stderr)
print(f"ha: {len(fails)} failed assertion(s)")
sys.exit(1 if fails else 0)
