#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate values.schema.json from values.yaml (ported from toc-helm-chart-template).

Types come from the defaults, descriptions from the helm-docs "# --" comments,
and ci/schema-overrides.yaml adds what a default cannot say
(enums, free-form maps, alternative types). One source, two outputs: the
README (helm-docs) and the schema read the same comments.

Objects are closed (additionalProperties: false) when their default has keys,
so a misspelt key fails `helm lint` instead of being silently ignored. Objects
whose default is empty, and Kubernetes pass-through blocks listed in FREE_FORM,
stay open.

Every value must be described: a leaf needs its own "# --" comment unless an
ancestor below the top level has one (helm-docs then documents the block as a
whole). A description must not contain " --": helm-docs reads that as its
"key -- description" form and silently drops the row from the README.

Two files: docs/helm-values.schema.json keeps the descriptions (editors,
review), deploy/helm/scrim/values.schema.json is the same schema without
descriptions and whitespace. Helm stores the packaged schema in every release record (a Secret
capped at 1 MiB), so the chart ships the compact one.

Usage: deploy/helm/scrim/ci/gen-schema.py [--check]
"""
import json
import re
import sys
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent.parent
VALUES = CHART / "values.yaml"
OVERRIDES = CHART / "ci" / "schema-overrides.yaml"
SCHEMA = CHART / "values.schema.json"
ROOT = CHART.parents[2]
DOC_SCHEMA = ROOT / "docs" / "helm-values.schema.json"

# Keys whose value is a Kubernetes object (or part of one) passed through as is.
FREE_FORM = {
    "resources", "securityContext", "podSecurityContext", "containerSecurityContext",
    "strategy", "updateStrategy", "affinity", "nodeSelector", "startupProbe",
    "livenessProbe", "readinessProbe", "annotations", "podAnnotations", "labels",
    "podLabels", "commonLabels", "commonAnnotations", "ingressController", "dns",
    "secretStoreRef", "httpGet", "tcpSocket", "exec", "values", "matchLabels",
    "namespaceSelector", "podSelector", "seccompProfile", "capabilities",
    "internetEgress", "data", "existing", "keys", "secretLabels", "secretAnnotations",
    "configMapLabels", "configMapAnnotations", "objectMetadata",
    "extraConfigMaps", "extraSecrets", "extraSelectorLabels", "disabled", "alertLabels",
    "lifecycle", "dnsConfig", "config", "policyRules", "behavior", "prometheus",
    "selector",
}


# Lists of Kubernetes objects passed through as is (items must be objects).
OBJECT_LISTS = {
    "extraVolumes", "extraVolumeMounts", "extraEnv", "extraEnvFrom", "extraContainers",
    "extraInitContainers", "tolerations", "topologySpreadConstraints",
    "extraIngress", "extraEgress", "extraFrom", "metricsScrapers", "egress",
    "relabelings", "metricRelabelings", "additionalRules", "hosts", "tls",
    "hostAliases", "secretMounts", "scrimEgress", "sidecarEgress", "apiServerEgress",
    "adminFrom", "groups", "extraObjects",
}


def descriptions(text):
    """Map dotted key path -> description from '# --' comments."""
    out = {}
    stack = []  # (indent, key)
    pending = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "# --" or stripped.startswith("# -- "):
            pending = stripped[4:].strip()
            continue
        if stripped.startswith("#") and pending is not None:
            more = stripped[1:].strip()
            if more.startswith("@default"):
                continue
            pending = (pending + " " + more).strip()
            continue
        m = re.match(r"^(\s*)([A-Za-z0-9_.\-]+|\"[^\"]+\"):(\s|$)", line)
        if m is None or stripped.startswith("-"):
            if stripped and not stripped.startswith("#"):
                pending = None
            continue
        indent = len(m.group(1))
        key = m.group(2).strip('"')
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        if pending is not None:
            out[".".join(k for _, k in stack)] = pending
            pending = None
    return out


def type_of(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return None


def build(value, path, descs, free=False):
    node = {}
    t = type_of(value)
    if t:
        node["type"] = t
    d = descs.get(path)
    if d:
        node["description"] = d
    if isinstance(value, dict):
        name = path.rsplit(".", 1)[-1]
        open_map = free or name in FREE_FORM or not value
        if value:
            node["properties"] = {
                k: build(v, f"{path}.{k}" if path else k, descs, free=open_map and name in FREE_FORM)
                for k, v in value.items()
            }
        node["additionalProperties"] = bool(open_map)
    if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
        node["items"] = {"type": "object"}
    elif isinstance(value, list) and not value and path.rsplit(".", 1)[-1] in OBJECT_LISTS:
        node["items"] = {"type": "object"}
    if value is None:
        node.pop("type", None)
    return node


def merge(dst, src):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = v


def apply_overrides(schema, overrides):
    for path, frag in (overrides or {}).items():
        node = schema
        for part in path.split("."):
            node = node.setdefault("properties", {}).setdefault(part, {})
        if "type" in frag and isinstance(frag["type"], list):
            node.pop("type", None)
        merge(node, frag)


# Kubernetes types the defaults cannot show: a PDB budget is an int or a
# percentage, an HPA target may be left out. Applied to every pdb and
# autoscaling block, so a component added later gets them too.
BUDGET = {"type": ["integer", "string", "null"], "minimum": 0, "pattern": "^[0-9]+%$"}
TARGET = {"type": ["integer", "null"], "minimum": 1}
WORKLOAD_TYPES = {
    "pdb": {"minAvailable": BUDGET, "maxUnavailable": BUDGET},
    "autoscaling": {"targetCPUUtilizationPercentage": TARGET, "targetMemoryUtilizationPercentage": TARGET},
}


def workload_types(node):
    for name, child in (node.get("properties") or {}).items():
        for key, frag in WORKLOAD_TYPES.get(name, {}).items():
            props = child.get("properties") or {}
            if key in props:
                props[key].pop("type", None)
                merge(props[key], dict(frag))
        workload_types(child)


def undocumented(value, path, descs, depth=0):
    """Leaf paths with no description of their own or of a non-top-level ancestor."""
    if path in descs and depth > 1:
        return []
    if isinstance(value, dict) and value:
        out = []
        for k, v in value.items():
            out += undocumented(v, f"{path}.{k}" if path else k, descs, depth + 1)
        return out
    return [] if path in descs else [path]


def compact(node):
    """The schema without "description" annotations (only string-valued ones:
    a value named "description" is a property whose schema is an object)."""
    if isinstance(node, dict):
        return {k: compact(v) for k, v in node.items()
                if not (k == "description" and isinstance(v, str))}
    if isinstance(node, list):
        return [compact(v) for v in node]
    return node


def main():
    text = VALUES.read_text()
    values = yaml.safe_load(text)
    descs = descriptions(text)
    schema = {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "title": f"{CHART.name} chart values",
        "type": "object",
        "properties": {k: build(v, k, descs) for k, v in values.items()},
        "additionalProperties": False,
    }
    workload_types(schema)
    apply_overrides(schema, yaml.safe_load(OVERRIDES.read_text()) if OVERRIDES.exists() else {})
    missing = [k for k, v in schema["properties"].items() if not v.get("description")]
    if missing:
        print("top-level keys without a '# --' description: " + ", ".join(missing), file=sys.stderr)
        return 1
    bad = [k for k, d in descs.items() if " --" in d]
    if bad:
        print("descriptions containing ' --' (helm-docs drops them): " + ", ".join(bad), file=sys.stderr)
        return 1
    missing = undocumented(values, "", descs)
    if missing:
        print("values without a '# --' description: " + ", ".join(missing), file=sys.stderr)
        return 1
    outputs = {
        DOC_SCHEMA: json.dumps(schema, indent=2, sort_keys=False) + "\n",
        SCHEMA: json.dumps(compact(schema), separators=(",", ":"), sort_keys=False) + "\n",
    }
    if "--check" in sys.argv:
        stale = [str(p.relative_to(ROOT)) for p, out in outputs.items()
                 if not p.exists() or p.read_text() != out]
        if stale:
            print(", ".join(stale) + " out of date: run ci/gen-schema.py", file=sys.stderr)
            return 1
        return 0
    for p, out in outputs.items():
        p.write_text(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
