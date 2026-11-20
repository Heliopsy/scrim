#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare two renders of the chart for changes `helm upgrade` cannot apply.

    check-upgrade.py OLD.yaml NEW.yaml

Both files are `helm template` output of the same release name, namespace and
values: OLD from the previous release, NEW from the working tree. Fails (exit 1)
when an object present in both changes a field Kubernetes refuses to update or
that loses data:

  Deployment, StatefulSet   spec.selector
  StatefulSet               spec.serviceName, spec.podManagementPolicy,
                            spec.volumeClaimTemplates (whole templates)
  PersistentVolumeClaim     spec (accessModes, storageClassName, volumeName,
                            volumeMode, dataSource, selector, size)
  Service                   headless (clusterIP None) versus not
  Job (not a hook)          spec.template, spec.selector

CronJobs are not compared: their jobTemplate is mutable, and a changed one
applies to the next Job the schedule creates.

A PersistentVolumeClaim or StatefulSet that disappears is reported too: with
helm.sh/resource-policy keep the data stays, but the release no longer owns it.
Objects only in NEW are fine. Helm test pods and hooks are recreated on every
run and are skipped.
"""
import sys

import yaml


def load(path):
    out = {}
    with open(path) as f:
        for doc in yaml.safe_load_all(f):
            if not isinstance(doc, dict) or "kind" not in doc:
                continue
            meta = doc.get("metadata") or {}
            ann = meta.get("annotations") or {}
            if "helm.sh/hook" in ann:
                continue
            key = (doc["kind"], meta.get("namespace", ""), meta.get("name", ""))
            out[key] = doc
    return out


def dig(doc, *path):
    for p in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(p)
    return doc


def pvc_spec(spec):
    spec = dict(spec or {})
    # Only requests.storage matters here; limits on a PVC are ignored by most
    # provisioners and are not immutable.
    spec["resources"] = dig(spec, "resources", "requests", "storage")
    return spec


def vct(sts):
    # The whole template counts: Kubernetes refuses any change to
    # volumeClaimTemplates, labels included.
    out = {}
    for t in dig(sts, "spec", "volumeClaimTemplates") or []:
        out[dig(t, "metadata", "name")] = {"metadata": t.get("metadata"), "spec": t.get("spec")}
    return out


def main(old_path, new_path):
    old, new = load(old_path), load(new_path)
    errors, notes = [], []

    def cmp(key, what, a, b):
        if a != b:
            errors.append(f"{key[0]}/{key[2]}: {what} changed\n    old: {a}\n    new: {b}")

    for key, o in sorted(old.items()):
        kind = key[0]
        n = new.get(key)
        if n is None:
            if kind in ("PersistentVolumeClaim", "StatefulSet"):
                notes.append(f"{kind}/{key[2]} is gone in the new chart (the release stops owning it)")
            continue
        if kind in ("Deployment", "StatefulSet"):
            cmp(key, "spec.selector", dig(o, "spec", "selector"), dig(n, "spec", "selector"))
        if kind == "StatefulSet":
            cmp(key, "spec.serviceName", dig(o, "spec", "serviceName"), dig(n, "spec", "serviceName"))
            cmp(key, "spec.podManagementPolicy",
                dig(o, "spec", "podManagementPolicy") or "OrderedReady",
                dig(n, "spec", "podManagementPolicy") or "OrderedReady")
            cmp(key, "spec.volumeClaimTemplates", vct(o), vct(n))
        if kind == "PersistentVolumeClaim":
            cmp(key, "spec", pvc_spec(o.get("spec")), pvc_spec(n.get("spec")))
        if kind == "Service":
            cmp(key, "headless (spec.clusterIP None)",
                dig(o, "spec", "clusterIP") == "None", dig(n, "spec", "clusterIP") == "None")
        if kind == "Job":
            cmp(key, "spec.template", dig(o, "spec", "template"), dig(n, "spec", "template"))
            cmp(key, "spec.selector", dig(o, "spec", "selector"), dig(n, "spec", "selector"))

    for line in notes:
        print(f"note: {line}")
    for line in errors:
        print(f"FAIL: {line}")
    checked = sum(1 for k in old if k in new)
    print(f"{checked} objects in both renders, {len(errors)} immutable-field change(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
