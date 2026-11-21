#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check every pod the chart renders against the Pod Security Standards
"restricted" profile, plus the chart's own rules.

Restricted (https://kubernetes.io/docs/concepts/security/pod-security-standards/):
no host namespaces, ports or paths, no privileged containers, capabilities
drop ALL (add at most NET_BIND_SERVICE), allowPrivilegeEscalation false,
runAsNonRoot, no runAsUser 0, seccomp RuntimeDefault or Localhost, only the
allowed volume types, no unsafe sysctls, no AppArmor unconfined, no custom
SELinux user/role, default /proc mount.

The chart's own rules: every container (init containers too) sets cpu and
memory requests and a memory limit, and every pod states
automountServiceAccountToken (false unless the component needs its token).

Ported from toc-helm-chart-template. scrim also checks the containers its
Kyverno MutatingPolicy injects (the sidecar and the egress guard; the pod
around them is the user's), with one documented exception: the egress guard
init container runs as root with NET_ADMIN to install its nftables table and
exits before the agent starts (docs/kubernetes.md, "Why the sidecar needs the
egress guard"). Pod Security "restricted" (and "baseline") refuse it, so
sidecar-mode namespaces need "privileged" or an exemption for it.

Usage: check-pods.py RENDERED.yaml...
"""
import json
import sys

import yaml

POD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
VOLUME_TYPES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
                "persistentVolumeClaim", "projected", "secret"}
SAFE_SYSCTLS = {"kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range",
                "net.ipv4.ip_unprivileged_port_start", "net.ipv4.tcp_syncookies",
                "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports",
                "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout",
                "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes"}


def pod_spec(doc):
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec") or {}
    if kind == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return doc["spec"]["template"]["spec"]


# Container name -> problems it is allowed to have, with the reason.
EXCEPTIONS = {
    "scrim-egress-guard": {
        "problems": {"runAsNonRoot not true", "runAsUser 0", "adds capabilities ['NET_ADMIN']"},
        "why": "installs the sidecar egress guard (nftables) as root with NET_ADMIN, then exits",
    },
}


def unmarshal(expression):
    """The JSON of a policy variable written as json.unmarshal(r'''...''')."""
    e = expression.strip()
    prefix, suffix = "json.unmarshal(r'''", "''')"
    if not (e.startswith(prefix) and e.endswith(suffix)):
        return None
    return json.loads(e[len(prefix):-len(suffix)])


def injected(doc):
    """Pod specs made of the containers a Kyverno MutatingPolicy adds to pods."""
    variables = {v.get("name"): v.get("expression", "") for v in (doc.get("spec") or {}).get("variables") or []}
    inits = unmarshal(variables["initContainers"]) if "initContainers" in variables else []
    if inits is None:
        raise SystemExit(f"MutatingPolicy/{doc['metadata']['name']}: initContainers is not json.unmarshal of a literal")
    if inits:
        yield "initContainers", {"initContainers": inits, "containers": [],
                                 "automountServiceAccountToken": "user's pod"}


def check(spec, injected_only=False):
    errs = []
    psc = spec.get("securityContext") or {}
    for f in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(f):
            errs.append(f"{f} is set")
    if "automountServiceAccountToken" not in spec and not injected_only:
        errs.append("automountServiceAccountToken not stated")
    for v in spec.get("volumes") or []:
        types = [k for k in v if k != "name"]
        if not set(types) <= VOLUME_TYPES:
            errs.append(f"volume {v['name']}: type {types} not allowed")
    for s in psc.get("sysctls") or []:
        if s.get("name") not in SAFE_SYSCTLS:
            errs.append(f"unsafe sysctl {s.get('name')}")
    pod_seccomp = (psc.get("seccompProfile") or {}).get("type")
    if pod_seccomp not in (None, "RuntimeDefault", "Localhost"):
        errs.append(f"pod seccompProfile {pod_seccomp}")
    if psc.get("runAsUser") == 0:
        errs.append("pod runAsUser 0")
    se = psc.get("seLinuxOptions") or {}
    if se.get("user") or se.get("role"):
        errs.append("pod seLinuxOptions user/role set")

    containers = [("init", c) for c in spec.get("initContainers") or []]
    containers += [("", c) for c in spec.get("containers") or []]
    containers += [("ephemeral", c) for c in spec.get("ephemeralContainers") or []]
    for kind, c in containers:
        name = f"{kind + ' ' if kind else ''}container {c['name']}"
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            errs.append(f"{name}: privileged")
        if sc.get("allowPrivilegeEscalation") is not False:
            errs.append(f"{name}: allowPrivilegeEscalation is not false")
        caps = sc.get("capabilities") or {}
        if "ALL" not in (caps.get("drop") or []):
            errs.append(f"{name}: capabilities do not drop ALL")
        if set(caps.get("add") or []) - {"NET_BIND_SERVICE"}:
            errs.append(f"{name}: adds capabilities {caps['add']}")
        if not (sc.get("runAsNonRoot") is True or (psc.get("runAsNonRoot") is True and sc.get("runAsNonRoot") is not False)):
            errs.append(f"{name}: runAsNonRoot not true")
        if sc.get("runAsUser") == 0:
            errs.append(f"{name}: runAsUser 0")
        seccomp = (sc.get("seccompProfile") or {}).get("type") or pod_seccomp
        if seccomp not in ("RuntimeDefault", "Localhost"):
            errs.append(f"{name}: no RuntimeDefault/Localhost seccompProfile")
        if sc.get("procMount") not in (None, "Default"):
            errs.append(f"{name}: procMount {sc['procMount']}")
        if (sc.get("appArmorProfile") or {}).get("type") == "Unconfined":
            errs.append(f"{name}: AppArmor unconfined")
        se = sc.get("seLinuxOptions") or {}
        if se.get("user") or se.get("role"):
            errs.append(f"{name}: seLinuxOptions user/role set")
        for p in c.get("ports") or []:
            if p.get("hostPort"):
                errs.append(f"{name}: hostPort {p['hostPort']}")
        if kind == "ephemeral":
            continue
        res = c.get("resources") or {}
        req = res.get("requests") or {}
        if not req.get("cpu") or not req.get("memory"):
            errs.append(f"{name}: no cpu/memory requests")
        if not (res.get("limits") or {}).get("memory"):
            errs.append(f"{name}: no memory limit")
    out = []
    for e in errs:
        cname = e.split(":", 1)[0].rsplit(" ", 1)[-1]
        allowed = EXCEPTIONS.get(cname, {}).get("problems", set())
        if e.split(": ", 1)[-1] in allowed:
            print(f"allowed: {e} ({EXCEPTIONS[cname]['why']})")
            continue
        out.append(e)
    return out


def main():
    failed = 0
    checked = 0
    for path in sys.argv[1:]:
        with open(path) as fh:
            for doc in yaml.safe_load_all(fh):
                if doc and doc.get("kind") == "MutatingPolicy":
                    for var, spec in injected(doc):
                        checked += 1
                        for e in check(spec, injected_only=True):
                            print(f"{path}: MutatingPolicy/{doc['metadata']['name']} variable {var}: {e}", file=sys.stderr)
                            failed += 1
                    continue
                if not doc or doc.get("kind") not in POD_KINDS:
                    continue
                checked += 1
                for e in check(pod_spec(doc)):
                    print(f"{path}: {doc['kind']}/{doc['metadata']['name']}: {e}", file=sys.stderr)
                    failed += 1
    print(f"{checked} pod templates checked, {failed} problems")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
