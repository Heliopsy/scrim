#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the artifacthub.io/images annotation of Chart.yaml from values.yaml.

Every image block in values.yaml (a map with a non-empty "repository") and
every "imageName" string becomes one entry, referenced exactly as the chart
renders it by default: registry/repository:tag@digest, with the chart
appVersion as the tag where the block sets useAppVersion and no tag. A block
with an empty repository (one that falls back to another image) is skipped.
The list therefore cannot drift from the defaults; verify.sh runs this with
--check. global.imageRegistry is not applied: the list names the upstream
images.

Usage: deploy/helm/scrim/ci/gen-images.py [--check]

Ported from toc-helm-chart-template. The scrim image has no digest by
default (its tag is the release's appVersion), so its entry is tag only.
"""
import re
import sys
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent.parent
VALUES = CHART / "values.yaml"
CHART_YAML = CHART / "Chart.yaml"
KEY = "  artifacthub.io/images: |"


def images(values, app_version):
    out = []

    def walk(node, path):
        if not isinstance(node, dict):
            return
        if isinstance(node.get("repository"), str) and node["repository"]:
            tag = str(node.get("tag") or "")
            from_app = False
            if not tag and node.get("useAppVersion"):
                tag = app_version
                from_app = True
            ref = node["repository"]
            if node.get("registry"):
                ref = f"{node['registry']}/{ref}"
            if tag:
                ref += f":{tag}"
            if node.get("digest"):
                ref += f"@{node['digest']}"
            if from_app:
                # release-please bumps appVersion and this line together.
                ref += " # x-release-please-version"
            out.append((node["repository"].rsplit("/", 1)[-1], ref, path))
        for k, v in node.items():
            if k == "imageName" and isinstance(v, str) and v:
                # A full reference in one string.
                out.append((v.split("@")[0].rsplit(":", 1)[0].rsplit("/", 1)[-1], v, path))
                continue
            walk(v, f"{path}.{k}" if path else k)

    walk(values, "")
    seen = {}
    for name, _, path in out:
        seen[name] = seen.get(name, 0) + 1
    # A repository name used twice is told apart by its value path.
    return [(name if seen[name] == 1 else path, ref) for name, ref, path in out]


def render(entries):
    lines = [KEY]
    for name, ref in entries:
        lines.append(f"    - name: {name}")
        lines.append(f"      image: {ref}")
    return "\n".join(lines) + "\n"


def main():
    chart_text = CHART_YAML.read_text()
    app_version = str(yaml.safe_load(chart_text)["appVersion"])
    block = render(images(yaml.safe_load(VALUES.read_text()), app_version))
    pattern = re.compile(r"^" + re.escape(KEY) + r"\n(?:    .*\n)*", re.M)
    if not pattern.search(chart_text):
        print(f"Chart.yaml has no '{KEY.strip()}' annotation", file=sys.stderr)
        return 1
    new = pattern.sub(lambda _: block, chart_text, count=1)
    if "--check" in sys.argv:
        if new != chart_text:
            print("Chart.yaml artifacthub.io/images is out of date: run deploy/helm/scrim/ci/gen-images.py", file=sys.stderr)
            return 1
        return 0
    CHART_YAML.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
