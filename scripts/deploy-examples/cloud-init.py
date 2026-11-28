#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Writes deploy/examples/cloud-init/user-data.yaml from the files it embeds.

The cloud-init example carries copies of the systemd example and of the
workstation install script. Edit those, then run this script; check.sh fails
while the copies differ.

    python3 -I scripts/deploy-examples/cloud-init.py
"""
import pathlib

ex = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "examples"

FILES = [
    ("/etc/sysusers.d/scrim.conf", "systemd/system/scrim.sysusers.conf", "0644"),
    ("/etc/tmpfiles.d/scrim.conf", "systemd/system/scrim.tmpfiles.conf", "0644"),
    ("/etc/systemd/system/scrim.service", "systemd/system/scrim.service", "0644"),
    ("/etc/scrim/config.yaml", "systemd/system/config.yaml", "0644"),
    ("/usr/local/sbin/scrim-install", "workstation/install.sh", "0755"),
]

HEAD = """\
#cloud-config
# cloud-init user-data: installs scrim from a signed release and enables it as a
# system service. Checked with `cloud-init schema --config-file user-data.yaml`.
#
# The files under write_files are copies of deploy/examples/systemd/system/ and
# deploy/examples/workstation/install.sh, written by
# scripts/deploy-examples/cloud-init.py; `just deploy-examples-check` fails when
# they drift. No secret is in here: user-data is readable from the instance
# metadata service, so secrets reach /etc/scrim/secrets/agents/ from your
# provisioning afterwards, which then runs `systemctl start scrim`: scrim
# refuses to start while its redact target files://agents/* matches nothing.

package_update: true
packages:
  - curl
  - ca-certificates

write_files:
"""

TAIL = """
runcmd:
  - [systemd-sysusers, /etc/sysusers.d/scrim.conf]
  - [systemd-tmpfiles, --create, /etc/tmpfiles.d/scrim.conf]
  # cosign verifies the release; pinned by version and sha256.
  - - sh
    - -ec
    - |
      case "$(uname -m)" in
        x86_64) arch=amd64 sum=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa ;;
        aarch64) arch=arm64 sum=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2 ;;
      esac
      curl -fsSL -o /usr/local/bin/cosign "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-$arch"
      echo "$sum  /usr/local/bin/cosign" | sha256sum -c -
      chmod 0755 /usr/local/bin/cosign
  - [env, VERSION=1.3.0, PREFIX=/usr/local, /usr/local/sbin/scrim-install] # x-release-please-version
  - [systemctl, daemon-reload]
  # Enabled, not started: see the comment at the top.
  - [systemctl, enable, scrim.service]
"""


def main() -> None:
    out = [HEAD.rstrip("\n")]
    for dest, src, mode in FILES:
        out += [f"  - path: {dest}", "    owner: root:root", f"    permissions: '{mode}'", "    content: |"]
        out += [("      " + line) if line else "" for line in (ex / src).read_text().splitlines()]
    (ex / "cloud-init" / "user-data.yaml").write_text("\n".join(out) + "\n" + TAIL)


if __name__ == "__main__":
    main()
