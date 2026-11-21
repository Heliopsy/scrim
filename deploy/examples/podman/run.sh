#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scrim in one rootless podman container. Run from this directory:
#
#   printf '%s' "$GITHUB_TOKEN" | podman secret create scrim-github-token -
#   ./run.sh
#
# Agents on this host then use http://127.0.0.1:9790/anthropic as their
# Anthropic base URL (and /openai/v1 for OpenAI), or http://127.0.0.1:9791 as
# HTTPS_PROXY with scrim's CA trusted. Remove everything again with
#   podman rm -f -v scrim && podman volume rm scrim-state && podman secret rm scrim-github-token
set -euo pipefail

IMAGE=${IMAGE:-ghcr.io/heliopsy/scrim:0.3.0} # x-release-please-version
NAME=${NAME:-scrim}
VOLUME=${VOLUME:-scrim-state}
SECRET=${SECRET:-scrim-github-token}

# State (SQLite, placeholder key, CA) survives restarts and upgrades in a
# named volume, which the container's UID 65532 can write.
podman volume exists "$VOLUME" || podman volume create "$VOLUME" >/dev/null

podman run -d --name "$NAME" \
  --read-only \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --tmpfs /run/scrim:rw,mode=0700,U \
  -e XDG_RUNTIME_DIR=/run/scrim \
  -v "$VOLUME":/var/lib/scrim \
  -v ./config.yaml:/etc/scrim/config.yaml:ro,Z \
  --secret "$SECRET",target=/run/scrim-secrets/agents/github-token,uid=65532,gid=65532,mode=0400 \
  -p 127.0.0.1:9790:9790 \
  -p 127.0.0.1:9791:9791 \
  -p 127.0.0.1:9792:9792 \
  --health-cmd '["/usr/local/bin/scrim", "doctor", "--timeout", "5s"]' \
  --health-interval 30s \
  --health-start-period 20s \
  "$IMAGE" proxy
