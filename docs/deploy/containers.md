# Containers

The signed image `ghcr.io/heliopsy/scrim` under rootless podman, for a host that runs its
services as containers. Four forms of the same container:

| Form | Use it when |
| --- | --- |
| [`podman run`](#podman-run) | trying it out, or a script starts it |
| [Quadlet](#quadlet) | systemd should start it at boot and restart it, with `podman auto-update` for patch releases |
| [`podman kube play`](#podman-kube-play) | you want the same Pod YAML locally that you would give Kubernetes |
| [Compose](#compose) | the rest of your stack is a compose file |

Agents reach the container through the published ports, as base URL
(`http://127.0.0.1:9790/anthropic`, `/openai/v1`) or as forward proxy
(`HTTPS_PROXY=http://127.0.0.1:9791`). `scrim run` on the host does not use a containerized
scrim: its sessions are bound to process trees the container cannot see. Redaction applies to
every caller; credential injection needs an identified agent, so without `scrim run` it is decided
by your [policy rules](../policy.md) and refused by default.

Files: [`deploy/examples/podman/`](../../deploy/examples/podman/). Every command here uses podman.
The compose file follows the Compose Specification, so `docker compose` reads it as well.

## Prerequisites

- podman 4.9 or later, rootless (`podman info --format '{{.Host.Security.Rootless}}'` prints
  `true`). Quadlet needs systemd.
- podman-compose 1.x for the compose example (`podman compose` calls it).
- cosign to verify the image.

Verify the image and pin its digest:

```sh
cosign verify ghcr.io/heliopsy/scrim:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v.+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.[0].critical.image."docker-manifest-digest"'
# sha256:490a9ca52efeba6f9ed4c886f0dba55e33325603988c6570dd29477827cf683e for 0.1.0
```

The examples use the tag so they read easily; for a deployment use
`ghcr.io/heliopsy/scrim@sha256:...`.

## What every form sets up

- A read-only root filesystem, every capability dropped, `no-new-privileges`, UID 65532.
- State (SQLite, placeholder key, CA) in a named volume at `/var/lib/scrim`. Rootless podman maps
  UID 65532 to a subordinate UID that can write a named volume but not a directory of yours.
- The sockets on a tmpfs owned by the container user (`--tmpfs /run/scrim:rw,mode=0700,U` with
  `XDG_RUNTIME_DIR=/run/scrim`). The `U` option needs podman; Docker spells it `uid=65532`, which
  podman 4.9 rejects.
- Secrets as podman secrets, mounted read-only at `/run/scrim-secrets/agents/<name>`, owned by
  65532. `/run/secrets` itself is podman's own mount and takes no subdirectories under a read-only
  root, hence the separate path.
- The config file ([`config.yaml`](../../deploy/examples/podman/config.yaml)) at
  `/etc/scrim/config.yaml`, with the listeners on every address inside the container and the
  ports published on the host's loopback only.
- A health check that runs `scrim doctor` in exec form, since the image has no shell (the kube
  play Pod has none).

## podman run

[`run.sh`](../../deploy/examples/podman/run.sh):

```sh
cd deploy/examples/podman
printf '%s' "$GITHUB_TOKEN" | podman secret create scrim-github-token -
./run.sh
```

The command it runs:

```sh
podman run -d --name scrim \
  --read-only --cap-drop=all --security-opt=no-new-privileges \
  --tmpfs /run/scrim:rw,mode=0700,U -e XDG_RUNTIME_DIR=/run/scrim \
  -v scrim-state:/var/lib/scrim \
  -v ./config.yaml:/etc/scrim/config.yaml:ro,Z \
  --secret scrim-github-token,target=/run/scrim-secrets/agents/github-token,uid=65532,gid=65532,mode=0400 \
  -p 127.0.0.1:9790:9790 -p 127.0.0.1:9791:9791 -p 127.0.0.1:9792:9792 \
  --health-cmd '["/usr/local/bin/scrim", "doctor", "--timeout", "5s"]' \
  --health-interval 30s --health-start-period 20s \
  ghcr.io/heliopsy/scrim:0.1.0 proxy
```

## Quadlet

[`scrim.container`](../../deploy/examples/podman/quadlet/scrim.container) and
[`scrim-state.volume`](../../deploy/examples/podman/quadlet/scrim-state.volume) describe the same
container for systemd. Rootless:

```sh
mkdir -p ~/.config/containers/systemd ~/.config/scrim
cp deploy/examples/podman/quadlet/scrim.container deploy/examples/podman/quadlet/scrim-state.volume \
  ~/.config/containers/systemd/
cp deploy/examples/podman/config.yaml ~/.config/scrim/container.yaml
printf '%s' "$GITHUB_TOKEN" | podman secret create scrim-github-token -
/usr/libexec/podman/quadlet -dryrun -user          # prints the generated scrim.service
systemctl --user daemon-reload
systemctl --user start scrim
loginctl enable-linger "$USER"                      # start at boot without a login
```

The Quadlet unit has no `[Install]` enablement step: the generator links it into
`default.target` from `WantedBy=`. The image is `ghcr.io/heliopsy/scrim:0.1` with
`AutoUpdate=registry`, so `podman auto-update` (or `systemctl --user enable --now
podman-auto-update.timer`) pulls 0.1.x patch releases, restarts the unit and rolls back when the
new container fails to start. Pin `0.1.0` or a digest to update only by editing the file.

`scrim install --quadlet` (0.2.0 and later) writes and records an equivalent unit
([service.md](../service.md)).

## podman kube play

[`kube/scrim.yaml`](../../deploy/examples/podman/kube/scrim.yaml) is a ConfigMap and a Pod. kube
play reads Secrets from podman secrets whose data is a Kubernetes Secret, so create it through kube
play too, with the value from your shell:

```sh
cd deploy/examples/podman/kube
cat <<EOF | podman kube play -
apiVersion: v1
kind: Secret
metadata:
  name: scrim-agent-secrets
data:
  github-token: $(printf '%s' "$GITHUB_TOKEN" | base64 -w0)
EOF
podman kube play scrim.yaml
```

The state lives in the volume `scrim-state` (the PersistentVolumeClaim's name). `podman kube down
scrim.yaml` stops the pod and keeps it.

## Compose

[`compose/compose.yaml`](../../deploy/examples/podman/compose/compose.yaml). Compose has no portable
way to give a file to a non-root container user, so this one reads the secret from scrim's
environment ([`compose/config.yaml`](../../deploy/examples/podman/compose/config.yaml) uses the env
store), filled from the shell that runs compose:

```sh
cd deploy/examples/podman/compose
export SCRIM_SECRET_GITHUB_TOKEN=...      # from your secret manager, not a file
podman compose up -d
```

The sockets go to `/tmp/scrim` on the compose `tmpfs`, which both podman and Docker create
writable for any user. An environment variable is visible in `podman inspect`; prefer the podman
run, Quadlet or kube play forms for long-lived secrets.

## Verify

The same checks for every form; the container is named `scrim` in all of them (kube play names it
`scrim-scrim`).

```sh
curl -s http://127.0.0.1:9792/readyz       # {"status":"ok","checks":{...,"store files":"ok"}}
podman exec scrim scrim status             # Data plane: "snapshot N, 1 values"
podman exec scrim scrim doctor             # all checks passed
podman healthcheck run scrim && echo healthy   # run, Quadlet and compose define one
```

`scrim status` shows `DEGRADED` for break-glass, capture mode and direct-egress blocking while
they are inactive, which is the normal state here.

Canary request (Anthropic answers 401 to the fake key):

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9790/anthropic/v1/messages \
  -H 'x-api-key: not-a-real-key' -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"canary <the token>"}]}'
```

To see what left, run the container once with capture mode on (add
`-e SCRIM_PROXY_CAPTURE_DIR=/var/lib/scrim/capture` before the image), send the request, then copy
the captures out and search them:

```sh
podman cp scrim:/var/lib/scrim/capture ./capture
grep -rlF '<the token>' capture/ || echo "value absent"
grep -o '⟦scrim:github:[0-9a-f]*⟧' capture/*.request.body
rm -r capture
```

The forward proxy is in the path when a request through it with a placeholder is refused for an
unknown caller:

```sh
podman exec scrim scrim ca export > scrim-ca.pem
curl -s --proxy http://127.0.0.1:9791 --cacert scrim-ca.pem \
  -H 'Authorization: Bearer SCRIM_GITHUB_TOKEN' https://api.github.com/user
# {"error":{"type":"scrim_tool_proxy_error","code":"policy_denied",...}}
```

Give agents in other containers that `scrim-ca.pem` (mounted, plus `NODE_EXTRA_CA_CERTS` or
`SSL_CERT_FILE`, see [ca.md](../ca.md)) and the base URL or proxy address.

## Upgrade and roll back

Change the tag (or digest) and recreate the container; the volume keeps the state.

```sh
podman pull ghcr.io/heliopsy/scrim:0.1.1
podman rm -f scrim && IMAGE=ghcr.io/heliopsy/scrim:0.1.1 ./run.sh   # podman run
podman auto-update                                                    # Quadlet on the 0.1 tag
podman kube play --replace scrim.yaml                                 # after editing the image
podman compose up -d                                                  # after editing the image
```

Roll back the same way with the previous tag. `podman auto-update --rollback` (the default) puts
the previous image back when the updated unit fails to start.

## Uninstall

```sh
podman rm -f -v scrim && podman volume rm scrim-state           # podman run
systemctl --user stop scrim && rm ~/.config/containers/systemd/scrim.container \
  ~/.config/containers/systemd/scrim-state.volume && systemctl --user daemon-reload \
  && podman volume rm systemd-scrim-state                       # Quadlet
podman kube down --force scrim.yaml                             # kube play, volumes too
podman compose down -v                                          # compose, volume too
podman secret rm scrim-github-token scrim-agent-secrets 2>/dev/null
podman rmi ghcr.io/heliopsy/scrim:0.1.0
```
