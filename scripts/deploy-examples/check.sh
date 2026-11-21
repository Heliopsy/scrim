#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/deploy-examples/check.sh [TOOLS_DIR]
#
# Checks every file under deploy/examples, the files docs/deploy shows:
#
#   - each scrim config file with `scrim config validate`, run in the image of
#     this tree (image.sh) with the mounts the example gives it (stub secrets,
#     generated here);
#   - copies that must not drift (cloud-init write_files, the Ansible role's
#     unit and default config, the kube play ConfigMap, the kustomize base);
#   - systemd units and Quadlet files with `systemd-analyze verify` and
#     quadlet's dry run; cloud-init user-data with `cloud-init schema`;
#   - the Ansible role with `ansible-playbook --syntax-check` and ansible-lint;
#   - the compose file with `podman-compose config`;
#   - every Kubernetes manifest, kustomize overlay and rendered Helm values file
#     with kubeconform -strict against pinned Kubernetes and CRD schemas, and
#     the Helm values with `helm lint`;
#   - shell scripts with shellcheck, JSON with python's parser.
#
# TOOLS_DIR (default .tools/deploy-examples) is where tools.sh installed the
# pinned tools. SCRIM_EXAMPLES_IMAGE names a scrim image of this tree to use;
# without it image.sh builds one and it is removed on exit. Needs podman,
# python3, systemd-analyze and shellcheck on the host. Every container it
# starts is removed when it exits.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
while IFS='=' read -r key value; do
  case "$key" in '' | '#'*) continue ;; esac
  if [ -z "${!key+x}" ]; then export "$key=$value"; fi
done <"$here/tools.env"

tools=$(cd "${1:-$root/.tools/deploy-examples}" && pwd)
export PATH="$tools/bin:$tools/venv/bin:$PATH"
ex=$root/deploy/examples
work=$(mktemp -d)
built=""
trap 'rm -rf "$work"; [ -z "$built" ] || podman rmi -f "$built" >/dev/null 2>&1 || true' EXIT
if [ -n "${SCRIM_EXAMPLES_IMAGE:-}" ]; then
  image=$SCRIM_EXAMPLES_IMAGE
else
  image=$("$here/image.sh")
  built=$image
fi

failed=0
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; failed=1; }
run() { "$@" || fail "$*"; }

# ---------------------------------------------------------------- shell, JSON

step "shellcheck"
run shellcheck "$ex/workstation/install.sh" "$ex/podman/run.sh" \
  "$ex/kubernetes/raw/create-secrets.sh" "$here/tools.sh" "$here/check.sh" "$here/smoke.sh" "$here/image.sh"

step "JSON"
while IFS= read -r f; do
  python3 -I -m json.tool "$f" >/dev/null || fail "$f is not valid JSON"
done < <(find "$ex" -name '*.json')

# ---------------------------------------------------------------- drift between copies

step "copies that must match their source"
python3 -I - "$ex" <<'EOF' || failed=1
import sys, yaml, pathlib
ex = pathlib.Path(sys.argv[1])
bad = []
def same(a, b, what):
    if a != b:
        bad.append(what)

# cloud-init embeds the systemd example and the install script.
ud = yaml.safe_load((ex / "cloud-init/user-data.yaml").read_text())
src = {
    "/etc/sysusers.d/scrim.conf": "systemd/system/scrim.sysusers.conf",
    "/etc/tmpfiles.d/scrim.conf": "systemd/system/scrim.tmpfiles.conf",
    "/etc/systemd/system/scrim.service": "systemd/system/scrim.service",
    "/etc/scrim/config.yaml": "systemd/system/config.yaml",
    "/usr/local/sbin/scrim-install": "workstation/install.sh",
}
seen = set()
for wf in ud["write_files"]:
    if wf["path"] in src:
        seen.add(wf["path"])
        same(wf["content"], (ex / src[wf["path"]]).read_text(), "cloud-init " + wf["path"])
for p in set(src) - seen:
    bad.append("cloud-init lacks " + p)

# The Ansible role ships the same unit, and its default config is the
# systemd example's config.
same((ex / "ansible/roles/scrim/files/scrim.service").read_text(),
     (ex / "systemd/system/scrim.service").read_text(), "ansible scrim.service")
defaults = yaml.safe_load((ex / "ansible/roles/scrim/defaults/main.yml").read_text())
cfg = yaml.safe_load((ex / "systemd/system/config.yaml").read_text())
cfg.pop("apiVersion"); cfg.pop("kind")
same(defaults["scrim_config"], cfg, "ansible scrim_config default")

# kube play's ConfigMap carries podman/config.yaml.
docs = list(yaml.safe_load_all((ex / "podman/kube/scrim.yaml").read_text()))
cm = next(d for d in docs if d and d["kind"] == "ConfigMap")
same(cm["data"]["config.yaml"], (ex / "podman/config.yaml").read_text(), "kube play ConfigMap")

# The kustomize base config is the raw ConfigMap's plus the overlay include.
raw = yaml.safe_load((ex / "kubernetes/raw/20-configmap.yaml").read_text())
base = yaml.safe_load((ex / "kubernetes/kustomize/base/config.yaml").read_text())
base.pop("include", None)
same(base, yaml.safe_load(raw["data"]["config.yaml"]), "kustomize base config")

# Flux's HelmRelease values are the central-mode values file.
same((ex / "flux/helm/values.yaml").read_text(),
     (ex / "kubernetes/helm/values-central.yaml").read_text(), "flux helm values")

# Flux's chart source is the chart's own OCIRepository example.
chart_src = yaml.safe_load((ex / "../helm/scrim/examples/flux/ocirepository.yaml").read_text())
fleet_src = yaml.safe_load((ex / "flux/sources/scrim-chart.yaml").read_text())
same({k: fleet_src[k] for k in ("apiVersion", "kind", "metadata", "spec")},
     {k: chart_src[k] for k in ("apiVersion", "kind", "metadata", "spec")}, "flux chart OCIRepository")

# Every scrim version marked for release-please is the current release, so
# the release pull request moves them all at once.
import json, re
root = ex.parent.parent
current = json.loads((root / ".release-please-manifest.json").read_text())["."]
cfg = json.loads((root / "release-please-config.json").read_text())
for f in cfg["packages"]["."].get("extra-files", []):
    path = f["path"] if isinstance(f, dict) else f
    if not path.startswith(("deploy/examples/", "scripts/deploy-examples/")):
        continue
    marked = [l for l in (root / path).read_text().splitlines() if "x-release-please-version" in l]
    if not marked:
        bad.append(f"{path} is a release-please extra file without a marked line")
    for l in marked:
        if re.findall(r"[0-9]+\.[0-9]+\.[0-9]+", l) != [current]:
            bad.append(f"{path}: marked line is not version {current}: {l.strip()}")

# Every SOPS example is encrypted: each data and stringData value is ENC[...].
for f in sorted(p for p in (ex / "secrets/sops").glob("*.sops.yaml") if p.name != ".sops.yaml"):
    doc = yaml.safe_load(f.read_text())
    vals = list((doc.get("data") or {}).values()) + list((doc.get("stringData") or {}).values())
    if not vals or "sops" not in doc or not all(str(v).startswith("ENC[") for v in vals):
        bad.append(f"{f.name} is not SOPS-encrypted")

for b in bad:
    print("FAIL: drift:", b, file=sys.stderr)
sys.exit(1 if bad else 0)
EOF

# ---------------------------------------------------------------- scrim config validate

# Stub secrets: generated values in the shapes scrim checks (hex keys, a CA
# with a PKCS#8 key, a DSN). None of them is used for anything.
stubs=$work/stubs
mkdir -p "$stubs/agents" "$stubs/keys" "$stubs/ca" "$stubs/pg" "$stubs/cred" "$stubs/files"
openssl rand -hex 32 >"$stubs/keys/placeholder-k1"
cp "$stubs/keys/placeholder-k1" "$stubs/keys/k1"
openssl rand -hex 32 >"$stubs/keys/approvals-signing-key"
openssl rand -hex 16 >"$stubs/agents/github-token"
echo "postgres://scrim@postgres.scrim.svc:5432/scrim?sslmode=verify-full" >"$stubs/pg/dsn"
openssl rand -hex 16 >"$stubs/cred/bao-role-id"
openssl rand -hex 16 >"$stubs/cred/bao-secret-id"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$stubs/ca/tls.key" -out "$stubs/ca/tls.crt" -days 2 -subj "/CN=check" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" 2>/dev/null
chmod -R a+rX "$stubs"

# validate NAME DIR [podman args...]: DIR holds config.yaml (and whatever it
# includes); it is mounted at /etc/scrim.
validate() {
  local name=$1 dir=$2
  shift 2
  echo "-- $name"
  podman run --rm --read-only --network=none --name "scrim-examples-validate-$$" \
    --tmpfs /run/scrim:rw,mode=0700,U -e XDG_RUNTIME_DIR=/run/scrim \
    -v "$dir:/etc/scrim:ro,Z" "$@" \
    "$image" config validate --config /etc/scrim/config.yaml >"$work/validate.out" 2>&1 ||
    { cat "$work/validate.out" >&2; fail "scrim config validate: $name"; }
}
cfgdir() { local d=$work/cfg-$1; mkdir -p "$d"; cp "$2" "$d/config.yaml"; chmod -R a+rX "$d"; echo "$d"; }

step "scrim config validate ($image)"
validate workstation "$(cfgdir ws "$ex/workstation/config.yaml")"
d=$(cfgdir sysf "$ex/systemd/system/config.yaml")
cp -r "$stubs" "$d/secrets"
validate "systemd files" "$d"
validate "systemd openbao" "$(cfgdir sysb "$ex/systemd/system/config-openbao.yaml")" \
  -v "$stubs/cred:/run/credentials/scrim.service:ro,Z" -e CREDENTIALS_DIRECTORY=/run/credentials/scrim.service
validate podman "$(cfgdir podman "$ex/podman/config.yaml")" -v "$stubs:/run/scrim-secrets:ro,Z"
validate compose "$(cfgdir compose "$ex/podman/compose/config.yaml")"
python3 -I -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["data"]["config.yaml"], end="")' \
  "$ex/kubernetes/raw/20-configmap.yaml" >"$work/raw.yaml"
k8s_mounts=(-v "$stubs:/run/secrets/scrim:ro,Z" -v "$stubs/keys:/run/secrets/scrim-keys:ro,Z"
  -v "$stubs/ca:/run/secrets/scrim-ca:ro,Z" -v "$stubs/pg:/run/secrets/scrim-postgres:ro,Z")
validate "kubernetes raw" "$(cfgdir raw "$work/raw.yaml")" "${k8s_mounts[@]}"

# Each kustomize overlay: every key of its built ConfigMap, as the pod sees it.
for o in dev staging prod; do
  d=$work/kz-$o
  mkdir -p "$d"
  kustomize build "$ex/kubernetes/kustomize/overlays/$o" >"$work/kz-$o.yaml"
  python3 -I - "$work/kz-$o.yaml" "$d" <<'EOF'
import sys, yaml, pathlib
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if doc and doc["kind"] == "ConfigMap" and doc["metadata"]["name"].startswith("scrim-config"):
        for k, v in doc["data"].items():
            pathlib.Path(sys.argv[2], k).write_text(v)
EOF
  chmod -R a+rX "$d"
  validate "kustomize $o" "$d" "${k8s_mounts[@]}"
done

# ---------------------------------------------------------------- systemd and Quadlet

# A root holding the distribution's units, /bin/kill and stub binaries, so
# verify resolves every dependency and ExecStart path without touching the
# host. Any line verify prints is a failure: unknown keys are only warnings.
sdroot() {
  local r=$1
  mkdir -p "$r/usr/lib/systemd" "$r/bin" "$r/usr/bin" "$r/usr/local/bin" "$r/home/u/.local/bin" "$r/etc/systemd/system"
  cp -r /usr/lib/systemd/system "$r/usr/lib/systemd/"
  cp /bin/kill "$r/bin/kill"
  for b in "$r/usr/local/bin/scrim" "$r/home/u/.local/bin/scrim" "$r/usr/bin/podman"; do
    printf '#!/bin/sh\n' >"$b"
    chmod 0755 "$b"
  done
}
verify_unit() {
  local name=$1 r=$2 unit=$3
  echo "-- $name"
  if ! systemd-analyze verify --man=no --root="$r" "$unit" >"$work/verify.out" 2>&1 || [ -s "$work/verify.out" ]; then
    cat "$work/verify.out" >&2
    fail "systemd-analyze verify: $name"
  fi
}

step "systemd units"
r=$work/sd-system
sdroot "$r"
cp "$ex/systemd/system/scrim.service" "$r/etc/systemd/system/"
verify_unit "system unit" "$r" /etc/systemd/system/scrim.service
mkdir -p "$r/etc/systemd/system/scrim.service.d"
cp "$ex/systemd/system/scrim.service.d/openbao.conf" "$r/etc/systemd/system/scrim.service.d/"
verify_unit "system unit with the OpenBao drop-in" "$r" /etc/systemd/system/scrim.service
# A user unit cannot be verified under --root; check it as a system unit with
# %h spelled out.
r=$work/sd-user
sdroot "$r"
sed 's#%h#/home/u#g' "$ex/systemd/user/scrim.service" >"$r/etc/systemd/system/scrim.service"
verify_unit "user unit" "$r" /etc/systemd/system/scrim.service

step "Quadlet"
quadlet=${QUADLET:-/usr/libexec/podman/quadlet}
q=$work/quadlet
mkdir -p "$q"
cp "$ex/podman/quadlet/"* "$q/"
if QUADLET_UNIT_DIRS=$q "$quadlet" -dryrun -user >"$work/quadlet.out" 2>"$work/quadlet.err"; then
  grep -q '^---scrim.service---' "$work/quadlet.out" || fail "quadlet generated no scrim.service"
  r=$work/sd-quadlet
  sdroot "$r"
  awk '/^---scrim.service---$/{f=1; next} /^---/{f=0} f' "$work/quadlet.out" |
    sed -e 's#%h#/home/u#g' -e 's#%t#/run/user/1000#g' -e '/^SourcePath=/d' \
      -e 's#^Requires=scrim-state-volume.service##' -e 's#^After=scrim-state-volume.service##' \
      -e 's#^RequiresMountsFor=.*##' >"$r/etc/systemd/system/scrim.service"
  # Quadlet keeps its own [X-Container] section, which systemd ignores silently.
  verify_unit "quadlet scrim.service" "$r" /etc/systemd/system/scrim.service
else
  cat "$work/quadlet.err" >&2
  fail "quadlet -dryrun"
fi

# ---------------------------------------------------------------- cloud-init

step "cloud-init schema ($CLOUD_INIT_VERSION)"
podman run --rm --network=host --name "scrim-examples-cloudinit-$$" \
  -v "$ex/cloud-init:/w:ro,Z" "$UBUNTU_IMAGE" sh -ec "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends cloud-init=$CLOUD_INIT_VERSION >/dev/null 2>&1
    cloud-init schema --config-file /w/user-data.yaml --annotate" ||
  fail "cloud-init schema"

# ---------------------------------------------------------------- Ansible

step "Ansible"
(
  cd "$ex/ansible"
  export ANSIBLE_CONFIG=$ex/ansible/ansible.cfg ANSIBLE_LOCAL_TEMP=$work/ansible ANSIBLE_HOME=$work/ansible-home
  ansible-playbook --syntax-check playbook.yml
  ansible-lint --offline playbook.yml roles/scrim
) || fail "ansible"

# ---------------------------------------------------------------- compose

step "compose (podman-compose config)"
(
  cd "$ex/podman/compose"
  SCRIM_SECRET_GITHUB_TOKEN=not-a-secret podman-compose config >/dev/null
) || fail "podman-compose config"

# ---------------------------------------------------------------- Kubernetes

k8s_schemas="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$K8S_SCHEMAS_COMMIT/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json"
crd_schemas="https://raw.githubusercontent.com/datreeio/CRDs-catalog/$CRD_SCHEMAS_COMMIT/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"
kc() {
  kubeconform -strict -summary -kubernetes-version "$KUBERNETES_VERSION" \
    -cache "$tools/kubeconform-cache" \
    -schema-location "$k8s_schemas" -schema-location "$crd_schemas" "$@"
}
mkdir -p "$tools/kubeconform-cache"

step "kubeconform: manifests"
# Every Kubernetes object in the examples. Kustomize's own files and Helm
# values are not objects; SOPS files lose their sops metadata first (the
# encrypted values are plain strings to the schema).
mapfile -t manifests < <(
  find "$ex/kubernetes/raw" "$ex/podman/kube" "$ex/flux" "$ex/argocd" "$ex/secrets" "$ex/kyverno" \
    -name '*.yaml' ! -name '.sops.yaml' ! -name 'kustomization.yaml' ! -name 'kustomizeconfig.yaml' \
    ! -name 'values.yaml' 2>/dev/null | sort
)
python3 -I - "$work/manifests" "${manifests[@]}" <<'EOF'
import sys, yaml, pathlib
out = pathlib.Path(sys.argv[1])
out.mkdir()
for i, f in enumerate(sys.argv[2:]):
    docs = [d for d in yaml.safe_load_all(open(f)) if d]
    for d in docs:
        d.pop("sops", None)
    (out / f"{i:03d}-{pathlib.Path(f).name}").write_text(yaml.safe_dump_all(docs, sort_keys=False))
EOF
run kc "$work/manifests"

step "kubeconform: kustomize overlays"
for o in dev staging prod; do
  run kc "$work/kz-$o.yaml"
done
while IFS= read -r k; do
  d=$(dirname "$k")
  echo "-- kustomize build ${d#"$root"/}"
  kustomize build "$d" >"$work/kb.yaml" || { fail "kustomize build $d"; continue; }
  run kc "$work/kb.yaml"
done < <(find "$ex/flux" "$ex/argocd" "$ex/secrets/external-secrets" -name kustomization.yaml 2>/dev/null | sort)

step "Helm"
chart=$root/deploy/helm/scrim
for v in "$ex"/kubernetes/helm/values-*.yaml "$chart/examples/production.yaml"; do
  echo "-- $(basename "$v")"
  run helm lint --strict "$chart" -f "$v"
  helm template scrim "$chart" --namespace scrim -f "$v" >"$work/helm.yaml" ||
    { fail "helm template $v"; continue; }
  run kc "$work/helm.yaml"
  # The config the central Deployment reads: its ConfigMap files, in the
  # order SCRIM_CONFIG gives, checked by the image of this tree with stubs for
  # the mounted Secrets.
  hc=$work/helm-config-$(basename "$v" .yaml)
  mkdir -p "$hc"
  if order=$(python3 -I - "$work/helm.yaml" "$hc" <<'EOF'
import sys, yaml, pathlib
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
dep = next((d for d in docs if d["kind"] == "Deployment"), None)
if dep is None:
    sys.exit(3)
env = {e["name"]: e.get("value") for e in dep["spec"]["template"]["spec"]["containers"][0].get("env", [])}
for d in docs:
    if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-config"):
        for k, val in d.get("data", {}).items():
            pathlib.Path(sys.argv[2], k).write_text(val)
print(env["SCRIM_CONFIG"])
EOF
  ); then
    mkdir -p "$hc-secrets/bao" "$hc-secrets/postgres" "$hc-secrets/admin" "$hc-secrets/metrics"
    cp "$stubs/agents/github-token" "$hc-secrets/bao/token"
    cp "$stubs/pg/dsn" "$hc-secrets/postgres/dsn"
    openssl rand -hex 16 >"$hc-secrets/admin/token"
    openssl rand -hex 32 >"$hc-secrets/metrics/token"
    chmod -R a+rX "$hc" "$hc-secrets"
    echo "-- scrim config validate: $(basename "$v")"
    podman run --rm --read-only --network=none --name "scrim-examples-validate-$$" \
      --tmpfs /run/scrim:rw,mode=0700,U -e XDG_RUNTIME_DIR=/run/scrim -e SCRIM_CONFIG="$order" \
      -v "$hc:/etc/scrim/config:ro,Z" -v "$stubs/ca:/etc/scrim/ca:ro,Z" \
      -v "$stubs/keys:/etc/scrim/placeholder:ro,Z" -v "$hc-secrets:/run/secrets/scrim:ro,Z" \
      "$image" config validate >"$work/validate.out" 2>&1 ||
      { cat "$work/validate.out" >&2; fail "scrim config validate: helm $(basename "$v")"; }
  fi
done

if [ "$failed" -ne 0 ]; then
  echo >&2
  echo "deployment example checks failed" >&2
  exit 1
fi
echo
echo "deployment example checks passed"
