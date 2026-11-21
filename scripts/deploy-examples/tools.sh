#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/deploy-examples/tools.sh DIR
#
# Installs the tools the deployment example checks need into DIR/bin, at the
# versions tools.env pins, each refused unless its sha256 is the pinned one:
# helm, kustomize, kubeconform, cosign, a scrim release (verified with that
# cosign against the release workflow's identity), and a Python virtualenv in
# DIR/venv with ansible-lint, ansible-core and podman-compose from
# deploy/examples/ansible/requirements-lint.txt, installed with
# --require-hashes. linux/amd64 only, like the CI runner. The virtualenv is
# made with $PYTHON (default python3), which must be Python 3.13 or later
# (ansible-core's floor); CI sets up the version requirements-lint.txt was
# compiled for.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
while IFS='=' read -r key value; do
  case "$key" in '' | '#'*) continue ;; esac
  if [ -z "${!key+x}" ]; then export "$key=$value"; fi
done <"$here/tools.env"

[ $# -eq 1 ] || { echo "usage: $0 DIR" >&2; exit 2; }
mkdir -p "$1/bin"
dir=$(cd "$1" && pwd)
bin=$dir/bin

fetch() {
  local url=$1 want=$2 dest=$3 got
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --connect-timeout 20 --max-time 300 -o "$dest" "$url"
  got=$(sha256sum "$dest" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    rm -f "$dest"
    echo "$url has sha256 $got, pinned $want" >&2
    exit 1
  fi
}

have() { [ -x "$bin/$1" ] && [ -f "$bin/.$1-$2" ]; }
mark() { rm -f "$bin/.$1-"*; touch "$bin/.$1-$2"; }

if ! have helm "$HELM_VERSION"; then
  fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_LINUX_AMD64_SHA256" "$dir/helm.tgz"
  tar -xzf "$dir/helm.tgz" -C "$bin" --strip-components=1 linux-amd64/helm
  rm -f "$dir/helm.tgz"
  mark helm "$HELM_VERSION"
fi

if ! have kustomize "$KUSTOMIZE_VERSION"; then
  fetch "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F$KUSTOMIZE_VERSION/kustomize_${KUSTOMIZE_VERSION}_linux_amd64.tar.gz" \
    "$KUSTOMIZE_LINUX_AMD64_SHA256" "$dir/kustomize.tgz"
  tar -xzf "$dir/kustomize.tgz" -C "$bin" kustomize
  rm -f "$dir/kustomize.tgz"
  mark kustomize "$KUSTOMIZE_VERSION"
fi

if ! have kubeconform "$KUBECONFORM_VERSION"; then
  fetch "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" \
    "$KUBECONFORM_LINUX_AMD64_SHA256" "$dir/kubeconform.tgz"
  tar -xzf "$dir/kubeconform.tgz" -C "$bin" kubeconform
  rm -f "$dir/kubeconform.tgz"
  mark kubeconform "$KUBECONFORM_VERSION"
fi

if ! have cosign "$COSIGN_VERSION"; then
  fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64" \
    "$COSIGN_LINUX_AMD64_SHA256" "$bin/cosign"
  chmod 0755 "$bin/cosign"
  mark cosign "$COSIGN_VERSION"
fi

# The release itself, through the same steps a user follows
# (deploy/examples/workstation/install.sh), with the pinned cosign.
if ! have scrim "$SCRIM_VERSION"; then
  PATH="$bin:$PATH" VERSION="$SCRIM_VERSION" OS=linux ARCH=amd64 PREFIX="$dir" \
    bash "$root/deploy/examples/workstation/install.sh" >/dev/null
  rm -f "$bin/scrim.prev"
  mark scrim "$SCRIM_VERSION"
fi

req=$root/deploy/examples/ansible/requirements-lint.txt
stamp=$(sha256sum "$req" | cut -c1-16)
if ! [ -f "$dir/venv/.req-$stamp" ]; then
  py=${PYTHON:-python3}
  "$py" -I -c 'import sys; sys.exit(sys.version_info < (3, 13))' ||
    { echo "$py is older than Python 3.13; set PYTHON to a newer interpreter" >&2; exit 1; }
  rm -rf "$dir/venv"
  "$py" -m venv "$dir/venv"
  "$dir/venv/bin/pip" install --quiet --disable-pip-version-check --no-deps --require-hashes -r "$req"
  touch "$dir/venv/.req-$stamp"
fi

echo "tools in $bin and $dir/venv/bin"
