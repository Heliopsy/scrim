#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/cli-tools/install.sh DIR
#
# Installs the command-line tools the tool profile end-to-end test runs into
# DIR/bin at the versions tools.env pins, each release asset refused unless
# its sha256 is the pinned one: gh, kubectl, helm, terraform, tofu, hcloud,
# doctl, the AWS CLI and the Google Cloud CLI, plus azure-cli and twine in a
# virtualenv in DIR/venv. linux/amd64 only, like the CI runner. Prints the
# directory to add to PATH.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
while IFS='=' read -r key value; do
  case "$key" in '' | '#'*) continue ;; esac
  if [ -z "${!key+x}" ]; then export "$key=$value"; fi
done <"$here/tools.env"

[ $# -eq 1 ] || { echo "usage: $0 DIR" >&2; exit 2; }
mkdir -p "$1/bin"
dir=$(cd "$1" && pwd)
bin=$dir/bin
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() {
  local url=$1 want=$2 dest=$3 got
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --connect-timeout 20 --max-time 600 -o "$dest" "$url"
  got=$(sha256sum "$dest" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    rm -f "$dest"
    echo "$url has sha256 $got, pinned $want" >&2
    exit 1
  fi
}

unzip_to() { python3 -I -m zipfile -e "$1" "$2"; }

fetch "https://github.com/cli/cli/releases/download/v$GH_VERSION/gh_${GH_VERSION}_linux_amd64.tar.gz" "$GH_LINUX_AMD64_SHA256" "$tmp/gh.tgz"
tar -xzf "$tmp/gh.tgz" -C "$bin" --strip-components=2 "gh_${GH_VERSION}_linux_amd64/bin/gh"

fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_LINUX_AMD64_SHA256" "$bin/kubectl"
chmod 0755 "$bin/kubectl"

fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_LINUX_AMD64_SHA256" "$tmp/helm.tgz"
tar -xzf "$tmp/helm.tgz" -C "$bin" --strip-components=1 linux-amd64/helm

fetch "https://releases.hashicorp.com/terraform/$TERRAFORM_VERSION/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" "$TERRAFORM_LINUX_AMD64_SHA256" "$tmp/terraform.zip"
unzip_to "$tmp/terraform.zip" "$tmp/terraform"
install -m 0755 "$tmp/terraform/terraform" "$bin/terraform"

fetch "https://github.com/opentofu/opentofu/releases/download/v$TOFU_VERSION/tofu_${TOFU_VERSION}_linux_amd64.tar.gz" "$TOFU_LINUX_AMD64_SHA256" "$tmp/tofu.tgz"
tar -xzf "$tmp/tofu.tgz" -C "$bin" tofu

fetch "https://github.com/hetznercloud/cli/releases/download/$HCLOUD_VERSION/hcloud-linux-amd64.tar.gz" "$HCLOUD_LINUX_AMD64_SHA256" "$tmp/hcloud.tgz"
tar -xzf "$tmp/hcloud.tgz" -C "$bin" hcloud

fetch "https://github.com/digitalocean/doctl/releases/download/v$DOCTL_VERSION/doctl-$DOCTL_VERSION-linux-amd64.tar.gz" "$DOCTL_LINUX_AMD64_SHA256" "$tmp/doctl.tgz"
tar -xzf "$tmp/doctl.tgz" -C "$bin" doctl

fetch "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-$AWSCLI_VERSION.zip" "$AWSCLI_LINUX_AMD64_SHA256" "$tmp/awscli.zip"
unzip_to "$tmp/awscli.zip" "$tmp/awscli"
chmod -R u+x "$tmp/awscli/aws"
"$tmp/awscli/aws/install" --install-dir "$dir/aws-cli" --bin-dir "$bin" --update >/dev/null

fetch "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-$GCLOUD_VERSION-linux-x86_64.tar.gz" "$GCLOUD_LINUX_AMD64_SHA256" "$tmp/gcloud.tgz"
rm -rf "$dir/google-cloud-sdk"
tar -xzf "$tmp/gcloud.tgz" -C "$dir"
ln -sf "$dir/google-cloud-sdk/bin/gcloud" "$bin/gcloud"

python3 -m venv "$dir/venv"
"$dir/venv/bin/pip" install --quiet --disable-pip-version-check "azure-cli==$AZURE_CLI_VERSION" "twine==$TWINE_VERSION"
ln -sf "$dir/venv/bin/az" "$bin/az"
ln -sf "$dir/venv/bin/twine" "$bin/twine"

echo "$bin"
