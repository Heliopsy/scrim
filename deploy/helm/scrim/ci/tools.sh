#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# ci/tools.sh DIR [HELM_MAJOR]
#
# Installs the chart's test tools, pinned by version and sha256, into DIR/bin
# (and the helm-unittest plugin into DIR/helm-plugins): helm (major 3 or 4,
# default 4), kubeconform, helm-docs, ct with its lint configuration, kind,
# kubectl and promtool. CI and a laptop use the same versions. Prints the
# lines to export. Renovate bumps the versions (the renovate: comments);
# `just pin-sums` then rewrites each checksum from the asset its sha256: line
# names.
set -euo pipefail

dir=${1:?usage: $0 DIR [HELM_MAJOR]}
major=${2:-4}
mkdir -p "$dir/bin" "$dir/dl" "$dir/helm-plugins"
dir=$(cd "$dir" && pwd)

# renovate: datasource=github-releases depName=helm/helm
HELM3_VERSION=v3.22.1
# sha256: https://get.helm.sh/helm-{version}-linux-amd64.tar.gz
HELM3_SHA256=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea
# renovate: datasource=github-releases depName=helm/helm
HELM4_VERSION=v4.3.2
# sha256: https://get.helm.sh/helm-{version}-linux-amd64.tar.gz
HELM4_SHA256=d1c0278d46beab79582d7e50f5b3dc206944ba8e577cde618513fd07daa53983
# renovate: datasource=github-releases depName=yannh/kubeconform
KUBECONFORM_VERSION=v0.8.0
# sha256: https://github.com/yannh/kubeconform/releases/download/{version}/kubeconform-linux-amd64.tar.gz
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
# renovate: datasource=github-releases depName=norwoodj/helm-docs extractVersion=^v(?<version>.+)$
HELM_DOCS_VERSION=1.14.2
# sha256: https://github.com/norwoodj/helm-docs/releases/download/v{version}/helm-docs_{version}_Linux_x86_64.tar.gz
HELM_DOCS_SHA256=a8cf72ada34fad93285ba2a452b38bdc5bd52cc9a571236244ec31022928d6cc
# renovate: datasource=github-releases depName=helm/chart-testing extractVersion=^v(?<version>.+)$
CT_VERSION=3.15.0
# sha256: https://github.com/helm/chart-testing/releases/download/v{version}/chart-testing_{version}_linux_amd64.tar.gz
CT_SHA256=467561730f25fe09d5e6cd09a3e1f6aa759871c657a57602947c716d9be2c583
# renovate: datasource=github-releases depName=kubernetes-sigs/kind
KIND_VERSION=v0.33.0
# sha256: https://github.com/kubernetes-sigs/kind/releases/download/{version}/kind-linux-amd64
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
# The cluster version verify.sh validates against (K8S_VERSION) and kind runs.
# renovate: datasource=github-releases depName=kubernetes/kubernetes
KUBECTL_VERSION=v1.37.2
# sha256: https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
# Same release as scripts/monitoring-check.sh.
# renovate: datasource=github-releases depName=prometheus/prometheus extractVersion=^v(?<version>.+)$
PROMETHEUS_VERSION=3.16.0
# sha256: https://github.com/prometheus/prometheus/releases/download/v{version}/prometheus-{version}.linux-amd64.tar.gz
PROMETHEUS_SHA256=68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34
# renovate: datasource=github-releases depName=helm-unittest/helm-unittest extractVersion=^v(?<version>.+)$
HELM_UNITTEST_VERSION=1.2.1
# sha256: https://github.com/helm-unittest/helm-unittest/releases/download/v{version}/helm-unittest-linux-amd64-{version}.tgz
HELM_UNITTEST_SHA256=48e86ecc1467b009630e5954375e5d8494139f73b466df5fe8c04fa45b634939

[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "ci/tools.sh: linux-amd64 only" >&2; exit 1; }

fetch() { # URL SHA256 FILE
  local f="$dir/dl/$3"
  [ -f "$f" ] && echo "$2  $f" | sha256sum -c --quiet - 2>/dev/null && return 0
  curl -fsSL --retry 5 -o "$f" "$1"
  echo "$2  $f" | sha256sum -c --quiet - || { echo "ci/tools.sh: checksum mismatch for $1" >&2; rm -f "$f"; exit 1; }
}

case "$major" in
  3) hv=$HELM3_VERSION hs=$HELM3_SHA256 ;;
  4) hv=$HELM4_VERSION hs=$HELM4_SHA256 ;;
  *) echo "ci/tools.sh: helm major $major" >&2; exit 2 ;;
esac
fetch "https://get.helm.sh/helm-$hv-linux-amd64.tar.gz" "$hs" "helm-$hv.tgz"
tar -xzf "$dir/dl/helm-$hv.tgz" -C "$dir/bin" --strip-components=1 linux-amd64/helm

fetch "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" \
  "$KUBECONFORM_SHA256" kubeconform.tgz
tar -xzf "$dir/dl/kubeconform.tgz" -C "$dir/bin" kubeconform

fetch "https://github.com/norwoodj/helm-docs/releases/download/v$HELM_DOCS_VERSION/helm-docs_${HELM_DOCS_VERSION}_Linux_x86_64.tar.gz" \
  "$HELM_DOCS_SHA256" helm-docs.tgz
tar -xzf "$dir/dl/helm-docs.tgz" -C "$dir/bin" helm-docs

fetch "https://github.com/helm/chart-testing/releases/download/v$CT_VERSION/chart-testing_${CT_VERSION}_linux_amd64.tar.gz" \
  "$CT_SHA256" ct.tgz
mkdir -p "$dir/ct"
tar -xzf "$dir/dl/ct.tgz" -C "$dir/ct" ct etc/chart_schema.yaml etc/lintconf.yaml
mv "$dir/ct/ct" "$dir/bin/ct"

fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$KIND_SHA256" kind
install -m 0755 "$dir/dl/kind" "$dir/bin/kind"

fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" kubectl
install -m 0755 "$dir/dl/kubectl" "$dir/bin/kubectl"

fetch "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/prometheus-$PROMETHEUS_VERSION.linux-amd64.tar.gz" \
  "$PROMETHEUS_SHA256" prometheus.tgz
tar -xzf "$dir/dl/prometheus.tgz" -C "$dir/bin" --strip-components=1 "prometheus-$PROMETHEUS_VERSION.linux-amd64/promtool"

# The plugin's release tarball, unpacked where HELM_PLUGINS points: the same
# for Helm 3 and 4, and no `helm plugin install` from a git checkout.
fetch "https://github.com/helm-unittest/helm-unittest/releases/download/v$HELM_UNITTEST_VERSION/helm-unittest-linux-amd64-$HELM_UNITTEST_VERSION.tgz" \
  "$HELM_UNITTEST_SHA256" helm-unittest.tgz
rm -rf "$dir/helm-plugins/unittest" && mkdir -p "$dir/helm-plugins/unittest"
tar -xzf "$dir/dl/helm-unittest.tgz" -C "$dir/helm-plugins/unittest"

echo "export PATH=$dir/bin:\$PATH HELM_PLUGINS=$dir/helm-plugins CT_ETC=$dir/ct/etc"
