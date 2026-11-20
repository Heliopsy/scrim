#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Create the three Secrets the raw manifests and the kustomize base mount:
#
#   scrim-keys           placeholder key and approvals signing key, generated here
#   scrim-ca             interception CA (kubernetes.io/tls, PKCS#8 key), generated here
#   scrim-agent-secrets  the secrets scrim redacts, one file each, from SECRETS_DIR
#
#   CONTEXT=my-cluster SECRETS_DIR=~/scrim-agent-secrets ./create-secrets.sh
#
# SECRETS_DIR holds one file per secret, named as the catalog refers to it
# (github-token for files://agents/github-token). Nothing here prints a value,
# and the generated keys are written to a temporary directory that is removed
# on exit. Existing Secrets are left alone: delete one first to replace it.
# Every kubectl call names its context; the current context is never used.
set -euo pipefail

: "${CONTEXT:?set CONTEXT to the kubectl context of the target cluster}"
: "${SECRETS_DIR:?set SECRETS_DIR to a directory with one file per agent secret}"
NAMESPACE=${NAMESPACE:-scrim}

k() { timeout 30 kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@"; }

echo "context: $CONTEXT, namespace: $NAMESPACE"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077

if ! k get secret scrim-keys >/dev/null 2>&1; then
  openssl rand -hex 32 >"$work/placeholder-k1"
  openssl rand -hex 32 >"$work/approvals-signing-key"
  k create secret generic scrim-keys \
    --from-file=placeholder-k1="$work/placeholder-k1" \
    --from-file=approvals-signing-key="$work/approvals-signing-key"
fi

if ! k get secret scrim-ca >/dev/null 2>&1; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$work/tls.key" -out "$work/tls.crt" -days 730 \
    -subj "/O=scrim/CN=scrim interception CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" 2>/dev/null
  k create secret tls scrim-ca --cert="$work/tls.crt" --key="$work/tls.key"
fi

if ! k get secret scrim-agent-secrets >/dev/null 2>&1; then
  k create secret generic scrim-agent-secrets --from-file="$SECRETS_DIR"
fi
