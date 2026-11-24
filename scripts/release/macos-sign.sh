#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/macos-sign.sh COMMAND [ARG...]
#
# Signs the darwin binaries with a Developer ID Application certificate and
# has Apple notarise them. The release workflow runs it on GitHub's macOS
# runner in jobs that build nothing; a maintainer with the certificate in a
# keychain can run the same steps on a Mac.
#
#   configured            prints true when every signing input is set, false
#                         when none is, and fails naming the missing ones when
#                         only some are
#   keychain              imports the certificate into a temporary keychain
#                         and prints the signing identity
#   sign IDENTITY FILE... codesign each FILE (hardened runtime, secure
#                         timestamp) and verify the signature
#   notarize FILE...      submits FILEs in one zip to the notary service,
#                         waits for the verdict and fails unless Accepted
#   cleanup               deletes the temporary keychain and key files
#
# Inputs, from the environment (repository secrets in the workflow; see
# docs/install.md, "For maintainers: macOS signing and notarisation"):
#
#   APPLE_DEVELOPER_ID_P12           base64 of the .p12 holding the Developer ID
#                                    Application certificate and its private key
#   APPLE_DEVELOPER_ID_P12_PASSWORD  the .p12's password
#   APPLE_NOTARY_API_KEY             base64 of the App Store Connect API key (.p8)
#   APPLE_NOTARY_API_KEY_ID          that key's ID
#   APPLE_NOTARY_API_ISSUER_ID       the issuer ID of the App Store Connect team
#
# Bare Mach-O binaries cannot carry a stapled ticket; Gatekeeper looks the
# notarisation up online the first time a downloaded binary runs.
set -euo pipefail

inputs=(APPLE_DEVELOPER_ID_P12 APPLE_DEVELOPER_ID_P12_PASSWORD APPLE_NOTARY_API_KEY
  APPLE_NOTARY_API_KEY_ID APPLE_NOTARY_API_ISSUER_ID)
work=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/scrim-macos-sign
keychain=$work/signing.keychain-db

die() {
  echo "error: $*" >&2
  exit 1
}

case "${1:-}" in
  configured)
    set_=() missing=()
    for v in "${inputs[@]}"; do
      if [ -n "${!v:-}" ]; then set_+=("$v"); else missing+=("$v"); fi
    done
    if [ ${#set_[@]} -eq 0 ]; then
      echo false
    elif [ ${#missing[@]} -eq 0 ]; then
      echo true
    else
      die "macOS signing is half configured: set ${missing[*]} as well, or remove ${set_[*]}"
    fi
    ;;

  keychain)
    mkdir -p "$work"
    chmod 0700 "$work"
    pass=$(openssl rand -hex 24)
    printf '%s' "$APPLE_DEVELOPER_ID_P12" | base64 --decode >"$work/cert.p12"
    security create-keychain -p "$pass" "$keychain"
    security set-keychain-settings -lut 3600 "$keychain"
    security unlock-keychain -p "$pass" "$keychain"
    security import "$work/cert.p12" -k "$keychain" -f pkcs12 \
      -P "$APPLE_DEVELOPER_ID_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
    rm -f "$work/cert.p12"
    security set-key-partition-list -S apple-tool:,apple: -s -k "$pass" "$keychain" >/dev/null
    # codesign searches the user's keychain list; the temporary one goes first.
    # shellcheck disable=SC2046
    security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')
    ids=$(security find-identity -v -p codesigning "$keychain" | sed -n 's/.*"\(Developer ID Application: .*\)"$/\1/p' | sort -u)
    [ -n "$ids" ] || die "APPLE_DEVELOPER_ID_P12 holds no valid Developer ID Application identity"
    [ "$(printf '%s\n' "$ids" | wc -l | tr -d ' ')" = 1 ] || die "APPLE_DEVELOPER_ID_P12 holds more than one Developer ID Application identity"
    printf '%s\n' "$ids"
    ;;

  sign)
    [ $# -ge 3 ] || die "usage: $0 sign IDENTITY FILE..."
    identity=$2
    shift 2
    for f in "$@"; do
      codesign --force --options runtime --timestamp --keychain "$keychain" --sign "$identity" "$f"
      codesign --verify --strict --verbose=2 "$f"
      codesign --display --verbose=2 "$f" 2>&1 | grep -E '^(Authority|TeamIdentifier|Timestamp|Runtime)' >&2 || true
    done
    ;;

  notarize)
    [ $# -ge 2 ] || die "usage: $0 notarize FILE..."
    shift
    mkdir -p "$work/zip"
    chmod 0700 "$work"
    printf '%s' "$APPLE_NOTARY_API_KEY" | base64 --decode >"$work/notary.p8"
    for f in "$@"; do
      cp "$f" "$work/zip/$(basename "$(dirname "$f")")-$(basename "$f")"
    done
    ditto -c -k "$work/zip" "$work/submit.zip"
    out=$(xcrun notarytool submit "$work/submit.zip" --wait --timeout 30m --output-format json \
      --key "$work/notary.p8" --key-id "$APPLE_NOTARY_API_KEY_ID" --issuer "$APPLE_NOTARY_API_ISSUER_ID")
    echo "$out" >&2
    status=$(printf '%s' "$out" | plutil -extract status raw -o - - 2>/dev/null || true)
    id=$(printf '%s' "$out" | plutil -extract id raw -o - - 2>/dev/null || true)
    if [ "$status" != Accepted ]; then
      [ -z "$id" ] || xcrun notarytool log "$id" --key "$work/notary.p8" \
        --key-id "$APPLE_NOTARY_API_KEY_ID" --issuer "$APPLE_NOTARY_API_ISSUER_ID" >&2 || true
      die "notarisation ended with status '${status:-unknown}'"
    fi
    echo "notarised: submission $id" >&2
    ;;

  cleanup)
    security delete-keychain "$keychain" 2>/dev/null || true
    rm -rf "$work"
    ;;

  *) die "usage: $0 configured|keychain|sign|notarize|cleanup" ;;
esac
