# Installing scrim

scrim ships as one file per platform: the `scrim` binary is the Go control plane with the Rust data
plane embedded, and runs the data plane as a child process (design D11). The data plane is also
published on its own as `scrim-dataplane`, for Kubernetes sidecars and edge forwarders.

| Platform | Archive |
| --- | --- |
| Linux x86-64 | `scrim_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `scrim_<version>_linux_arm64.tar.gz` |
| macOS Intel | `scrim_<version>_darwin_amd64.tar.gz` |
| macOS Apple | `scrim_<version>_darwin_arm64.tar.gz` |

The Linux binaries are statically linked and need nothing from the host but the kernel. The macOS
binaries need only the base system. `scrim-dataplane_<version>_<os>_<arch>.tar.gz` holds the data
plane alone for the same four platforms.

Images, both multi-arch (linux/amd64, linux/arm64), distroless, non-root (UID 65532):

- `ghcr.io/heliopsy/scrim`
- `ghcr.io/heliopsy/scrim-dataplane`

Image tags are the version without the `v` (`0.1.0`), the minor series (`0.1`) and `latest`.
Pre-releases (`0.2.0-rc.1`) are tagged with their exact version only and never move `latest` or
the minor series.

## What every release carries

| File | What it is |
| --- | --- |
| `*.tar.gz` | the binary, `LICENSE` and `README.md` |
| `*.tar.gz.spdx.json` | SPDX SBOM of that archive, Go and Rust dependencies both |
| `checksums.txt` | SHA-256 of every archive and SBOM |
| `checksums.txt.sigstore.json` | Sigstore bundle: keyless cosign signature over `checksums.txt` |

Every archive and SBOM also has a SLSA build provenance attestation, stored with the repository on
GitHub. Each image is signed with cosign, has an SBOM attestation per architecture, and a build
provenance attestation in the registry.

Signatures are keyless. There is no key to download: the signing certificate is issued by Sigstore
to the release workflow `.github/workflows/release.yaml` of `Heliopsy/scrim` through GitHub's OIDC
token, and the signature is recorded in the public Rekor transparency log. Verifying means checking
that identity.

## Download and verify a binary

Needs `curl`, [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) 2.4 or later,
and optionally the [GitHub CLI](https://cli.github.com/) for the provenance check.

```sh
VERSION=0.1.0
OS=linux        # linux or darwin
ARCH=amd64      # amd64 or arm64
BASE=https://github.com/Heliopsy/scrim/releases/download/v$VERSION

curl -fsSLO "$BASE/scrim_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sigstore.json"
```

1. Check that the checksums file was signed by the scrim release workflow:

   ```sh
   cosign verify-blob \
     --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   ```

   It prints `Verified OK`. The identity names the workflow file and the ref it ran from: the
   release tag when a tag was pushed, `main` when release-please started the build.

2. Check the archive against the signed checksums:

   ```sh
   sha256sum --check --ignore-missing checksums.txt
   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
   ```

3. Check the build provenance, which ties the archive to the commit and workflow run that built it:

   ```sh
   gh attestation verify "scrim_${VERSION}_${OS}_${ARCH}.tar.gz" \
     --repo Heliopsy/scrim \
     --signer-workflow Heliopsy/scrim/.github/workflows/release.yaml
   ```

   Without the GitHub CLI, download the attestation bundle and use cosign:

   ```sh
   DIGEST=$(sha256sum "scrim_${VERSION}_${OS}_${ARCH}.tar.gz" | cut -d' ' -f1)
   curl -fsSL "https://api.github.com/repos/Heliopsy/scrim/attestations/sha256:$DIGEST" \
     | jq '.attestations[0].bundle' > provenance.sigstore.json
   cosign verify-blob-attestation \
     --bundle provenance.sigstore.json \
     --new-bundle-format \
     --type slsaprovenance1 \
     --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     "scrim_${VERSION}_${OS}_${ARCH}.tar.gz"
   ```

4. Unpack and run:

   ```sh
   tar -xzf "scrim_${VERSION}_${OS}_${ARCH}.tar.gz" ./scrim
   install -m 0755 scrim ~/.local/bin/scrim
   scrim version
   ```

   On macOS a file downloaded by a browser carries the quarantine attribute; the binaries are not
   notarised yet. After verifying, clear it with `xattr -d com.apple.quarantine scrim`. A download
   with `curl` is not quarantined.

The SBOM for an archive is `scrim_${VERSION}_${OS}_${ARCH}.tar.gz.spdx.json`, covered by the same
signed checksums. It lists the Go modules of the control plane and the Rust crates of the embedded
data plane.

## Container images

Verify before running. The signature, the SBOM attestation and the provenance are all checked
against the registry:

```sh
IMAGE=ghcr.io/heliopsy/scrim:0.1.0
ID='^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v.+)$'
ISSUER=https://token.actions.githubusercontent.com

# Signature over the multi-arch index (each architecture's manifest is signed too).
cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" "$IMAGE"

# SLSA build provenance of the index.
gh attestation verify "oci://$IMAGE" --repo Heliopsy/scrim
```

Each architecture has its own SBOM, attested to that architecture's manifest rather than to the
index, so look its digest up first:

```sh
ARCH=amd64   # or arm64
CHILD=$(skopeo inspect --raw "docker://$IMAGE" \
  | jq -r --arg a "$ARCH" '.manifests[] | select(.platform.architecture == $a) | .digest')
cosign verify-attestation --type spdxjson \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" \
  "${IMAGE%:*}@$CHILD" | jq -r .payload | base64 -d | jq .predicate
```

The image SBOM lists the base image's packages and the Go modules of `scrim`. The Rust crates of
the embedded data plane are in the SBOM of the matching release archive.

For deployments, pull by the digest `cosign verify` printed rather than by tag.

Run with rootless podman. The image works with a read-only root filesystem; state goes to the volume
at `/var/lib/scrim`, and a config file is read from `/etc/scrim/config.yaml`:

```sh
podman volume create scrim-state
podman run --rm \
  --read-only \
  --cap-drop=all --security-opt=no-new-privileges \
  -v scrim-state:/var/lib/scrim \
  -v ./config.yaml:/etc/scrim/config.yaml:ro,Z \
  -p 127.0.0.1:9790:9790 \
  ghcr.io/heliopsy/scrim:0.1.0 version
```

Use a named volume rather than a host directory: rootless podman maps the container's UID 65532 to
a subordinate UID that cannot write a directory owned by your user.

`scrim` starts its data plane from memory (`memfd_create`). Where the kernel forbids executing
memfds (`vm.memfd_noexec=2`), it falls back to a hash-checked file under `$XDG_RUNTIME_DIR`; give it
a tmpfs then, for example `--tmpfs /run/scrim:rw,exec,mode=0700,uid=65532 -e XDG_RUNTIME_DIR=/run/scrim`.

The data plane image runs stateless and needs no volume:

```sh
podman run --rm --read-only --cap-drop=all ghcr.io/heliopsy/scrim-dataplane:0.1.0 --version
```

## Build from source

Needs Go and Rust at the versions in `go.mod` and `rust-toolchain.toml`, `git`, GNU `tar`, and for a
release-identical build `cargo-auditable` (`cargo install --locked cargo-auditable`). Linux builds
target musl; on Debian and Ubuntu install `musl-tools`.

```sh
git clone https://github.com/Heliopsy/scrim
cd scrim
git checkout v0.1.0
just release-build linux-amd64       # dist/bin/linux-amd64/{scrim,scrim-dataplane}
```

`just release-build` runs `scripts/release/dataplane.sh` for the platform, then
`scripts/release/controlplane.sh`, which embeds that data plane into the Go build. The scripts are
what the release workflow runs, so the binaries are byte-identical to the released ones when built
from the tag on the same platform with the same toolchains. The release pipeline itself checks this
on every release by rebuilding linux-amd64 on a second runner and comparing.

To compare a local build with a release:

```sh
just release-build linux-amd64
tar -xzf "scrim_0.1.0_linux_amd64.tar.gz" -O ./scrim | sha256sum
sha256sum dist/bin/linux-amd64/scrim
```

Container images are assembled from the built binaries, never compiled inside the container, so
they too are reproducible from the same binaries:

```sh
just release-build linux-amd64 linux-arm64   # arm64 needs an arm64 host or a cross linker
just release-image scrim                     # localhost/scrim-rel/scrim:<version>
```
