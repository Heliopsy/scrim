# Installing scrim

scrim ships as one file per platform: the `scrim` binary is the Go control plane with the Rust data
plane embedded, and runs the data plane as a child process (design D11). The data plane is also
published on its own as `scrim-dataplane`, for Kubernetes sidecars.

| Platform | Archive |
| --- | --- |
| Linux x86-64 | `scrim_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `scrim_<version>_linux_arm64.tar.gz` |
| macOS Intel | `scrim_<version>_darwin_amd64.tar.gz` |
| macOS Apple | `scrim_<version>_darwin_arm64.tar.gz` |
| Windows x86-64 | `scrim_<version>_windows_amd64.tar.gz` |
| Windows arm64 | `scrim_<version>_windows_arm64.tar.gz` |

The Linux binaries are statically linked and need nothing from the host but the kernel. The macOS
binaries need only the base system. The Windows binaries (`scrim.exe`) need Windows 10 version 1809
or Windows Server 2019 or later (for Unix sockets) and nothing else: the C runtime is linked in.
Windows supports less than Linux and macOS; see [Windows](#windows) below.
`scrim-dataplane_<version>_<os>_<arch>.tar.gz` holds the data plane alone for the same six
platforms.

Images, both multi-arch (linux/amd64, linux/arm64), distroless, non-root (UID 65532):

- `ghcr.io/heliopsy/scrim`
- `ghcr.io/heliopsy/scrim-dataplane`

Image tags are the version without the `v` (`1.0.0`), the minor series (`1.0`) and `latest`.
Pre-releases (`1.1.0-rc.1`) are tagged with their exact version only and never move `latest` or
the minor series.

## What every release carries

| File | What it is |
| --- | --- |
| `*.tar.gz` | the binary, `LICENSE` and `README.md` |
| `*.tar.gz.spdx.json` | SPDX SBOM of that archive, Go and Rust dependencies both |
| `scrim_<version>_results*` | the release's leak and performance results ([below](#check-the-published-results)) |
| `checksums.txt` | SHA-256 of every archive, SBOM and result file |
| `checksums.txt.sigstore.json` | Sigstore bundle: keyless cosign signature over `checksums.txt` |

Every archive, SBOM and result file also has a SLSA build provenance attestation, stored with the repository on
GitHub. Each image is signed with cosign, has an SBOM attestation per architecture, and a build
provenance attestation in the registry.

Signatures are keyless. There is no key to download: the signing certificate is issued by Sigstore
to the release workflow `.github/workflows/release.yaml` of `Heliopsy/scrim` through GitHub's OIDC
token, and the signature is recorded in the public Rekor transparency log. Verifying means checking
that identity.

## Download and verify a binary

Needs `curl`, [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) 2.4 or later,
and optionally the [GitHub CLI](https://cli.github.com/) for the provenance check.

<!-- docs-test: skip: downloads a published release from GitHub -->

```sh
VERSION=1.0.0
OS=linux        # linux, darwin or windows (see Windows below)
ARCH=amd64      # amd64 or arm64
BASE=https://github.com/Heliopsy/scrim/releases/download/v$VERSION

curl -fsSLO "$BASE/scrim_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.sigstore.json"
```

1. Check that the checksums file was signed by the scrim release workflow:

   <!-- docs-test: skip: verifies the downloaded release online with Sigstore -->

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

   <!-- docs-test: skip: needs the downloaded release files -->

   ```sh
   sha256sum --check --ignore-missing checksums.txt
   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
   ```

3. Check the build provenance, which ties the archive to the commit and workflow run that built it:

   <!-- docs-test: skip: verifies the downloaded release online with the GitHub CLI -->

   ```sh
   gh attestation verify "scrim_${VERSION}_${OS}_${ARCH}.tar.gz" \
     --repo Heliopsy/scrim \
     --signer-workflow Heliopsy/scrim/.github/workflows/release.yaml
   ```

   Without the GitHub CLI, download the attestation bundle and use cosign:

   <!-- docs-test: skip: downloads the attestation of the release from GitHub -->

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

   <!-- docs-test: skip: unpacks the downloaded release into ~/.local/bin -->

   ```sh
   tar -xzf "scrim_${VERSION}_${OS}_${ARCH}.tar.gz" ./scrim
   install -m 0755 scrim ~/.local/bin/scrim
   scrim version
   ```

   To run it as a service (a systemd user or system unit, or a Quadlet container), see
   [service.md](service.md): `scrim install --user` or `sudo scrim install --system`.

   The macOS binaries are signed with a Developer ID and notarised by Apple when the release says
   so; the release notes of a release whose darwin binaries are not notarised say that. Check a
   binary with `codesign --verify --strict --verbose=2 scrim` (it names the Developer ID) and
   `spctl --assess --type execute -vv scrim`. A binary that is not notarised and was downloaded by a
   browser carries the quarantine attribute: after verifying it as above, clear it with
   `xattr -d com.apple.quarantine scrim`. A download with `curl` is not quarantined.

The SBOM for an archive is `scrim_${VERSION}_${OS}_${ARCH}.tar.gz.spdx.json`, covered by the same
signed checksums. It lists the Go modules of the control plane and the Rust crates of the embedded
data plane.

## Windows

Download and verify the archive the same way, from Git Bash or WSL with the commands above
(`OS=windows`), or from PowerShell with `cosign.exe` and the GitHub CLI:

<!-- docs-test: skip: PowerShell on Windows, downloads a published release -->

```powershell
$VERSION = "1.0.0"; $ARCH = "amd64"   # or arm64
$BASE = "https://github.com/Heliopsy/scrim/releases/download/v$VERSION"
$ARCHIVE = "scrim_${VERSION}_windows_${ARCH}.tar.gz"
foreach ($f in $ARCHIVE, "checksums.txt", "checksums.txt.sigstore.json") {
  Invoke-WebRequest -Uri "$BASE/$f" -OutFile $f
}
cosign verify-blob --bundle checksums.txt.sigstore.json `
  --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
$want = (Select-String -Path checksums.txt -Pattern "  $ARCHIVE$").Line.Split(" ")[0]
if ((Get-FileHash $ARCHIVE -Algorithm SHA256).Hash.ToLower() -ne $want) { throw "checksum mismatch" }
gh attestation verify $ARCHIVE --repo Heliopsy/scrim --signer-workflow Heliopsy/scrim/.github/workflows/release.yaml
tar -xzf $ARCHIVE scrim.exe
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\Programs\scrim" | Out-Null
Move-Item -Force scrim.exe "$env:LOCALAPPDATA\Programs\scrim\scrim.exe"
& "$env:LOCALAPPDATA\Programs\scrim\scrim.exe" version
```

`tar` is part of Windows 10 and later. Add `%LOCALAPPDATA%\Programs\scrim` to your user `Path` to
run `scrim` from any shell. The Windows binaries are not Authenticode-signed, so SmartScreen may warn
about a file downloaded by a browser; the signed checksums and the provenance are what tie it to
the release.

What runs on Windows:

- `scrim proxy` (the daemon) with its embedded data plane, the stores, the policy and approvals,
  the agent API and `scrim mcp`.
- `scrim run` with the base URL and forward proxy modes, session tokens and the CA trust variables.
  Start it from a shell; there is no `scrim install` service unit on Windows yet.

Where scrim keeps its files: when `HOME` is unset, scrim uses `%USERPROFILE%` for it, so the
configuration is `%USERPROFILE%\.config\scrim\config.yaml` and state is under
`%USERPROFILE%\.local\state\scrim` (set `XDG_CONFIG_HOME` or `XDG_STATE_HOME` to move them).
Sockets go to `%TEMP%\scrim` and the unpacked data plane to `%LOCALAPPDATA%\scrim`. Directories
scrim creates for keys and state get a DACL that grants only you, SYSTEM and Administrators, and
scrim refuses a key or state directory whose DACL grants any other account. Settings that need Unix
make scrim refuse to start, each named; [limitations.md](limitations.md#platforms) lists them.

## Check the published results

Each release attaches the leak and performance results measured on the commit it was built from,
with the linux-amd64 binaries it ships: the leak suite report, the end-to-end matrix, fuzzing time,
the latency gate and the redaction benchmarks.
[leak-assurance.md](leak-assurance.md#published-results) says what each file holds and which
failures stop a release; `scrim_<version>_results.md` is the summary to read first.

They are covered by the same signed `checksums.txt` and have the same provenance as the archives, so
they are checked the same way. With `VERSION`, `BASE` and the verified `checksums.txt` from above:

<!-- docs-test: skip: downloads the results of a published release from GitHub -->

```sh
for f in $(grep -o "scrim_${VERSION}_results[^ ]*" checksums.txt); do
  curl -fsSLO "$BASE/$f"
done
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "scrim_${VERSION}_results.md" \
  --repo Heliopsy/scrim \
  --signer-workflow Heliopsy/scrim/.github/workflows/release.yaml
```

Then check the outcome yourself rather than trusting the summary:

<!-- docs-test: skip: needs the downloaded result files -->

```sh
jq '{pass, summary}' "scrim_${VERSION}_results_leak-report.json"
jq -r '.[] | "\(.cell) \(.pass) gated_leaks=\(.gated_leaks)"' "scrim_${VERSION}_results_e2e-matrix.json"
```

To produce the same files on your own machine, run `scripts/release/results.sh` from a checkout of
the tag (its header lists the commands); the latency numbers will be those of your machine.

## Container images

Verify before running. The signature, the SBOM attestation and the provenance are all checked
against the registry:

<!-- docs-test: skip: verifies the published image online -->

```sh
IMAGE=ghcr.io/heliopsy/scrim:1.0.0
ID='^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v.+)$'
ISSUER=https://token.actions.githubusercontent.com

# Signature over the multi-arch index (each architecture's manifest is signed too).
cosign verify --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" "$IMAGE"

# SLSA build provenance of the index.
gh attestation verify "oci://$IMAGE" --repo Heliopsy/scrim
```

Each architecture has its own SBOM, attested to that architecture's manifest rather than to the
index, so look its digest up first:

<!-- docs-test: skip: reads the published image from ghcr.io -->

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

<!-- docs-test: skip: runs the published image -->

```sh
podman volume create scrim-state
podman run --rm \
  --read-only \
  --cap-drop=all --security-opt=no-new-privileges \
  -v scrim-state:/var/lib/scrim \
  -v ./config.yaml:/etc/scrim/config.yaml:ro,Z \
  -p 127.0.0.1:9790:9790 \
  ghcr.io/heliopsy/scrim:1.0.0 version
```

Use a named volume rather than a host directory: rootless podman maps the container's UID 65532 to
a subordinate UID that cannot write a directory owned by your user.

`scrim` starts its data plane from memory (`memfd_create`). Where the kernel forbids executing
memfds (`vm.memfd_noexec=2`), it falls back to a hash-checked file under `$XDG_RUNTIME_DIR`; give it
a tmpfs owned by the container user then, for example
`--tmpfs /run/scrim:rw,exec,mode=0700,U -e XDG_RUNTIME_DIR=/run/scrim` (`U` chowns it to the
container user; podman 4.9 rejects `uid=`).

To run the image as a service, `scrim install --quadlet` writes a Quadlet unit for it
([service.md](service.md)).

The data plane image runs stateless and needs no volume:

<!-- docs-test: skip: runs the published image -->

```sh
podman run --rm --read-only --cap-drop=all ghcr.io/heliopsy/scrim-dataplane:1.0.0 --version
```

## For maintainers: macOS signing and notarisation

The release workflow signs and notarises the darwin binaries when five repository secrets are set
(Settings, Secrets and variables, Actions, Repository secrets). With none set, the release still
publishes; its darwin binaries are unsigned, the workflow prints a notice, and the release notes say
they are not notarised. With only some set, the release fails and names the missing ones. Only the
two macOS signing jobs, which build nothing, receive them.

| Secret | What it holds |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12` | base64 of a `.p12` file with the **Developer ID Application** certificate and its private key |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | the password the `.p12` was exported with |
| `APPLE_NOTARY_API_KEY` | base64 of the App Store Connect API key file (`AuthKey_<KEYID>.p8`) |
| `APPLE_NOTARY_API_KEY_ID` | that key's ID (10 characters, shown next to the key) |
| `APPLE_NOTARY_API_ISSUER_ID` | the issuer ID shown above the key list (a UUID) |

To create them (needs an Apple Developer Program membership; the Account Holder creates the
certificate):

1. On a Mac, Keychain Access, Certificate Assistant, Request a Certificate From a Certificate
   Authority, saved to disk. At developer.apple.com, Certificates, Identifiers & Profiles,
   Certificates, add a **Developer ID Application** certificate (G2 Sub-CA) from that request,
   download it and open it so it lands in your login keychain next to its private key.
2. In Keychain Access, select the certificate with its key, Export, format Personal Information
   Exchange (.p12), with a strong password. Then `base64 -i DeveloperID.p12 | pbcopy` and paste it as
   `APPLE_DEVELOPER_ID_P12`; the password is `APPLE_DEVELOPER_ID_P12_PASSWORD`. Delete the `.p12`
   file afterwards.
3. At App Store Connect, Users and Access, Integrations, App Store Connect API, Team Keys, generate a
   key with the **Developer** role. Download `AuthKey_<KEYID>.p8` (it can be downloaded once),
   `base64 -i AuthKey_<KEYID>.p8 | pbcopy` into `APPLE_NOTARY_API_KEY`, and copy the key ID and the
   issuer ID into the other two secrets.
4. Dispatch the release workflow on a pre-release tag and check that the "Sign and notarise the
   darwin binaries" job reports `Accepted`.

`scripts/release/macos-sign.sh` holds the steps: a temporary keychain, `codesign` with the hardened
runtime and a secure timestamp, `notarytool submit --wait`. The data planes are signed before they
are embedded, so the copy inside `scrim` stays byte for byte the shipped `scrim-dataplane`. Signed
darwin binaries carry Apple's timestamp and are not byte-reproducible; the reproducibility check
covers linux-amd64. Bare executables cannot carry a stapled ticket, so Gatekeeper looks the
notarisation up online the first time a downloaded binary runs.

## Build from source

Needs Go and Rust at the versions in `go.mod` and `rust-toolchain.toml`, `git`, GNU `tar`, and for a
release-identical build `cargo-auditable` (`cargo install --locked cargo-auditable`). Linux builds
target musl; on Debian and Ubuntu install `musl-tools`.

<!-- docs-test: skip: clones and builds a release; the release workflow's reproduce job runs it -->

```sh
git clone https://github.com/Heliopsy/scrim
cd scrim
git checkout v1.0.0
just release-build linux-amd64       # dist/bin/linux-amd64/{scrim,scrim-dataplane}
```

`just release-build` runs `scripts/release/dataplane.sh` for the platform, then
`scripts/release/controlplane.sh`, which embeds that data plane into the Go build. The scripts are
what the release workflow runs, so the binaries are byte-identical to the released ones when built
from the tag on the same platform with the same toolchains. The release pipeline itself checks this
on every release by rebuilding linux-amd64 on a second runner and comparing.

To compare a local build with a release:

<!-- docs-test: skip: needs a release archive and a release build -->

```sh
just release-build linux-amd64
tar -xzf "scrim_1.0.0_linux_amd64.tar.gz" -O ./scrim | sha256sum
sha256sum dist/bin/linux-amd64/scrim
```

Container images are assembled from the built binaries, never compiled inside the container, so
they too are reproducible from the same binaries:

<!-- docs-test: skip: builds release binaries and images -->

```sh
just release-build linux-amd64 linux-arm64   # arm64 needs an arm64 host or a cross linker
just release-image scrim                     # localhost/scrim-rel/scrim:<version>
```
