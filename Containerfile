# SPDX-License-Identifier: AGPL-3.0-only
#
# ghcr.io/heliopsy/scrim: the control plane with the data plane embedded.
#
# Not a build recipe. The image is assembled from the release binary that
# scripts/release built, signed and checksummed, so the bytes in the image are
# the bytes in the release archive and nothing is compiled twice:
#
#   scripts/release/image.sh scrim
#
# The build context is a staging directory holding linux-<arch>/scrim for each
# architecture; TARGETARCH, set by the build engine per --platform, picks one.
# No RUN step, so a multi-arch build needs no emulation.

# Pinned by the digest of the multi-arch index; dependabot moves it.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
ARG SOURCE=https://github.com/Heliopsy/scrim

LABEL org.opencontainers.image.title="scrim" \
      org.opencontainers.image.description="Keeps secrets away from LLM providers while AI agents keep working" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.url="${SOURCE}" \
      org.opencontainers.image.documentation="${SOURCE}/blob/main/docs/install.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="Heliopsy" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --chmod=0755 linux-${TARGETARCH}/scrim /usr/local/bin/scrim
# State lives on a volume so the root filesystem can be read-only. The
# directory is created here, owned by the runtime user, because the base has
# no shell to create it at start-up.
COPY --chown=65532:65532 --chmod=0700 state/ /var/lib/scrim/

# distroless nonroot. Numeric so runAsNonRoot can check it without /etc/passwd.
USER 65532:65532
WORKDIR /var/lib/scrim
ENV HOME=/var/lib/scrim \
    XDG_STATE_HOME=/var/lib/scrim \
    XDG_CONFIG_HOME=/etc
VOLUME ["/var/lib/scrim"]
ENTRYPOINT ["/usr/local/bin/scrim"]
