# Release recipes. Imported by the justfile; each wraps one script in
# scripts/release, which the release workflow runs directly.

# Release binaries for each PLATFORM (default: this host) into dist/bin.
release-build *PLATFORMS:
    scripts/release/build.sh {{PLATFORMS}}

# Archives, SBOMs and checksums from dist/bin into dist/release.
release-package:
    scripts/release/package.sh dist/bin dist/release

# Build and smoke test the image NAME (scrim or scrim-dataplane) from dist/bin.
release-image NAME:
    scripts/release/image.sh build {{NAME}} dist/bin

# Remove release build output and the local release images.
release-clean:
    scripts/release/image.sh clean scrim
    scripts/release/image.sh clean scrim-dataplane
    rm -rf dist target/release-build
