---
title: Verifying a release
linkTitle: Verify a release
weight: 10
description: Check that the chart, images and CLI you install were built from this repository by its release workflow.
---

Every release is built by the
[release workflow](https://github.com/Tessarac-LLC/natterjack/blob/main/.github/workflows/release.yml)
from a protected tag. It signs the images and chart with Sigstore, without a
long-lived key, under the workflow's own identity, and records SLSA build
provenance for every image, the chart and each CLI archive. You need
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and the
[GitHub CLI](https://cli.github.com/).

The release notes list each image by digest. Set the tag you install:

```sh
TAG=v1.0.0
```

## Images

```sh
for image in natterjack-controller natterjack-agent natterjack; do
  cosign verify "ghcr.io/tessarac-llc/$image:$TAG" \
    --certificate-identity "https://github.com/Tessarac-LLC/natterjack/.github/workflows/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  gh attestation verify "oci://ghcr.io/tessarac-llc/$image:$TAG" --repo Tessarac-LLC/natterjack
done
```

`cosign verify` proves the signature; `gh attestation verify` proves the
image was built by that workflow from that repository. Each image also
carries an SPDX SBOM:

```sh
cosign download sbom "ghcr.io/tessarac-llc/natterjack-agent:$TAG"
```

## Chart

```sh
cosign verify "ghcr.io/tessarac-llc/charts/natterjack:${TAG#v}" \
  --certificate-identity "https://github.com/Tessarac-LLC/natterjack/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://ghcr.io/tessarac-llc/charts/natterjack:${TAG#v}" --repo Tessarac-LLC/natterjack
```

The chart pins every image by digest, so a verified chart installs only
verified images.

## CLI archives

From the [release page](https://github.com/Tessarac-LLC/natterjack/releases),
download the archive for your system and `SHA256SUMS`, then:

```sh
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify "natterjack_${TAG}_linux_amd64.tar.gz" --repo Tessarac-LLC/natterjack
```

On macOS use `shasum -a 256 --ignore-missing -c SHA256SUMS`.
