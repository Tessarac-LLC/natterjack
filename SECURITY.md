# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Report vulnerabilities privately through
GitHub: [Report a vulnerability](https://github.com/Tessarac-LLC/natterjack/security/advisories/new).

Include what you found, how to reproduce it, and the version or commit
affected. A maintainer acknowledges reports within 3 business days and
keeps you informed until the fix is released. We credit reporters in the
advisory unless you ask us not to.

## Supported versions

Security fixes are released for the latest minor version. Upgrade to the
latest patch release to receive them.

## How releases are protected

- Every change reaches `main` only through a reviewed pull request with all
  required checks passing; direct pushes and force-pushes are blocked.
- Release tags can be created only by maintainers and can never be moved or
  deleted. Published releases are immutable.
- Container images and the Helm chart are signed with Sigstore (keyless) and
  ship with an SBOM and SLSA build provenance. See the
  [verification guide](https://natterjack.io/docs/security/verify/).

## Security model

Why installing Natterjack does not weaken the security of your cluster is set
out, claim by claim with the evidence for each, in the
[security model](https://natterjack.io/docs/security/).
