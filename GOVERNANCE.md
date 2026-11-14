# Governance

Natterjack is an open-source project sponsored by Tessarac, LLC and licensed
under Apache-2.0. Anyone may use it, fork it, and contribute to it.

## Roles

| Role | Who | Can |
| --- | --- | --- |
| Contributor | Anyone with a GitHub account | Open issues and discussions; open pull requests from a fork |
| Maintainer | Members of [`natterjack-maintainers`](MAINTAINERS.md) | Review and approve pull requests, merge into `main`, triage, create release tags, approve release publishing |
| Organization owner | Owners of the Tessarac-LLC GitHub organization | Change repository settings and rules |

## How changes land

Every change, from anyone, is a pull request into `main`:

1. All required checks pass (build, tests, linting, scanning, sign-off).
2. A maintainer approves it. Approval is dismissed by any later push, and the
   person who pushed last cannot be the one who approves.
3. Every review thread is resolved.
4. It is squash-merged, so `main` has a linear, signed history.

These rules are enforced by GitHub repository rulesets, not by convention:
nobody can push to `main` directly, force-push it, or delete it. While the
project has a single maintainer, organization owners may merge their own pull
request without a second person's approval, but only through a pull request
and never skipping a required check. This exception is removed when a second
maintainer joins.

## Releases

A release is a `v*` tag on a commit in `main`. Only maintainers can create `v*`
tags, and no one can move or delete one once it exists. The release workflow
runs in the protected `release` environment, which needs a maintainer's
approval, and publishes images, the Helm chart, an SBOM and SLSA provenance,
all signed with Sigstore. Published releases are immutable.

## Becoming a maintainer

A contributor with a sustained record of high-quality reviews and merged
pull requests may be nominated by an existing maintainer. Nominations are
decided by a majority of the current maintainers. Maintainers who are
inactive for six months may be moved to emeritus status.

## Decisions

Day-to-day decisions are made in pull requests and issues by lazy consensus.
Design changes that alter the API, the security model, or supported platforms
start as an issue labelled `design` and need approval from a majority of
maintainers.

## Code of conduct

Everyone taking part in the project follows the [code of conduct](CODE_OF_CONDUCT.md).
