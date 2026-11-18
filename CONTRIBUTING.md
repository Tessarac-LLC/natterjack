# Contributing to Natterjack

Thanks for helping. Every contribution, from a typo fix to a new cloud
provider, follows the same path.

## Before you start

- Bugs and small fixes: open a pull request directly, or an issue first if
  you are unsure.
- Features, API changes, or anything touching the security model or the data
  path: open an issue first so a maintainer can agree the approach.
- Security vulnerabilities: never in public. Follow [SECURITY.md](SECURITY.md).

## Workflow

1. Fork the repository and create a branch from `main`.
2. Make your change with tests. Run `make check` locally; it runs the same
   linters and tests as CI.
3. Sign off every commit (see below).
4. Open a pull request against `main` and fill in the template.
5. A maintainer approves CI for your first run, reviews, and merges once
   every required check is green.

Pull requests are squash-merged, so the pull request title becomes the commit
subject on `main`. Use the [Conventional Commits](https://www.conventionalcommits.org/)
form: `feat: …`, `fix: …`, `docs: …`, `chore: …`, `test: …`, `ci: …`, with
`!` for breaking changes.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/): that you
wrote the change or otherwise have the right to submit it under the project's
licence. Add it with `git commit -s`. The name and email must match the
commit author. The `dco` check fails a pull request with any commit missing it.

Commits made in the GitHub web editor are signed off automatically.

## What CI checks

| Check | What it runs |
| --- | --- |
| `lint / actions` | actionlint and zizmor on every workflow |
| `lint / markdown` | markdownlint on all documentation |
| `dco` | Sign-off on every commit |
| `scan / secrets` | TruffleHog on the pull request's changes |
| `scan / dependencies` | GitHub dependency review: no new vulnerable or disallowed-licence dependencies |
| `site / build` | The website builds with no broken internal links |
| `go / lint`, `go / test`, `go / vuln`, `go / codeql` | generated files up to date, golangci-lint, unit and envtest suites with the race detector, govulncheck, CodeQL security queries |
| `go / fuzz` | Every Go fuzz target for 60 seconds |
| `go / dataplane` | The kernel data path tests in throwaway privileged containers |
| `chart / lint` | helm lint, every rendering valid against the Kubernetes schemas, bad input refused |
| `chart / e2e (…)` | The chart installed on kind for each supported Kubernetes version: readiness, RBAC, admission policies, recovery |
| `datapath / e2e (…)` | Real egress traffic on kind for each CNI and service mesh: safety checks, failover, steering and the security tests |
| `release / dry-run` | The release built against a local registry: multi-arch images with SBOMs, a chart that installs them, reproducible CLI archives |
| `terraform / check` | Terraform format, validate, tests and docs; cfn-lint on the CloudFormation templates |

All of them must pass before a pull request can merge.

## Code style

- Go: `gofmt`, `golangci-lint` with the repository config. Errors are wrapped
  with context; no `panic` outside `main`.
- Every behaviour change has a test that fails without it.
- No new dependency without a reason in the pull request description.
- Documentation changes ship with the code change that needs them.
