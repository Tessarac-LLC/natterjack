# Natterjack

[![lint](https://github.com/Tessarac-LLC/natterjack/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/Tessarac-LLC/natterjack/actions/workflows/lint.yml)
[![scan](https://github.com/Tessarac-LLC/natterjack/actions/workflows/scan.yml/badge.svg?branch=main)](https://github.com/Tessarac-LLC/natterjack/actions/workflows/scan.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Tessarac-LLC/natterjack/badge)](https://scorecard.dev/viewer/?uri=github.com/Tessarac-LLC/natterjack)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Natterjack is a Kubernetes operator that replaces the cloud NAT gateway with
highly available, zone-aware egress gateways running on nodes you already have.

- **No per-GB processing charge.** Traffic leaves through Elastic IPs on your
  own nodes instead of a managed NAT gateway.
- **Active-active in every zone.** Flows spread across gateways; a lost gateway
  moves new flows to a survivor in the same zone in well under a second.
- **Secure without extra configuration.** Gateways run in an isolated network
  namespace that only forwards outbound and never accepts inbound connections,
  even if a cloud firewall rule is wrong.
- **Your IaC stays in charge.** Natterjack finds egress interfaces by tag and
  only moves their attachment. It never creates, edits or deletes cloud
  resources or tags.
- **Works with your CNI and service mesh.**

Natterjack v1.0.0 supports AWS (EKS and self-managed Kubernetes on EC2).

## Documentation

Everything lives at **[natterjack.io](https://natterjack.io/docs/)**: the quick
start, AWS prerequisites and Terraform, the security model and how to verify
it, the Helm values reference and troubleshooting.

The design is in [docs/design](docs/design/2026-11-14-natterjack-design.md).

## Contributing

Contributions are welcome from anyone. Read [CONTRIBUTING.md](CONTRIBUTING.md)
first: every commit is signed off under the
[DCO](https://developercertificate.org/), and every change lands through a
reviewed pull request. How the project is run is in
[GOVERNANCE.md](GOVERNANCE.md).

Report security issues privately as described in [SECURITY.md](SECURITY.md),
never in a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
