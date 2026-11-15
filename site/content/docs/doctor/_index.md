---
title: Checking an installation
linkTitle: Doctor
weight: 30
description: Run natterjack doctor before moving traffic, and read its report.
---

`natterjack doctor` checks an installation and prints a go or no-go report.
Run it after every install or upgrade, and before you remove a NAT gateway.
It only reads from the cluster.

## In the cluster

The chart ships the doctor as a Helm test:

```sh
helm test natterjack --namespace natterjack --logs
```

The test pod runs with read-only access that exists only while the test runs.
The pod itself stays so its logs can be read again, and the next test replaces
it. Helm does not remove test pods on uninstall, so delete it first:

```sh
kubectl delete pod --namespace natterjack -l app.kubernetes.io/component=doctor
```

Set `doctor.enabled=false` to leave the test out.

## From your workstation

Download the archive for your system from the
[releases](https://github.com/Tessarac-LLC/natterjack/releases), check it
against `SHA256SUMS` and its provenance, and run:

```sh
gh attestation verify natterjack_<version>_linux_amd64.tar.gz --repo Tessarac-LLC/natterjack
natterjack doctor
```

It uses your kubeconfig. `--context` picks a context, and `--namespace` and
`--release` pick one release when a cluster has several. `-o json` prints the
report for automation. The exit status is 0 for go, 1 for no-go and 2 for a
usage error.

## Reading the report

Each line is `[ok]`, `[WARN]` or `[FAIL]`, the check, and what was found:

```text
[ok]    kubernetes         Kubernetes v1.34.2
[ok]    install            release natterjack in namespace natterjack
[FAIL]  controller         no controller replica is ready (0 of 2)
[ok]    controller leader  natterjack-controller-7d9c6b5f4-x2kqp leads
[ok]    agents             data path applied on all 6 nodes
[ok]    admission          agent policy natterjack-agent enforced
[ok]    admission          controller policy natterjack-controller enforced
[FAIL]  pool default       the controller cannot read the cloud: discover slots: ... (the controller authenticates as system:serviceaccount:natterjack:natterjack-controller; the cloud role must trust that subject and carry the Natterjack policy)

NO-GO: 2 problem(s) must be fixed before traffic moves; 0 warning(s).
```

| Check | A failure means |
| --- | --- |
| `kubernetes` | The cluster is older than 1.34. |
| `install` | No release, or several, were found. Pass `--namespace` and `--release`. |
| `controller` | No replica is ready. A controller is not ready while the cloud API fails; the pool lines say why. |
| `controller leader` | No running controller holds the leader Lease, so no slot is attached or moved. |
| `agents` | A node has no ready agent, or its data path failed to apply. The agent's own error is shown. |
| `gateways` | Gateways hold slots they do not serve. A warning while some still serve. |
| `admission` | An admission policy or its binding is missing. Reinstall the chart. |
| `pool <name>` | The controller cannot read the cloud (the identity it uses is named), has not reconciled the pool, or the pool is not ready. |
| `policies` | A policy is not in force; its message says why. |
