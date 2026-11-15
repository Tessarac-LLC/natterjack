---
title: Overview
weight: 10
description: What Natterjack is, the problem it solves, and how it works.
---

## The problem

Nodes in private subnets reach the internet through a NAT gateway. Managed NAT
gateways are simple and highly available, but they bill twice: an hourly charge
for each gateway (usually one per availability zone) and a processing charge on
every gigabyte that passes through, on top of the normal internet transfer
charge. For clusters that pull images, call external APIs or ship telemetry,
the per-gigabyte charge dominates.

## What Natterjack does

Natterjack runs egress gateways as pods on nodes you already have. Each
gateway owns an *egress slot*: a network interface with a public address that
your infrastructure-as-code created and tagged. Pods' internet traffic is
tunnelled to a healthy gateway in the same zone and translated to that slot's
public address.

- **Active-active.** All gateways in a zone carry traffic at once. New flows
  are spread across them by a hash of the connection; existing flows stay
  where they are.
- **Zone-local first.** Traffic only crosses zones when its own zone has no
  healthy gateway, so you do not trade the NAT charge for cross-zone charges.
- **Fast failover, slow repair.** Losing a gateway moves its flows to the
  others in under a second. Re-attaching the orphaned slot to another node
  happens in the background.
- **Works under eBPF data planes.** With Cilium's eBPF host routing or
  Calico's eBPF data plane, pod traffic skips the node's netfilter hooks. The
  agent then puts small eBPF programs first on the node's uplinks that hand
  that traffic back to the same steering rules. It picks this mode on its own;
  set `agent.steering` to `nftables` or `ebpf` to choose. The eBPF mode needs
  Linux 6.6 or later.
- **Infrastructure-as-code owns the infrastructure.** Natterjack never
  creates, retags or deletes cloud resources. It only moves the attachment of
  interfaces that already carry its tags.

## Supported platforms

| Platform | Status |
| --- | --- |
| Amazon EKS and self-managed Kubernetes on AWS | Supported |
| Google Cloud, Microsoft Azure, Oracle Cloud | Not yet supported |
