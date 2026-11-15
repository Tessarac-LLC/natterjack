---
title: Compatibility
weight: 40
description: Kubernetes, kernel, CNI and service mesh requirements, and what is tested.
---

## Requirements

| Component | Requirement |
| --- | --- |
| Kubernetes | 1.34 or later. |
| Node kernel | Linux 5.18 or later: the GENEVE tunnel carries IP packets directly. Amazon Linux 2 (kernel 5.10) is too old. |
| WireGuard tunnel | Linux 5.6 or later with the `wireguard` module, on every node, when a pool sets `tunnel: WireGuard`. |
| eBPF steering | Linux 6.6 or later (tcx), on nodes whose CNI moves pod traffic past netfilter. |
| Architectures | `linux/amd64` and `linux/arm64`. |

An agent whose kernel lacks a feature sets its pod's
`natterjack.io/dataplane-ready` condition false with reason `ApplyFailed`,
and the message names the kernel version it needs. `natterjack doctor`
reports every such node.

## CNIs

| CNI | Mode | Tested | Notes |
| --- | --- | --- | --- |
| AWS VPC CNI | default | on EKS | None. |
| kindnet | default | in CI | None. |
| Cilium | eBPF host routing, kube-proxy replacement | in CI | The agent steers with eBPF on the node's uplinks. |
| Calico | iptables or eBPF data plane | in CI | Set `agent.markMask=0x00003f00` (see below). |

### Steering under eBPF data planes

Cilium with eBPF host routing and Calico's eBPF data plane send pod traffic
past the host's netfilter hooks, where Natterjack's steering rules live. On
such nodes the agent attaches small tcx programs first on the node's uplinks
that hand pod traffic back to the steering rules. `agent.steering: auto`, the
default, picks this mode on nodes where it finds Cilium's or Calico's eBPF
devices. Set `nftables` or `ebpf` to choose. The `natterjack_agent_steering_mode`
metric shows each node's choice.

### Packet marks

The agent marks steered flows with bits from `agent.markMask`, which must be
one contiguous run of at least four bits that nothing else on the node uses.
The default, `0x00ff0000`, suits the AWS VPC CNI, kube-proxy, kindnet, Cilium,
Istio and Linkerd.

Calico keeps its own marks across `0xffff0000`, so with Calico install with:

```sh
--set agent.markMask=0x00003f00
```

The agent checks for clashes. It reads the node's other nftables and
iptables-nft rules and policy routing rules, and if any of them test or set
its bits, it reports the node's data path not ready and names the rule.
Rules written with the legacy iptables back end are invisible to this check.

## Service meshes

Natterjack works at layer 3, below the mesh. Sidecar proxies and ztunnel
send traffic from the pod's own network namespace, so a policy that selects
the pod still applies, and the tunnel between nodes is host-network traffic
no mesh captures.

| Mesh | Mode | Tested |
| --- | --- | --- |
| Istio | sidecar | in CI |
| Istio | ambient | in CI |
| Linkerd | default proxy injection | in CI |

For layer-7 egress policy, run the mesh's own egress gateway and select its
pods with an `EgressPolicy`, so its traffic leaves through Natterjack. An
`EgressPolicy` can select by ServiceAccount to line up with mesh identities.

## What CI proves

Every change runs the data-path test on a kind cluster for each CNI and mesh
above, against a fake EC2 API and a fake internet. The test checks that:

- selected pods in each zone leave from their zone's Elastic IP, and
  unselected pods do not;
- when a gateway node dies without warning, new flows leave through another
  zone's gateway within seconds;
- the slot then moves to another node in the zone, and traffic leaves from
  the same Elastic IP again;
- uninstalling removes every kernel object the agent created and every
  attachment.
