---
title: Concepts
weight: 20
description: Pools, slots, gateways and policies, and how traffic finds its way out.
---

## Egress slots

An *egress slot* is a network interface your infrastructure-as-code created
for Natterjack. On AWS it is an ENI in a public subnet with its own Elastic
IP, the source/destination check turned off, and a security group that admits
nothing from outside the VPC. It carries three tags:

| Tag | Value |
| --- | --- |
| `natterjack.io/egress` | `true` |
| `natterjack.io/cluster` | the cluster name the controller is installed with |
| `natterjack.io/pool` | optional: a name that pools select with `discovery.extraTags` |

A pool claims every slot whose tags match its `discovery.extraTags`. A pool
that does not ask for `natterjack.io/pool` claims only slots without that
tag, so one untagged pool takes every slot in a cluster that has one pool.

Natterjack never creates, retags or deletes a slot. The controller only
attaches it to a node and detaches it again. The
[Terraform module](../install/) creates slots correctly.

## Gateways

A node holding a slot is a *gateway*. Its agent moves the slot's interface
into a separate network namespace, the *gateway namespace*, so the node's
own routing, firewall and CNI never see it. Traffic tunnelled to the
gateway is translated there to the slot's address and leaves through the
slot. Gateways are ordinary nodes: Natterjack adds no instances.

Before a gateway takes traffic, its agent sends a request through the slot
to a service that echoes the caller's public address
(`https://checkip.amazonaws.com` by default) and checks that the answer is
the slot's address. Only then does it set the `natterjack.io/gateway-ready`
condition on its own pod. The self-test repeats every 30 seconds while the
gateway serves, and three failures in a row take the gateway out of
service.

## EgressPool

An `EgressPool` (cluster-scoped, short name `ep`) groups slots and says how
gateways run for them.

```yaml
apiVersion: natterjack.io/v1alpha1
kind: EgressPool
metadata:
  name: default
spec:
  gatewayNodeSelector:
    node.kubernetes.io/egress: "true"   # optional; empty means any Linux node
  maxGatewaysPerZone: 2                 # optional; unset uses every healthy slot
  tunnel: Geneve                        # or WireGuard
  probe:
    intervalMilliseconds: 100
    failureThreshold: 3
  drainSeconds: 60
  safetyChecks: Enforce                 # or Warn, for break-glass use only
```

| Field | Default | Meaning |
| --- | --- | --- |
| `discovery.extraTags` | none | Tags, with values, a slot must also carry to be in this pool (at most 16). |
| `gatewayNodeSelector` | any Linux node | Nodes that may hold a slot. |
| `gatewayTolerations` | none | Lets gateways run on tainted nodes. Give the agent DaemonSet the same tolerations in the Helm values. |
| `maxGatewaysPerZone` | one per healthy slot | Caps gateways per zone. Healthy slots beyond the cap stay unattached as `Spare`. |
| `tunnel` | `Geneve` | Encapsulation from source nodes to gateways. `WireGuard` encrypts it. |
| `probe.intervalMilliseconds` | `100` | Time between probes from each node to each gateway (20 to 10000). |
| `probe.failureThreshold` | `3` | Missed probes before a gateway is treated as down (1 to 100). |
| `drainSeconds` | `60` | How long established flows keep a gateway that is being removed on purpose (0 to 3600). |
| `safetyChecks` | `Enforce` | `Enforce` quarantines a slot that fails a safety check. `Warn` uses it and reports the failure. A slot attached outside the cluster is never used. |

### Slot states

The pool's status lists every slot it found, with its zone, public address,
node and state. When a slot is not `Active`, its `reason` says why in plain
language.

| State | Meaning |
| --- | --- |
| `Pending` | Discovered and valid, not yet assigned to a node. |
| `Attaching` | Being attached; waiting for its gateway to report ready. |
| `Active` | Attached, and its gateway passed its self-test. |
| `Draining` | Being moved off a node that is going away on purpose. |
| `Spare` | Healthy and held back by `maxGatewaysPerZone`. Replaces a failed slot first. |
| `Quarantined` | Failed a safety check; never used until fixed. |
| `Unschedulable` | No eligible node in its zone. |
| `Foreign` | Attached to an instance outside this cluster; never touched. |

### Pool conditions

| Condition | True when |
| --- | --- |
| `Ready` | At least one gateway serves the pool. |
| `Degraded` | A zone has no gateway, or no second gateway to fail over to. |
| `CrossZoneEgress` | Some zone's traffic leaves through another zone, which adds cross-zone transfer charges. |
| `SlotsQuarantined` | A slot failed a safety check. The message names it. |
| `SlotsUnschedulable` | A slot has no eligible node in its zone. |
| `ForeignSlots` | A slot is attached outside this cluster. |
| `CloudAccess` | The controller can read the cloud. When false, the message names the failing call and the identity the controller used. |

```sh
kubectl get egresspools
kubectl get egresspool default -o yaml
```

## Policies

Pods are not steered until a policy selects them. Traffic that no policy
selects leaves the way it did before Natterjack, normally through the
subnet's default route.

An `EgressPolicy` (namespaced, short name `egp`) selects pods in its own
namespace:

```yaml
apiVersion: natterjack.io/v1alpha1
kind: EgressPolicy
metadata:
  name: payments
  namespace: payments
spec:
  poolName: default
  podSelector:
    matchLabels:
      app: checkout
  serviceAccountNames: [checkout]  # optional; with podSelector, a pod must match both
  excludedCIDRs: [203.0.113.0/24]  # optional
```

A `ClusterEgressPolicy` (cluster-scoped, short name `cegp`) selects pods in
many namespaces and can also steer the nodes' own traffic: the kubelet,
image pulls and host-network pods.

```yaml
apiVersion: natterjack.io/v1alpha1
kind: ClusterEgressPolicy
metadata:
  name: everything
spec:
  poolName: default
  namespaceSelector: {}  # every namespace; leave it unset to select no pods
  nodeTraffic: true
```

When both kinds select a pod, its namespace's `EgressPolicy` wins. Cluster,
VPC and private address ranges are never steered, with or without
`excludedCIDRs`. A policy's `Accepted` condition is true once its pool exists
and the policy is in force.

## How a packet leaves

1. A selected pod opens a connection to an internet address.
2. The agent on the pod's node picks one of the live gateways in the pod's
   zone by a hash of the connection, and marks the flow. Every packet of the
   flow then goes to that gateway.
3. The packet is tunnelled to the gateway over GENEVE, or over WireGuard when
   the pool asks for it.
4. In the gateway namespace the packet is translated to the slot's address
   and leaves through the slot. Replies come back the same way.

All of this happens in the Linux kernel, with nftables rules and, under eBPF
data planes, small eBPF programs on the node's uplinks. No packet passes
through a user-space process.

## Failure and repair

Every agent probes every gateway it may use, every 100 ms by default, over
the same tunnel path traffic takes. After three missed probes (about 300 ms),
the agent removes the gateway from its hash and flushes the flows that used
it. Those flows' next packets go to another live gateway in the zone, or to
another zone when the zone has none left. Connections that were open through
the lost gateway are reset by the remote end, because their public source
address has changed. New connections and retries succeed at once.

The slot itself is repaired in the background. When Kubernetes marks the
failed node not ready, the controller detaches the slot and attaches it to
another eligible node in the same zone. That is about 50 seconds with
Kubernetes' default node-monitor grace period. Traffic returns to the zone,
and to the same public address, as soon as the new gateway passes its
self-test.

A planned disruption is gentler. When a gateway node is cordoned, or tainted
for removal by Karpenter, the cluster autoscaler, the AWS Node Termination
Handler or as out of service, the controller tells its agent to stop taking
new flows. Established flows keep the gateway for `drainSeconds`
before the slot moves.

Restarting an agent, as every upgrade does, disrupts nothing. The gateway's
namespace, tunnels, address translation and open flows live in the kernel,
not in the agent, and so does the program that answers probes: it keeps
answering while the agent is gone, and only while the slot can still send
traffic out. The controller holds a restarting agent's slot for a minute,
the new agent picks up its saved assignment from `/run/natterjack`, and
other nodes keep sending flows to the gateway meanwhile. Open connections
through it stay up. An agent that is down for more than a minute is treated
as failed, and its slot moves as above.
