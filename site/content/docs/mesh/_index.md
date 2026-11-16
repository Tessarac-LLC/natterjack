---
title: Service mesh reference architecture
linkTitle: Service meshes
weight: 45
description: Where Natterjack sits beneath Istio and Linkerd, and how to combine it with each mesh's egress controls.
---

A mesh decides, at layer 7, which external hosts a workload may call.
Natterjack decides, at layer 3, which public address and zone that call
leaves from. They do not overlap, and each works without the other.

| Layer | Owner | Decides |
| --- | --- | --- |
| HTTP, TLS SNI, hostnames | Mesh (sidecar, ztunnel, waypoint or egress gateway) | Whether a call to `api.example.com` is allowed, retried, observed |
| IP packet leaving the VPC | Natterjack | That the packet leaves from the zone's slot, from a fixed address, without a NAT gateway |

The data path is tested in CI with Istio sidecars, Istio ambient and Linkerd
(see [Compatibility](../compatibility/#service-meshes)).

## How traffic flows

1. The application opens a connection to an external host.
2. The mesh proxy (sidecar or ztunnel) applies its egress policy and opens
   its own connection, from the pod's network namespace.
3. That connection's packets leave the pod like any other. If a Natterjack
   policy selects the pod, the node's agent steers them to a gateway in the
   pod's zone, through the tunnel between nodes.
4. The gateway sends them out of the slot, from the slot's Elastic IP.

In-cluster traffic, including mesh mTLS between pods, is never steered:
VPC and private address ranges are excluded from every policy. The tunnel
between nodes is host-network traffic, which no mesh captures.

## Pattern 1: fixed addresses per workload

Select the workloads that need a fixed address, by namespace, pod labels or
ServiceAccount, the identity the mesh also uses:

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
      app.kubernetes.io/name: payments-api
```

The mesh's own egress rules still apply at each proxy: with Linkerd, an
[`EgressNetwork`](https://linkerd.io/2.18/reference/egress-network/) with
`trafficPolicy: Deny` and Gateway API routes for the allowed hosts; with
Istio, `outboundTrafficPolicy: REGISTRY_ONLY` and a `ServiceEntry` for each
allowed host.

## Pattern 2: one egress point for layer-7 control

Send all external traffic through the mesh's egress gateway, and let only
that gateway leave the cluster, through Natterjack:

1. Run Istio's egress gateway (or, in ambient mode, an egress waypoint) and
   route each `ServiceEntry` host through it, with
   `outboundTrafficPolicy: REGISTRY_ONLY` so that nothing bypasses it.
2. Select the egress gateway's pods:

   ```yaml
   apiVersion: natterjack.io/v1alpha1
   kind: EgressPolicy
   metadata:
     name: mesh-egress
     namespace: istio-egress
   spec:
     poolName: default
     podSelector:
       matchLabels:
         istio: egressgateway
   ```

3. Spread the egress gateway's replicas across zones with a topology spread
   constraint. Each replica leaves through its own zone's slot, so no traffic
   crosses zones after the mesh has chosen a replica.

Workloads without a proxy can still open connections directly. Block them
with a NetworkPolicy that allows external egress only from the egress
gateway's namespace.

## What to watch

- **Mark bits.** The agent's default mark mask, `0x00ff0000`, leaves Istio's
  and Linkerd's marks alone. The agent reports any rule that tests or sets
  its bits.
- **Readiness.** If every gateway in a zone is down, selected traffic fails
  over to another zone's gateway within seconds; external services see the other
  zone's address meanwhile, so allow-list every address in the pool.
- **Allow-lists.** Give external services the pool's addresses
  (`kubectl get egresspool`), not the egress gateway pods' addresses.
