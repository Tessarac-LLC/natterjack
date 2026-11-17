---
title: Troubleshooting
weight: 35
description: What each condition, slot state and agent status means, and what to do about it.
---

Start with [`natterjack doctor`](../doctor/). It reads everything on this
page and names what to fix. Then look at the pool:

```sh
kubectl get egresspool default -o yaml      # conditions and the slot table
kubectl describe egresspool default         # recent events
```

Every slot that is not `Active` carries a `reason` in plain language. Most
problems are explained there. This page lists each condition and reason,
what causes it and what to do.

## Pool conditions

### Ready

| Status | Reason | Meaning |
| --- | --- | --- |
| True | `GatewaysReady` | At least one gateway serves its slot. |
| False | `NoReadyGateway` | No gateway serves. Selected traffic has no way out except the bootstrap route. |

When `Ready` is False, read each slot's `state` and `reason`
([below](#slot-states)). Usually every slot has the same cause: the
controller cannot read the cloud (see `CloudAccess`), no node is eligible,
or every slot failed its safety checks.

### Degraded

`True` with reason `ZoneRedundancy` means a zone has no ready gateway, or
only one. With one gateway, losing that node sends the zone's traffic to
other zones until its slot moves; with none, it already does. Give each zone
at least two slots (the Terraform module's `slots_per_subnet`, default 2)
and at least two eligible nodes. If a zone still has a single gateway, look
for `Unschedulable` or `Spare` slots there. Reason `Redundant` is the
healthy state.

### CrossZoneEgress

`True` with reason `ZoneWithoutGateway`: a zone with nodes has no ready
gateway, so its traffic leaves through other zones. It still works, but
inter-zone data transfer is charged per GB. Fix the zone's slots as for
`Degraded`. A zone with nodes and no slot at all needs a public subnet and a
slot there.

The condition reflects the gateways' own readiness. A node can also send a
zone's traffic elsewhere when its probes cannot reach that zone's gateways
through the tunnel; its agent then logs `gateway unreachable from this node`
and `no live gateway in this node's zone`, and logs again when that ends.
`natterjack_agent_gateways_down` counts the gateways a node sees as down.

### CloudAccess

`False` with reason `CloudCallFailed` means the controller cannot list slots
from the cloud. The message carries the failing call and the cloud's error,
for example:

```text
discover slots: describe network interfaces: operation error EC2: ...
AccessDenied ... (the controller authenticates as
system:serviceaccount:natterjack:natterjack-controller; the cloud role must
trust that subject and carry the Natterjack policy)
```

Gateways that are already running keep serving: the agents do not need
the cloud. But no slot is attached or moved until access returns, so a
failed node is not replaced. The controller's readiness check also fails,
so its pods show not ready.

Check, in order:

1. **The identity.** With EKS Pod Identity, an association must exist for
   the controller's namespace and ServiceAccount, and the
   `eks-pod-identity-agent` add-on must run. With IRSA, the ServiceAccount
   needs the `eks.amazonaws.com/role-arn` annotation, and the role's trust
   must name the cluster's OIDC provider and that exact subject. A changed
   namespace or release name changes the subject.
2. **The role's policy.** It must be the one the Terraform module creates,
   for this `cluster_name`. The chart's `clusterName` must match it.
3. **The region.** `controller.aws.region` must be the cluster's region.
4. **The network.** In a VPC without a NAT gateway, the controller reaches
   EC2 and STS through the bootstrap route or VPC endpoints.
5. **The pod's credentials.** EKS gives a pod its credentials when the pod
   is created. A controller pod created before its Pod Identity association
   or IRSA annotation has none, and restarting its container does not help.
   Its readiness check reports `no cloud credentials`, and the error ends
   with `this pod has no workload identity`. A new pod is not ready until
   it has found credentials, so a rollout of pods without them stalls and
   the running replicas keep working. Recreate the pods:

   ```sh
   kubectl -n natterjack rollout restart deploy/natterjack-controller
   ```

   A new association can take a few seconds to apply to new pods; if a pod
   still reports no workload identity, restart again.

Every controller replica checks its own credentials every 15 seconds, and a
replica without them is not ready. A leader that has had none for two
minutes gives up leadership, so a replica that has them takes over; the
leader's container restarts, which shows in its restart count.

The condition clears by itself once a call succeeds; restart the controller
to retry at once.

### SlotsQuarantined

`True` with reason `SafetyCheckFailed` lists slots that failed a safety
check. With `safetyChecks: Enforce`, the default, a quarantined slot is
detached and never used until it passes. Each slot's `reason` names every
failing check:

| Reason | Fix |
| --- | --- |
| `security group sg-… allows inbound traffic from outside the VPC; a slot's security groups may admit only the VPC's own IPv4 blocks` | Remove every inbound rule whose source is not an IPv4 CIDR inside one of the VPC's associated blocks: wider CIDRs, IPv6 ranges, prefix lists and security groups. A security group the controller cannot read counts as open. |
| `the ENI has no security group` | Attach the module's empty security group. |
| `no Elastic IP is associated with the ENI` | Associate one. The module does this. |
| `source/destination check is enabled; it must be disabled for a gateway` | Disable it: a gateway forwards traffic that is not its own. |
| `tag node.k8s.amazonaws.com/no_manage=true is missing, so the VPC CNI could use the ENI for pods` | Add the tag. Without it the VPC CNI may assign pod addresses to the slot. |
| `interface type is "…"; only a plain ENI can be a slot` | Use a plain ENI, not an EFA or trunk interface. |
| `the ENI is managed by an AWS service` | Use an ENI you created. |
| `subnet subnet-… has no 0.0.0.0/0 route to an internet gateway` | Put the slot in a public subnet. |
| `subnet subnet-… has no IPv4 CIDR block` | Use a subnet with IPv4. |
| `claimed by more than one EgressPool (a, b); give it a natterjack.io/pool tag` | Tag the slot with the one pool that should own it. |

`safetyChecks: Warn` keeps failing slots in use and appends the failures to
their reason. Use it only to keep traffic flowing while you fix a check.

### SlotsUnschedulable

`True` with reason `NoEligibleNode` lists slots that have no node to run on in
their zone. The slot's reason gives the refusal for every node:

```text
no eligible node in zone us-east-1a (ip-10-0-1-5: already a gateway;
ip-10-0-1-9: no free network interface slot; ip-10-0-1-12: node
ip-10-0-1-12 does not match gatewayNodeSelector role=egress)
```

| Per-node reason | Meaning |
| --- | --- |
| `already a gateway` | A node serves one slot at a time. Add nodes or remove slots. |
| `not ready` | The node is not Ready. |
| `no agent` / `agent not ready` | The agent pod is missing or not ready on that node; see [the agent](#the-agent). |
| `no free network interface slot` | The instance is at its interface limit, so attaching was refused. The node is avoided for ten minutes, then tried again. Use a larger instance type or fewer interfaces per node. |
| `node … does not match gatewayNodeSelector k=v` | Label nodes to match, or widen the selector. |
| `node … has taint …, which gatewayTolerations do not tolerate` | Add a toleration to the pool. |
| `node … is not Linux` | Gateways run on Linux nodes only. |
| `node … is cordoned`, `… is being deleted`, `Karpenter is removing node …`, `the cluster autoscaler is removing node …`, `AWS Node Termination Handler is removing node …`, `node … is out of service` | The node is leaving; the slot goes elsewhere. |

`no nodes in zone …` means the zone has a slot but no node with an agent.

### ForeignSlots

`True` with reason `AttachedOutsideCluster`: a slot tagged for this cluster
is attached to an instance that is not one of its nodes. Natterjack never
detaches it, because it might be in use. Detach it yourself if that instance
should not have it; the controller then takes it over. A foreign slot's
address is left out of `status.publicIPs`.

## Slot states

| State | Meaning | Usual reasons |
| --- | --- | --- |
| `Pending` | Valid, not yet on a node | `detaching from an instance whose node is gone`; `moving off node …, which is not ready`, `…, which has no agent`, `…, which already serves slot …`; `moved off node …: <why>` |
| `Attaching` | Attached; the gateway has not yet passed its self-test | `waiting for the gateway to report ready`; `the agent on node … is restarting; the slot moves if it is not back in 45s` |
| `Active` | Serving | Empty; with `safetyChecks: Warn`, the checks it fails |
| `Draining` | Leaving its node; established flows continue | `node … is cordoned; moving in 12s`, or any leaving reason above |
| `Spare` | Healthy, held back | `zone … already has maxGatewaysPerZone gateways` |
| `Quarantined` | Failed a safety check | See [SlotsQuarantined](#slotsquarantined) |
| `Unschedulable` | No eligible node | See [SlotsUnschedulable](#slotsunschedulable) |
| `Foreign` | Attached outside the cluster | See [ForeignSlots](#foreignslots) |

A slot stuck in `Attaching` waits for its gateway's self-test; read the
`natterjack.io/gateway-ready` condition of that node's agent pod.

## Events

The controller records events on the pool:

| Reason | Type | When |
| --- | --- | --- |
| `SlotActive`, `SlotPending`, `SlotAttaching`, `SlotDraining`, `SlotSpare` | Normal | A slot changes state; the message carries its node and reason |
| `SlotQuarantined`, `SlotUnschedulable`, `SlotForeign` | Warning | As above |
| `SlotAttached`, `SlotDetached` | Normal | An attach or detach succeeded, with the reason for a detach |
| `AttachFailed`, `DetachFailed` | Warning | The cloud refused; the message has its error |
| `UnclaimedSlots` | Warning | Slots of this cluster that no pool claims, or slots tagged for another cluster |

`UnclaimedSlots` usually means a slot has a `natterjack.io/pool` tag that names
no pool, or the pool requires a tag the slot lacks. Slots tagged for another
cluster are ignored; if they are meant for this one, fix their
`natterjack.io/cluster` tag to match `clusterName`.

## The agent

Each agent reports on its own pod. There are no node conditions.

```sh
kubectl -n natterjack get pods -l app.kubernetes.io/component=agent -o wide
kubectl -n natterjack get pod <agent> -o jsonpath='{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
```

### natterjack.io/dataplane-ready

`True`, reason `Applied`: the node's routing, marks and tunnels are in place.
`False`, reason `ApplyFailed`: the message is the error. The agent pod stays
not ready until the first apply succeeds, and the node's traffic is not
steered.

| Message | Fix |
| --- | --- |
| `net.ipv4.conf.all.rp_filter is 1 (strict); set it to 0 or 2, as EKS AMIs do` | Set it to 0 or 2 on the node, for example in the launch template's user data. Strict mode drops steered replies. |
| `net.ipv4.ip_forward must be 1 on a Kubernetes node` | Enable forwarding. |
| `… this kernel's GENEVE devices cannot carry IP packets; the agent needs Linux 5.18 or later` | Use a newer AMI (Amazon Linux 2023, Bottlerocket). See [Compatibility](../compatibility/). |
| `… the kernel has no WireGuard (Linux 5.6 or later, module wireguard)` | Load the module or use `tunnel: Geneve`. |
| `… the kernel has no tcx (Linux 6.6 or later)` | Only the eBPF fast path needs tcx. Set `agent.steering=nftables`, or use a newer kernel. |
| `other rules on the node use the agent's mark bits 0x…, so steering would fail: …; set agent.markMask to bits none of them use` | Another component uses the same packet-mark bits; the message names the rule. Pick free bits for `agent.markMask` (with Calico, `"0x00003f00"`). |
| `policy routing rules sort ahead of the agent's (priority …) and can route steered traffic past its gateways: …; set agent.rulePriority below …` | A rule that picks a route by source, by incoming interface, or by a mark restored from the connection mark on every packet comes before the agent's, so steered pod traffic would follow it, usually the node's default route, instead of the agent's choice of gateway. The AWS VPC CNI's rules are at 1024 and 1536, after the default of 1000. Set `agent.rulePriority` below the rule the message names. |
| `node has no IPv4 address`, `no interface has the node address …` | The node needs an IPv4 InternalIP on an interface. |
| `pin gateway namespace at … (is the state directory a shared host mount?)` | The chart mounts the state directory from the host. Restore its default if it was changed. |

### natterjack.io/gateway-ready

Present only on nodes that serve or served a slot.

| Status and reason | Meaning |
| --- | --- |
| True `Serving` | `serving slot <id>` |
| False `SelfTestPending` | Waiting for three self-tests in a row through the slot, a second apart. |
| False `SelfTestFailed` | Three self-tests in a row failed; the gateway is out of service. See below. |
| False `NotServing` | The slot interface has not arrived (`slot interface … is not attached to this node yet`) or is not the expected one. |
| False `Draining` | Established flows continue; new flows go to other gateways. |
| False `ApplyFailed` | As for `dataplane-ready`. |
| False `NotAssigned` | The node serves no slot now. |

The self-test fetches `agent.selfTest.url` (default
`https://checkip.amazonaws.com`) through the slot every 30 seconds, and
checks that the answer is the slot's own public IP. Failures:

| Message | Fix |
| --- | --- |
| `traffic leaves from X, not the slot's public IP Y` | Something else routes the gateway's traffic: check the slot subnet's route table and that the Elastic IP is still associated with the slot. |
| `self-test through the slot: … timeout` | The slot subnet has no route to an internet gateway, a network ACL drops the traffic, or the security group has no outbound rule. |
| `resolve self-test host: …` | The node cannot resolve DNS. |
| `self-test service answered …` | The self-test service returned an error or something other than an address; point `agent.selfTest.url` at a service that returns the caller's address. |

## Policies

`EgressPolicy` and `ClusterEgressPolicy` carry one condition, `Accepted`:

- `True`, `PoolFound`: selected traffic leaves through the pool.
- `False`, `PoolNotFound`: `EgressPool … does not exist; selected traffic
  uses the cluster's default route`. Fix `poolName`, or create the pool.

A policy that is accepted but does not seem to apply usually selects nothing:
check `podSelector`, `serviceAccountNames` and `namespaceSelector` against the
pods' labels, and that the destination is not in `excludedCIDRs`. Traffic to
the cluster, the VPC and the pod ranges is never steered.

## Install and admission errors

| Error | Fix |
| --- | --- |
| `clusterName is required: …` | Set `clusterName` to the module's `cluster_name`. |
| `controller.aws.region is required` | Set the region. |
| `namespace … enforces Pod Security "…"; the agent needs "privileged". …` | Label the namespace, or install with `namespace.create=true` into a new one. |
| `agent.wireguardPort must differ from agent.tunnelPort` | Choose different ports. |
| `an agent may only change its own pod's status` | Something used an agent's token to touch another pod. This is the admission policy working; find out what used the token. |
| `the controller never creates or deletes pods`, `the controller may only change agent pods`, `… natterjack.io/ labels and annotations`, `… may not change a pod's spec` | As above, for the controller's token. |
| `set podSelector or serviceAccountNames; …` | An `EgressPolicy` must select something. Use `podSelector: {}` for every pod. |
| `set namespaceSelector, nodeTraffic, or both` | A `ClusterEgressPolicy` must select something. |
| `every entry must be an IPv4 CIDR` | Fix `excludedCIDRs`. |

## Collecting diagnostics

```sh
natterjack doctor -o json > doctor.json
kubectl get egresspools,egresspolicies,clusteregresspolicies -A -o yaml > natterjack.yaml
kubectl -n natterjack logs deploy/natterjack-controller --since=1h > controller.log
kubectl -n natterjack logs -l app.kubernetes.io/component=agent --prefix --since=1h > agents.log
```

None of these contain secrets. Attach them to an
[issue](https://github.com/Tessarac-LLC/natterjack/issues).
