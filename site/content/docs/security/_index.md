---
title: Security model
linkTitle: Security
weight: 50
description: What each part of Natterjack can do, what it cannot, and what an attacker gains by taking one over.
---

Natterjack sits in the path of a cluster's internet traffic and moves network
interfaces between machines, so it is built to need as little as possible.
Each claim below names where it is enforced.

## Who holds what

| Part | Runs as | Cloud access | Kubernetes access |
| --- | --- | --- | --- |
| Controller | Non-root (UID 65532), every capability dropped, read-only root filesystem, `RuntimeDefault` seccomp | Its own IAM role, through EKS Pod Identity or IRSA | Reads nodes, pools, policies and the pods in its namespace; writes pool and policy status; updates only Natterjack labels and annotations on agent pods |
| Agent, one per node | Privileged with host networking: it programs nftables, routes, policy rules, tunnels and eBPF on its node. Read-only root filesystem | None | Reads nodes, pods, namespaces, pools and policies; patches only its own pod's status |
| `natterjack doctor` | Non-root, during `helm test` only | None | Lists what it checks, through a Role that exists only for the test |

No part reads Secrets or ConfigMaps, and no part holds a credential another
part could use.

## Cloud permissions

The [Terraform module](../install/) gives the controller one IAM policy:

- `Describe*` calls for instances, network interfaces, route tables, security
  groups and subnets;
- `AttachNetworkInterface` and `DetachNetworkInterface` only on network
  interfaces tagged `natterjack.io/egress=true` and
  `natterjack.io/cluster=<this cluster>`, and only on instances tagged as
  members of this cluster (`aws:eks:cluster-name`, or
  `kubernetes.io/cluster/<name>` set to `owned` or `shared`).

It cannot create, delete or retag anything, and cannot touch Elastic IPs,
routes or security groups. Its role trusts only the controller's
ServiceAccount, through Pod Identity or through the cluster's OIDC provider
with `sub` and `aud` conditions, with sessions of at most an hour.

## Kubernetes guard rails

Two `ValidatingAdmissionPolicies` ship with the chart, both with
`failurePolicy: Fail`:

- **An agent may change only its own pod's status.** The policy compares the
  pod named in the request with the `authentication.kubernetes.io/pod-name`
  claim of the agent's bound ServiceAccount token. A taken-over agent cannot
  mark another node's gateway ready.
- **The controller may only update agent pods**, may change only
  `natterjack.io/` labels and annotations on them, and may never change a
  pod's spec, create a pod or delete one.

Both rely on Kubernetes 1.34, where these policies and the pod-name claim are
generally available. `natterjack doctor` fails when either policy is missing
or not enforced.

The metrics endpoints of the controller and agents serve TLS and require a
token allowed to read them, checked with `TokenReview` and
`SubjectAccessReview`.

## The data path

- **Slots take no connections from the internet.** A slot's security group
  admits at most the VPC's own IPv4 blocks, which a bootstrap route needs;
  the controller quarantines a slot whose group admits any other source
  (another CIDR, IPv6, a prefix list or a security group), or whose
  source/destination check is turned back on.
- **The slot lives in its own network namespace.** The node's processes, CNI
  and firewall never see it. In that namespace, nftables drops everything
  except replies to flows that left, Natterjack's own probes from cluster
  nodes, and new flows that came from a cluster node over the tunnel or from
  a private address over the VPC route table.
- **Tunnel packets come only from cluster nodes.** Each node drops GENEVE and
  WireGuard packets from any other address, and forwards a tunnel's new flows
  only into its own gateway namespace.
- **Cluster, VPC and private ranges are never steered**, whatever a policy
  says, so a policy cannot send internal traffic to the internet.
- **Encryption between nodes is a choice.** GENEVE runs unencrypted inside
  the VPC. A pool with `tunnel: WireGuard` encrypts the hop from each node to
  its gateway. Each agent makes its own key, keeps the private half in
  `agent.stateDir` on the node (a reboot makes a new one), and
  publishes only the public half on its pod.
- **A gateway proves itself before it serves.** It sends a request out
  through its slot and checks the answer names the slot's public address
  before taking traffic.

## If an attacker takes over

| They hold | They can | They cannot |
| --- | --- | --- |
| A pod selected by a policy | Send traffic from the pool's public addresses, as the policy allows | Choose another gateway, public address or pool for its flows |
| A pod not selected | Nothing more than before Natterjack | Have its traffic steered |
| An agent, or root on a node | Everything root on that node can; disturb flows that use that node's gateway; read pod and node objects | Move a slot, change another node's status, or read cloud credentials |
| The controller | Detach and attach this cluster's slots between this cluster's nodes, which can disrupt egress | Reach any other ENI or instance, create anything in the cloud, or change pod specs |

## Supply chain

Every change to `main` needs a reviewed pull request with all checks passing.
Release tags can be made only by maintainers and never moved. Images are built
with `ko` on a base pinned by digest, signed with Sigstore, and
published with an SPDX SBOM and SLSA build provenance; the chart is signed and
pins every image by digest. [Verify a release](verify/) before installing it.

Report a vulnerability privately through
[GitHub](https://github.com/Tessarac-LLC/natterjack/security/advisories/new).
