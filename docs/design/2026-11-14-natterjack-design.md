# Natterjack design

Status: draft for review, 2026-11-14.

Natterjack is a Kubernetes operator that replaces the cloud NAT gateway with
highly available egress gateways running on the cluster's existing nodes. It
keeps what people use NAT gateways for (outbound internet access from private
subnets, stable public source IPs, zone redundancy) and removes the per-GB
processing charge and most of the hourly charge.

API group and tag prefix: `natterjack.io` (pending domain registration; one
constant in the code, see "Open items").

Release scope: v1.0.0 supports AWS (EKS and self-managed Kubernetes on EC2).
The controller talks to the cloud only through a provider interface, so GCP,
Azure and OCI are added as providers without changes to the API, the agent or
the data path. Their slot designs below record the research done so far; they
are not part of v1.0.0 and are not documented as supported until each has its
own end-to-end suite.

## 1. Goals and non-goals

Goals:

1. Outbound IPv4 internet access for pods and nodes in private subnets, without
   a managed NAT gateway. AWS in v1.0.0; GCP, Azure and OCI through the same
   provider interface afterwards.
2. High availability inside a zone and across zones. Losing a gateway moves new
   flows to a surviving gateway in the same zone in well under a second.
3. Throughput that scales with the number of gateways (active-active, no single
   bottleneck per zone).
4. A stable, known set of public source IPs for partner allowlists.
5. Secure by construction: a misconfigured cloud firewall must not expose the
   node or the private network. Every security claim has an automated test.
6. Works with any CNI and alongside service meshes.
7. No new nodes. Gateways run on nodes the customer already has.
8. No conflict with infrastructure as code. The operator never creates, edits
   or deletes cloud networking resources or tags.

Non-goals:

- IPv6 egress. IPv6 needs no NAT (for example, the AWS egress-only internet
  gateway has no charge). Natterjack leaves IPv6 traffic untouched and works in
  dual-stack clusters.
- Inbound traffic of any kind. Natterjack never configures destination NAT.
- Layer-7 egress policy (hostname allowlists, TLS origination). That belongs to
  a service mesh egress gateway, which Natterjack sits underneath (section 9).
- Removing the cloud's internet data-transfer charge. That is charged either
  way.

## 2. Cost model

Verified against provider pricing on 2026-11-14 (sources in
`docs/reference/pricing.md`, to be written with citations):

| Cloud | Managed NAT charge | Natterjack charge |
| --- | --- | --- |
| AWS | $0.045/hour per NAT gateway plus $0.045/GB processed (US East (Ohio) example on the VPC pricing page) | $0.005/hour per public IPv4 address; cross-AZ transfer ($0.01/GB each way) only while a zone has no healthy gateway |
| GCP | Cloud NAT gateway fee plus $0.045/GiB processed | $0.005/hour per external IPv4 address in use |
| Azure | $0.045/hour plus $0.045/GB processed (Standard NAT Gateway) | $0.005/hour per Standard static public IPv4 |
| OCI | No NAT gateway price found in Oracle's price list | Value on OCI is static IPs and control, not cost; documented as such |

Internet data transfer is charged on every cloud in both designs and is out of
scope.

## 3. Prior art and the gap

| Project | Clouds | CNI | HA model | Runs on existing nodes |
| --- | --- | --- | --- | --- |
| Cilium egress gateway (OSS) | Any | Cilium only, with kube-proxy replacement and BPF masquerade | One gateway per policy; failover is an open issue (cilium/cilium#18230). HA is in Isovalent Enterprise | Yes |
| Azure kube-egress-gateway | Azure only | Chained CNI; not Azure CNI dynamic IP | At least two dedicated gateway nodes behind an internal load balancer | No |
| Antrea Egress | Any, with per-cloud manual IP work | Antrea | Gossip election plus gratuitous ARP; on AWS the IP must also be assigned in EC2 by something else | Yes |
| Calico egress gateway | AWS and others | Calico Enterprise or Cloud with Calico IPAM; incompatible with AWS VPC CNI | Health-probed replicas | Dedicated subnet per zone |
| Kube-OVN VPC egress gateway | Underlay networks | Kube-OVN plus Multus | Active-active ECMP, BFD failover under a second | Yes |
| spidernet-io/egressgateway | Any | Calico, Flannel, Weave, Spiderpool, Cilium native mode | Failover to backup node | Yes; nodes need public IPs on AWS |
| fck-nat | AWS only | n/a (EC2 instance) | Auto scaling group replacement, about 5 minutes | No |
| alterNAT | AWS only | n/a (EC2 instances) | Lambda checks each minute, falls back to a NAT gateway | No |

The gap Natterjack fills: active-active per zone with sub-second failover, any
CNI including the AWS VPC CNI, all four major clouds, a fixed public IP pool
owned by the customer's IaC, node traffic as well as pod traffic, and a
security model that holds when the cloud firewall is misconfigured.

## 4. Architecture

Two binaries, one Helm chart.

### 4.1 Components

**Controller** (Deployment, two replicas, leader election through a Lease).
The only component with cloud credentials. It:

- discovers egress slots in the cloud by tag (section 5);
- validates every slot against the safety checks (section 7.4);
- assigns each healthy slot to an eligible node in the slot's zone and attaches
  it through the cloud API;
- labels the agent pod on that node as a gateway and records the assignment in
  the `EgressPool` status;
- repairs: when a gateway node is lost or drained, moves its slot to another
  node in the same zone;
- reports every mismatch and misconfiguration (section 8).

**Agent** (DaemonSet on every Linux node). Holds no cloud credentials. On every
node it steers selected traffic to gateways. On a node assigned a slot it also
acts as the gateway. It needs `CAP_NET_ADMIN` and host networking, the same
privilege a CNI plugin or kube-proxy has; this is the main privilege Natterjack
adds to a cluster and the documentation says so.

### 4.2 Gateway membership: Kubernetes-native

A headless Service selects agent pods labelled `natterjack.io/gateway=true`.
Each gateway agent pod has a readiness gate that the agent sets true only once
its slot is attached, its isolated namespace is configured and a self-test to
the internet passes. The EndpointSlices of that Service are therefore the list
of working gateways, each with its zone, maintained by Kubernetes itself.
Every agent watches them.

### 4.3 Data path (all in the Linux kernel; no packet passes through Go)

Source node:

1. nftables marks traffic from selected pods (by `EgressPolicy`, section 6)
   and, once the agent runs, the node's own internet-bound traffic. Cluster,
   VPC and configured private destinations are never steered.
2. For the first packet of a flow, the mark selects a gateway: hash of the
   flow's 5-tuple into the table of healthy gateways in the node's zone, or in
   other zones when the node's zone has none. The choice is saved in the
   conntrack mark, so later packets of the flow, and every flow already
   established, keep their gateway when the table changes. Only new flows use
   the updated table.
3. Policy routing sends marked packets into a GENEVE tunnel to the chosen
   gateway's node IP. GENEVE rather than WireGuard by default: the traffic is
   bound for the internet, the tunnel stays inside the VPC, and encryption
   costs CPU that limits throughput. WireGuard is a per-pool option.
4. TCP MSS is clamped on steered flows to account for the tunnel header, so
   clouds with a 1460 or 1500 byte VPC MTU work without fragmentation. On AWS
   the 9001 byte VPC MTU absorbs the header.

Gateway node:

1. The tunnel ends in a dedicated network namespace owned by the agent. The
   cloud egress interface or IP lives only in that namespace (section 7.1).
2. nftables in that namespace source-NATs to the slot's public IP and sends
   the packet out. Replies are reverse-translated by conntrack and returned
   through the tunnel to the source node.

Throughput per zone is the sum of its gateways, bounded per gateway by the
cloud's per-instance internet bandwidth and per flow by the cloud's per-flow
limit (published in `docs/reference/bandwidth.md`). Customers add capacity by
tagging more slots.

An eBPF fast path (tc programs in C, built with `bpf2go` and loaded by the
agent through `cilium/ebpf`) implements the same steering for data planes that
bypass netfilter: Cilium with eBPF host routing or kube-proxy replacement, and
Calico in eBPF mode. The agent detects the data plane and selects the mode;
the mode can be forced in values.

### 4.4 Failure detection and failover

- Each agent probes every gateway it may use with a small UDP echo sent
  through the tunnel, so the probe tests the same path traffic takes. Default
  interval 100 ms, three misses to declare down (about 300 ms), configurable.
- A gateway declared down is removed from that node's hash table immediately.
  Conntrack entries marked for it are flushed so the affected flows re-hash on
  their next packet. Those connections reset at the remote end, because their
  public source IP has changed; this is unavoidable while the IP is held by one
  interface and is documented. New connections and retries succeed at once.
- EndpointSlice readiness remains the source of truth for which gateways
  exist; probes only decide which of them are alive from this node.
- Cross-zone fallback happens only when a zone has no live gateway, and is
  reported (`CrossZoneEgress` condition and metric) because it adds cost.

### 4.5 Planned disruption

The controller watches nodes for cordon, drain and the Karpenter disruption
taint. Before a gateway node goes away the agent sets its readiness false,
agents stop sending new flows to it, existing flows get a configurable drain
window (default 60 s), then the controller detaches the slot and attaches it
to another eligible node in the same zone. Spot interruption notices start the
same sequence early.

## 5. Egress slots per cloud

A slot is the unit the customer creates in IaC: a public IPv4 address bound to
something the controller can move between nodes in one zone. The controller
discovers slots by two tags or labels (AWS is the v1.0.0 provider; the other
rows are the researched designs for later providers): `natterjack.io/egress=true` and
`natterjack.io/cluster=<cluster name>`. The cluster name is a required Helm
value. The controller never writes tags.

| Cloud | Slot | How the controller moves it | Node-traffic bootstrap route |
| --- | --- | --- | --- |
| AWS | A secondary ENI in a public subnet of the zone, with an Elastic IP associated in IaC, source/destination check disabled, a security group with no inbound rules | `AttachNetworkInterface` / `DetachNetworkInterface`. The Elastic IP is a property of the ENI and moves with it | Private subnet route `0.0.0.0/0` to the ENI, declared in IaC. It stays valid when the ENI moves, so the route table never changes |
| OCI | A secondary VNIC subnet's secondary private IP with a reserved public IP, VNIC set to skip the source/destination check | Move the private IP between VNICs in the same subnet; the reserved public IP follows it. Each gateway node carries a VNIC in the public subnet | Route rule to the private IP, declared in IaC, unchanged on failover |
| GCP | A reserved static external IPv4 address, labelled | Remove and add the access config on the gateway VM's NIC. GCP has no public-subnet requirement | None. GCP does not support GKE nodes as backends of an internal load balancer used as a route next hop, so node traffic is steered by the agent only. Before the agent runs, nodes rely on Private Google Access and an in-VPC registry |
| Azure | A Standard static public IPv4, tagged | Associate and disassociate on the gateway node's NIC IP configuration | User-defined route to an internal load balancer with HA ports in front of gateway nodes, if section 12 item 1 confirms it works for AKS nodes; otherwise agent steering only, as on GCP |

Customers choose how many slots to create. The controller runs one gateway
per healthy slot, at most one per node, capped by the optional
`maxGatewaysPerZone`.

AWS specifics:

- The VPC CNI is told to ignore the slot ENI with the
  `node.k8s.amazonaws.com/no_manage` tag, which the customer sets in IaC.
- EKS adds `aws:eks:cluster-name` to every node instance regardless of how it
  was provisioned, so IAM can restrict attach and detach to this cluster's
  instances with no customer tagging.
- An ENI that is the target of a private subnet route is attached first and
  moved first on failure, because node traffic that has not yet been steered
  by an agent depends on it.
- Terraform: the ENI must not declare an `attachment` block, and the
  documentation shows the `lifecycle { ignore_changes = [attachment] }`
  setting. This is verified by an IaC test in CI (section 10), not assumed.

## 6. API

All CRDs are in `natterjack.io`, version `v1alpha1` until the API is declared
stable.

`EgressPool` (cluster-scoped): discovery settings (cluster name, extra tag
filters), gateway node selector and tolerations, `maxGatewaysPerZone`, tunnel
type, probe timing, drain window, safety-check policy. Status: per-zone and
per-slot table (slot ID, zone, public IP, state, node, reason) and conditions
(`Ready`, `Degraded`, `CrossZoneEgress`, `SlotsQuarantined`,
`SlotsUnschedulable`, `ForeignSlots`).

`EgressPolicy` (namespaced): which workloads use a pool, selected by pod
labels, namespace labels or ServiceAccount; destination CIDRs to exclude in
addition to the built-in cluster, VPC and private ranges. A cluster-scoped
`ClusterEgressPolicy` covers platform-wide defaults and node traffic.

Kubernetes Events and Prometheus metrics accompany every status change.

## 7. Security model

### 7.1 Structural isolation

The slot's interface or address is moved into a network namespace that only
the agent's gateway function uses. Kubelet, host-network pods and every other
process in the host namespace cannot see it or bind to it. Even if the cloud
firewall allows all inbound traffic, nothing listens at the public IP.

### 7.2 Rules in the gateway namespace

1. Default drop for new inbound connections; only replies to connections
   started from inside are accepted.
2. No destination NAT is ever configured, so no path from the internet into
   the private network exists.
3. Forward only from cluster, VPC and pod ranges (anti-spoofing). Never forward
   from the public side toward private addresses.
4. Tunnel endpoints accept GENEVE only from cluster node IPs.

### 7.3 Least privilege

- Cloud credentials only in the controller, through workload identity (EKS
  Pod Identity or IRSA, GKE Workload Identity, Azure Workload Identity, OCI
  workload identity). The policy for each cloud ships as JSON or HCL.
- AWS: attach and detach scoped by tag on the ENI and by
  `aws:eks:cluster-name` on the instance. The `ec2:Describe*` calls cannot be
  scoped to resources; the documentation says so.
- Kubernetes RBAC: minimal, listed line by line in the documentation.

### 7.4 Safety checks before a slot is used

The controller refuses (quarantines) a slot and reports the reason when:

- its security group or equivalent has any inbound rule;
- its subnet has no route to an internet gateway (AWS, OCI);
- it has no public IP;
- source/destination checking or IP forwarding is not set as required;
- it is attached to an instance outside this cluster.

These are defence in depth; section 7.1 is what holds when they are bypassed.
`safetyChecks: enforce` is the default; `warn` exists for break-glass.

### 7.5 Proof

`SECURITY.md` holds the threat model. Every claim names the control that
enforces it and the test that proves it. The attack suite (section 10) runs on
every release against deliberately misconfigured slots and publishes signed
results with the release.

## 8. Mistake handling

| Situation | Behaviour |
| --- | --- |
| More healthy slots than the cap | Extras stay unattached as `Spare` and replace failed slots first |
| Fewer slots than zones need | Runs with what exists; `Degraded` per zone without in-zone redundancy |
| A zone with no slots | Its pods use other zones; `CrossZoneEgress` with the cost reason; nodes there have no bootstrap route, reported |
| Slot in a zone with no eligible node | `Unschedulable`, naming the zone and why no node is eligible |
| Slot fails safety checks | `Quarantined` with the failed check |
| Tag present, cluster name differs | Ignored and listed, so a typo is visible |
| Slot attached to a node not in this cluster | `Foreign`; never touched |
| Slot deleted by IaC while in use | Traffic steers away; reported |
| Node at its interface limit | Another node is chosen |
| Workload identity misconfigured | Controller `Ready=false` with the exact failing call and the expected trust policy subject for the namespace and ServiceAccount in use |

`natterjack doctor` (CLI) and `helm test` run all checks before any traffic
moves and print a go or no-go report.

## 9. Service mesh and CNI compatibility

- Natterjack works at layer 3, below a mesh. Sidecar proxies and ztunnel
  originate traffic from the pod's network namespace, so selection by source
  pod still applies; the exact source address in each mesh mode is confirmed
  by packet capture in the compatibility tests, not assumed.
- Tunnel traffic is host-network and is never captured by a mesh.
- Reference architecture: a mesh egress gateway for layer-7 policy, its pods
  selected by an `EgressPolicy` so their traffic leaves through Natterjack.
- `EgressPolicy` can select by ServiceAccount to align with mesh identities;
  metrics carry namespace, workload and ServiceAccount labels.
- Compatibility matrix tested in CI: AWS VPC CNI; Calico iptables and eBPF
  modes; Cilium default and kube-proxy-free; Istio sidecar and ambient;
  Linkerd. Published in the README.

## 10. Testing

- Unit tests for slot discovery, assignment, hashing, safety checks and every
  row of section 8.
- Controller tests with envtest and a fake cloud implementing the provider
  interface.
- Data-plane integration tests in kind: steering, failover timing, conntrack
  behaviour, MSS clamping, isolation rules, both nftables and eBPF modes.
- End-to-end on real clusters per cloud (EKS, GKE, AKS, OKE). CI builds the
  network and cluster from Terraform with OIDC credentials, runs the suite,
  destroys everything.
- Attack suite on real clusters: slots deliberately opened to all inbound
  traffic; external scans of every public IP; attempts to reach kubelet and
  host-network ports; packets addressed to private IPs sent to the public IP;
  spoofed sources; all must be dropped.
- Failure tests: kill a gateway node, drain it, delete a slot, break workload
  identity, exceed interface limits; measure failover time.
- Throughput benchmarks per cloud and instance size, published.
- IaC tests: apply the shipped Terraform modules, let the controller move an
  ENI, assert `terraform plan` shows no changes.

## 11. Build, release and documentation

- Go for the controller, agent and CLI (kubebuilder layout, controller-runtime,
  `vishvananda/netlink`, `google/nftables`, `cilium/ebpf`). Dependencies at the
  latest releases, recorded in `go.sum`.
- GitHub Actions: lint, unit, envtest, kind integration, e2e and attack suites,
  compatibility matrix, benchmarks.
- Multi-arch images (amd64, arm64), distroless, signed with cosign, with SBOM
  and SLSA provenance, published to `ghcr.io/tessarac-llc`.
- Helm chart published as an OCI artifact to GHCR and listed on Artifact Hub.
- Licence: Apache-2.0. Contributions under the DCO.
- Documentation: README with a one-page quick start; per-cloud prerequisites
  with shipped Terraform and native-template examples; deployment order
  (including the new-cluster bootstrap: install with an in-VPC registry or
  before removing the existing NAT); migration from a managed NAT gateway;
  per-cloud bandwidth tables summarised by instance family and size cut-offs;
  pricing comparison; `SECURITY.md`; mesh reference architecture;
  troubleshooting by status condition; Helm values reference with every value
  explained and annotated examples for each cloud.
- The chart lets customers choose the namespace and which components to
  install. Nothing looks up another component by a fixed namespace. The chart
  can create the namespace with the Pod Security `privileged` label or verify
  the label on an existing one and fail with a clear message.

## 12. Open items requiring hands-on verification

These are settled by tests early in implementation; the design names the
fallback for each.

1. Azure (not in v1.0.0): whether a public IP can be associated with an AKS scale-set node's
   NIC IP configuration at runtime, and whether a user-defined route can use an
   internal load balancer fronting AKS nodes as next hop. Fallback: slot as a
   public IP on a secondary IP configuration set at node-pool creation, agent
   steering only for node traffic.
2. OCI (not in v1.0.0): whether a secondary VNIC can be attached to a running OKE worker and
   whether moving a private IP between VNICs needs any instance state change.
3. AWS VPC CNI: behaviour when an ENI tagged `no_manage` is moved into a
   network namespace, and on node reboot.
4. Mesh source addresses: packet capture for Istio sidecar, Istio ambient and
   Linkerd.
5. Domain: register `natterjack.io` (or choose another owned domain) before
   the first tagged release; the prefix is one constant until then.
6. Per-cloud end-to-end accounts and projects dedicated to this project.
