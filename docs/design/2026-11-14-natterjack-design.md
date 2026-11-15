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
acts as the gateway. It runs privileged with host networking, as CNI plugins
do: `CAP_NET_ADMIN` for nftables, routes, rules, links and conntrack, and
`CAP_SYS_ADMIN` to create the gateway network namespace and pin it with a bind
mount under `/run/natterjack` (a host path mounted with bidirectional
propagation), so the namespace and the slot inside it survive an agent
restart. This is the main privilege Natterjack adds to a cluster and the
documentation says so. Its metrics are served on port 9751 with
authentication and authorization through the API server, its health probes on
port 9752.

The agent reconciles one work item: on any change to its node's pods, all
nodes, namespaces, policies, pools, gateway pods or probe results, and every
30 seconds, it computes the whole desired data path and applies it. Each step
replaces what is there, so a missed event costs at most one resync.

### 4.2 Gateway membership: Kubernetes-native

The controller labels the agent pod on a gateway node
`natterjack.io/gateway=true` with its pool, and annotates it with the slot
assignment (slot ID, MAC, private IP, subnet CIDR, public IP, tunnel type).
Every agent watches agent pods with that label, so the list of gateways, each
with its node and zone, comes from Kubernetes itself with no extra objects.

The gateway agent reports that it carries traffic through a pod condition,
`natterjack.io/gateway-ready`, which it patches on its own pod's status. The
condition is true only once the slot interface is in the isolated namespace
with its address and routes, and a self-test through the slot has passed since
serving began. Its message names the slot (`serving slot <id>`); the
controller and every agent count the condition only when that slot matches
the pod's current assignment, so a condition left over from an earlier slot
never vouches for a new one. A custom condition rather than a pod readiness
gate or a Service: the agent pod's own readiness stays about the agent, so a
gateway problem never restarts or removes the agent that steers the node's
own traffic.

The self-test runs every 30 seconds: the agent resolves a check-IP service
(`https://checkip.amazonaws.com` by default) in the host namespace, connects
from inside the gateway namespace and requires the reply to be the slot's
public IP. Readiness turns true on the first pass and false only after three
consecutive failures, so one slow response does not move traffic.

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
   costs CPU that limits throughput. WireGuard is a per-pool option. The
   tunnel is one collect-metadata GENEVE device (`nj0`) carrying IP packets,
   not Ethernet frames (Linux 5.18 or later); each gateway's routing table
   sets the destination node per route. Each table also has a throw route for
   the gateway's own node IP, so the tunnel's outer packets never loop back
   into it. `nj0` has a host-scope /32 link-local address only so reverse
   path filtering accepts replies arriving on it.
4. Steered packets are source-translated to the node's IP as they enter the
   tunnel, so replies return to this node whatever the pod network is; the
   reverse translation by conntrack restores the pod address.
5. TCP MSS is clamped on steered flows to account for the tunnel header, so
   clouds with a 1460 or 1500 byte VPC MTU work without fragmentation. On AWS
   the 9001 byte VPC MTU absorbs the header.

A pool with `tunnel: WireGuard` encrypts the hop from source node to gateway
(Linux 5.6 or later). Each agent keeps a WireGuard private key in its state
directory, so it survives agent restarts and a reboot makes a new one, and
publishes the public key as its pod's `natterjack.io/wireguard-key` condition;
only the agent on a node can write its own pod's status (section 7.3). A
source node has one device per encrypted gateway (`njw-<n>`) whose only peer is
that gateway, at its node IP and `agent.wireguardPort` (UDP 51871 by default);
the gateway's routing table sends everything to that device. A gateway of an
encrypted pool listens on `njwg`, whose peers are the cluster's nodes, each
allowed only its own node IP, so WireGuard itself drops a forged inner source.
Replies return through `njwg`. A pool set to WireGuard never falls back to
GENEVE: a gateway that has not published a key gets no new flows, and a
packet for an encrypted gateway that arrives on `nj0` is dropped (section
7.2).

Gateway node:

1. The tunnel ends in a dedicated network namespace owned by the agent. The
   cloud egress interface or IP lives only in that namespace (section 7.1).
2. nftables in that namespace source-NATs to the slot's public IP and sends
   the packet out. Replies are reverse-translated by conntrack and returned
   through the tunnel to the source node.

The agent refuses a node where `net.ipv4.conf.all.rp_filter` is 1 (strict),
because replies from the tunnel would be dropped, and names the setting; EKS
AMIs use 2.

Throughput per zone is the sum of its gateways, bounded per gateway by the
cloud's per-instance internet bandwidth and per flow by the cloud's per-flow
limit (published in `docs/reference/bandwidth.md`). Customers add capacity by
tagging more slots.

An eBPF fast path covers data planes that move pod traffic from the pod's
device straight to the node's uplink, so the host's netfilter hooks never see
it: Cilium with eBPF host routing, and Calico's eBPF data plane. It does not
reimplement the steering. Two tc programs (C in
`internal/agent/dataplane/bpf/steer.c`, built reproducibly by `make bpf` in a
pinned builder image, embedded in the agent and loaded through `cilium/ebpf`)
sit first on every uplink, the device with the node's address and every
device a default route uses, through tcx links anchored at the head of each
hook, ahead of the CNI's own programs; tcx needs Linux 6.6 or later.

- The egress program takes a packet from a steered pod to a destination that
  is not excluded, rewrites its destination MAC and redirects it into the
  ingress of a dummy device, `njd0`. The packet re-enters the host's stack
  there, and the same nftables rules as in nftables mode pick its gateway,
  translate it and send it into the tunnel. A packet arriving from `njd0`
  that nftables left unsteered (a per-steer exclusion, no live gateway) goes
  out as it is, so nothing loops.
- Replies to connections that came in from outside reach the pod the same
  way and would look new to the host's conntrack. The ingress program records
  each connection that comes in to a steered pod, from a peer that is not
  excluded, in an LRU map, and the egress program leaves its replies alone.
- The maps (steered pods, excluded prefixes as an LPM trie, inbound
  connections, a diverted-packet counter) and the links are pinned under
  `/sys/fs/bpf/natterjack`, so the fast path keeps working while the agent
  restarts. Each Apply checks the links are still first on their hooks,
  updates them in place with the new programs, or attaches anew at the head
  when a CNI that started later put its program ahead; links of devices that
  are no longer uplinks are removed. Maps from an incompatible earlier
  version are replaced.

`--steering=auto`, the default, selects eBPF on nodes with a `cilium_host`,
`bpfin.cali` or `bpfout.cali` device; the chart's `agent.steering` forces
`nftables` or `ebpf`. Switching to nftables mode, and uninstalling, removes
the links, maps and `njd0`. The agent reports its mode as
`natterjack_agent_steering_mode` and the diverted count as
`natterjack_agent_ebpf_diverted_packets_total`.

### 4.4 Failure detection and failover

- Each agent probes every gateway it may use with a small UDP echo sent
  through the tunnel, so the probe tests the same path traffic takes: the
  probe socket carries the gateway's packet mark, the probe is translated to
  the node's IP like steered traffic, and the gateway answers on the
  gateway-namespace end of its internal link, accepting probes only from
  cluster nodes. A probe is 12 bytes, a magic value and a sequence number;
  the responder ignores anything else and answers only while it serves a
  slot, including while draining, so draining gateways keep their existing
  flows. The responder is a tc program on that link, so it keeps answering
  while the agent restarts; it also checks that the gateway namespace still
  routes out, so a slot whose interface has gone stops answering with no
  agent running. Default interval 100 ms, three misses to declare down (about
  300 ms), configurable per pool. One reply brings a gateway back.
- A gateway declared down is removed from that node's hash table immediately.
  Conntrack entries marked for it are flushed so the affected flows re-hash on
  their next packet. Those connections reset at the remote end, because their
  public source IP has changed; this is unavoidable while the IP is held by one
  interface and is documented. New connections and retries succeed at once.
- The gateway-ready condition remains the source of truth for which gateways
  take new flows; probes only decide which of them are alive from this node.
- Cross-zone fallback happens only when a zone has no live gateway, and is
  reported (`CrossZoneEgress` condition and metric) because it adds cost.

### 4.5 Planned disruption

The controller watches nodes for cordon, drain and the Karpenter disruption
taint. Before a gateway node goes away the controller annotates the gateway
pod `natterjack.io/drain-started`; the agent sets the gateway-ready condition
false with reason `Draining`, agents stop sending new flows to it, existing flows get a configurable drain
window (default 60 s), then the controller detaches the slot and attaches it
to another eligible node in the same zone. Spot interruption notices start the
same sequence early.

An agent restart, including a rolling upgrade, moves nothing. The slot, its
routes and rules, the tunnel and the probe responder are kernel state and stay
while the agent is gone. The controller keeps a slot on its node for a minute
while that node's agent pod is missing or terminating and the node is ready
and not being drained. The new agent reads the assignment its predecessor
saved under `/run/natterjack` and serves it until the controller writes the
assignment on the new pod. Every other agent keeps the gateway in use for up
to 90 seconds while its new agent starts on the same slot, ending the hold as
soon as the new agent reports a failure, the slot is drained or reassigned, or
the node goes. Probes still decide liveness throughout. A restart longer than
a minute moves the slot as a failure would.

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
4. Tunnel endpoints accept GENEVE and WireGuard only from cluster node IPs.

Traffic injected into the tunnel meets four independent checks, each tested
alone by an outsider on the same network that forges tunnel packets and
probes:

1. Host `input`: GENEVE packets from an address that is not a cluster node are
   dropped before decapsulation.
2. Host `prerouting`: a new flow arriving out of the tunnel whose inner source
   is not a cluster node is dropped.
3. Host `forward`: a new flow out of the tunnel may only go into the gateway
   namespace, and only on a node that serves a slot; on any other node it is
   dropped, so the tunnel can never be used to reach the node's networks.
4. Gateway namespace `forward` and `input` default to drop: only flows from
   cluster nodes through the internal link, and flows routed to the slot by a
   VPC route before agents steer, leave; only replies and node probes enter.

For an encrypted pool, two more rules keep traffic from being downgraded to
plain GENEVE: the gateway's policy rule sends only packets arriving on `njwg`
into the gateway namespace, and host `forward` lets a new flow into the
gateway namespace only from that pool's tunnel device. The privileged tests
replace a source node's WireGuard route with GENEVE and require that no reply
comes back, and an outsider with its own WireGuard key gets no handshake and
no reply.

When the agent is uninstalled (its DaemonSet is gone or being deleted), it
removes every kernel object it owns before exiting. A gateway namespace that
still holds a slot interface stays until the controller detaches it, so the
interface never returns to the host namespace.

### 7.3 Least privilege

- Cloud credentials only in the controller, through workload identity (EKS
  Pod Identity or IRSA, GKE Workload Identity, Azure Workload Identity, OCI
  workload identity). The policy for each cloud ships as JSON or HCL.
- AWS: attach and detach scoped by tag on the ENI and by
  `aws:eks:cluster-name` on the instance. The `ec2:Describe*` calls
  (instances, network interfaces, subnets, route tables, security groups)
  cannot be scoped to resources; the documentation says so. The controller
  reads each slot's subnet CIDR so the agent can address the slot and route
  through the subnet's router.
- Kubernetes RBAC: minimal, listed line by line in the documentation.
- An agent may change only its own pod's status, enforced by an admission
  policy on the pod name bound into its ServiceAccount token. Its readiness,
  self-test and WireGuard key conditions therefore cannot be forged from
  another node.

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
| A reconcile keeps failing | Retried with exponential backoff from 100 ms, capped at the resync interval, so a fixed problem is picked up within one resync |

`natterjack doctor` (CLI) and `helm test` run all checks before any traffic
moves and print a go or no-go report. The doctor only reads, and reports
from what the components themselves publish, so it sees what they see:

- Kubernetes is 1.34 or later.
- Exactly one release is found, or the one named with `--namespace` and
  `--release`.
- Controller replicas are ready, and the leader Lease is held, unexpired, by a
  running controller pod of that release.
- Every node the agent DaemonSet selects runs a ready agent whose
  `natterjack.io/dataplane-ready` pod condition is true; otherwise the node and
  the agent's own error are named. Gateways that hold a slot serve it.
- Each installed component's ValidatingAdmissionPolicy exists with a denying
  binding.
- Every EgressPool is reconciled and ready. `CloudAccess=False` carries the
  failing call and the identity in use. Degradation, cross-zone egress,
  quarantined, unschedulable and foreign slots are warnings.
- Every policy is accepted.

Exit status 0 is go and 1 is no-go. `-o json` gives the same report for
automation. The `helm test` pod runs the CLI image with read-only RBAC that
exists only while the test runs.

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
- Data-plane tests in throwaway privileged containers on every pull request
  (`make test-privileged`): a single node serving its own pods, stale-flow
  flushing, and a three-node tunnel (gateway, source and outsider) covering
  steering, translation, probes, the self-test through the slot and every
  injection check of section 7.2.
- Agent tests with envtest: the gateway-ready condition through pending,
  serving, self-test failure and recovery, draining and unassignment, probe
  replies, and refusing a pod that does not match the agent selector.
- Chart tests on every pull request: `helm lint`, every rendering validated
  against the Kubernetes schemas, and every bad value refused with a clear
  message (`make chart-lint`); then a kind install on the oldest and newest
  supported Kubernetes (`make chart-e2e`) proving no RBAC denials, no grant
  beyond what each binary uses, both admission policies with pod-bound
  tokens, recovery within one resync, `helm test` reporting no-go with the
  controller's cloud identity when no cloud is reachable, and an uninstall
  that leaves no kernel objects and no chart objects behind.
- Release dry run on every pull request (`make release-dry-run`): a full
  release pushed to a throwaway registry, then checked as a user would pull
  it: multi-arch images with SBOMs and stamped versions, a chart pinned to
  exactly those digests, and CLI archives rebuilt byte for byte.
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
- The `natterjack` CLI as an image (run by `helm test`) and as reproducible
  archives for Linux, macOS and Windows on amd64 and arm64, with SLSA
  provenance and SHA-256 sums on the GitHub release.
- Licence: Apache-2.0. Contributions under the DCO.
- Documentation: README with a one-page quick start; per-cloud prerequisites
  with shipped Terraform and native-template examples; deployment order
  (including the new-cluster bootstrap: install with an in-VPC registry or
  before removing the existing NAT); migration from a managed NAT gateway;
  per-cloud bandwidth tables summarised by instance family and size cut-offs;
  pricing comparison; `SECURITY.md`; mesh reference architecture;
  troubleshooting by status condition; Helm values reference with every value
  explained and annotated examples for each cloud.
- Kubernetes 1.34 or later: ValidatingAdmissionPolicy and the pod-name claim in
  bound ServiceAccount tokens are GA there.
- The values reference in the chart README is generated from `values.yaml` by
  helm-docs, and CI fails when it is stale. `values.schema.json` rejects
  unknown keys and malformed values before anything renders.
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
