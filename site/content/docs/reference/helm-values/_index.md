---
title: Helm values
weight: 10
description: Every value the Natterjack chart takes, with annotated examples for common installations.
---

<!-- Generated from charts/natterjack/values.yaml by 'make chart-docs'. Edit
site/helm-values.md.gotmpl or the comments in values.yaml, not this file. -->

The chart validates every value against its schema, so a misspelled key or a
value of the wrong type fails `helm install` rather than being ignored.

## Examples

### EKS with Pod Identity

The smallest installation. The controller's role comes from the Terraform
module or the CloudFormation templates, bound to its ServiceAccount by an EKS
Pod Identity association, so the ServiceAccount needs no annotation.

```yaml
# The name the slots are tagged with: natterjack.io/cluster=prod-east.
clusterName: prod-east
namespace:
  # Create the namespace with the Pod Security "privileged" label the agent
  # needs. Do not also pass Helm's --create-namespace.
  create: true
controller:
  aws:
    region: us-east-1
```

### IAM roles for service accounts

```yaml
clusterName: prod-east
controller:
  aws:
    region: us-east-1
  serviceAccount:
    annotations:
      # The module's controller_role_arn output.
      eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/natterjack-prod-east
```

### Calico

Calico keeps its packet marks in `0xffff0000`, which overlaps the agent's
default. Give the agent bits Calico does not use. With Calico's eBPF data
plane, `steering: auto` already picks `ebpf`.

```yaml
agent:
  markMask: "0x00003f00"
```

### Public ranges inside the VPC

Private, shared, link-local and reserved ranges are never steered. A VPC that
uses public addresses internally lists them, so traffic to them stays on the
VPC's own routes.

```yaml
agent:
  excludedCIDRs:
    - 100.20.0.0/16
```

### Pinned images from a mirror

Pin every image by digest, as printed by the release notes and checked by
[Verifying a release](../../security/verify/). A digest takes precedence over
a tag.

```yaml
images:
  pullSecrets: [registry-mirror]
controller:
  image:
    repository: registry.example.com/natterjack/natterjack-controller
    digest: sha256:<controller digest>
agent:
  image:
    repository: registry.example.com/natterjack/natterjack-agent
    digest: sha256:<agent digest>
doctor:
  image:
    repository: registry.example.com/natterjack/natterjack
    digest: sha256:<natterjack digest>
```

### Faster upgrades on large clusters

An agent restart leaves the node's slot, its traffic and the probe responder
in the kernel, so restarting several agents at once interrupts nothing that
finishes within a minute.

```yaml
agent:
  updateStrategy:
    maxUnavailable: 10%
```

## All values

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `agent.affinity` | object | `{}` | Affinity for agent pods. |
| `agent.enabled` | bool | `true` | Install the agent DaemonSet. |
| `agent.excludedCIDRs` | list | `[]` | Destinations never steered, in addition to private, shared, link-local and reserved ranges. Add any public ranges your VPC uses. |
| `agent.gatewayLink` | string | `"169.254.73.0/30"` | Link-local /30 between the host and gateway namespaces. |
| `agent.image.digest` | string | `""` | Pin by digest; takes precedence over the tag. |
| `agent.image.repository` | string | `"ghcr.io/tessarac-llc/natterjack-agent"` | Agent image repository. |
| `agent.image.tag` | string | `""` | Defaults to the chart's appVersion. |
| `agent.logLevel` | string | `"info"` | Log level: debug, info or error. |
| `agent.markMask` | string | `"0x00ff0000"` | Packet mark bits the agent owns: one contiguous run of at least four bits that no other component on the node uses. The default suits the AWS VPC CNI (0x80), kube-proxy (0x4000, 0x8000), kindnet, Cilium and Istio. Calico keeps its marks in 0xffff0000: use "0x00003f00" with it. An agent that finds another component's nftables or policy routing rules using its bits reports its node's data path not ready and names the rule. |
| `agent.mss` | int | `1460` | TCP MSS ceiling for flows leaving a slot. |
| `agent.nodeSelector` | object | `{"kubernetes.io/os":"linux"}` | The agent runs on every Linux node. Narrow this only if some nodes never send traffic through Natterjack and never serve as gateways. |
| `agent.podAnnotations` | object | `{}` | Extra annotations on agent pods. |
| `agent.podLabels` | object | `{}` | Extra labels on agent pods. |
| `agent.ports.health` | int | `9752` | Host port for the agent's liveness and readiness probes. |
| `agent.ports.metrics` | int | `9751` | Host port for the agent's metrics, which require an authorized Kubernetes identity. |
| `agent.priorityClassName` | string | `"system-node-critical"` | A node without its agent sends no traffic through Natterjack, so the agent is scheduled ahead of ordinary workloads. |
| `agent.probePort` | int | `6086` | UDP port gateways answer probes on, inside their namespace. |
| `agent.resources` | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | Agent container resources. A gateway node's forwarding happens in the kernel and is not counted here. |
| `agent.resync` | string | `"30s"` | How often the data path is re-applied when nothing changes. |
| `agent.routeTableBase` | int | `7700` | First policy routing table the agent owns. |
| `agent.rulePriority` | int | `1000` | Priority of the agent's policy routing rules; they use this and the next two. They must sort ahead of any rule that routes pod traffic by its source or by a mark carried on every packet of a connection, such as the AWS VPC CNI's (1024 and 1536). An agent that finds such a rule ahead of its own reports its node's data path not ready and names the rule. |
| `agent.selfTest.interval` | string | `"30s"` | How often a gateway tests its slot. |
| `agent.selfTest.url` | string | `"https://checkip.amazonaws.com"` | URL that answers with the caller's public IPv4 address. |
| `agent.serviceAccount.name` | string | `""` | ServiceAccount name. Defaults to `<release>-agent`. |
| `agent.stateDir` | string | `"/run/natterjack"` | Host directory for the gateway namespace mount and the mark table. It must be on a filesystem a reboot empties (a tmpfs under /run). |
| `agent.steering` | string | `"auto"` | How pod traffic is steered. `nftables` steers in the host's netfilter hooks. `ebpf` also puts tcx programs first on the node's uplinks, for CNIs that move pod traffic past netfilter (Cilium with eBPF host routing, Calico's eBPF data plane); it needs Linux 6.6 or later. `auto` picks `ebpf` on nodes running such a CNI. |
| `agent.tolerations` | list | `[{"operator":"Exists"}]` | The agent tolerates every taint by default so it runs on every node. |
| `agent.tunnelPort` | int | `6081` | GENEVE UDP port between nodes. Node security groups must allow it between nodes. |
| `agent.updateStrategy.maxUnavailable` | int | `1` | Agents restarted at once during an upgrade. A restart does not move the node's gateway role: the slot, its traffic and the probe responder stay in the kernel while the new agent starts. A restart that takes longer than a minute does move it. |
| `agent.wireguardPort` | int | `51871` | WireGuard UDP port between nodes, for pools with `tunnel: WireGuard`. Must differ from tunnelPort. Node security groups must allow it between nodes. |
| `clusterName` | string | `""` | Name of this cluster. The controller only uses egress slots tagged `natterjack.io/cluster=<clusterName>`. Required. |
| `controller.affinity` | object | `{}` | Affinity for controller pods. |
| `controller.aws.region` | string | `""` | AWS region of the cluster's VPC. Required when the controller is enabled. |
| `controller.enabled` | bool | `true` | Install the controller. Only one controller runs per cluster. |
| `controller.image.digest` | string | `""` | Pin by digest; takes precedence over the tag. |
| `controller.image.repository` | string | `"ghcr.io/tessarac-llc/natterjack-controller"` | Controller image repository. |
| `controller.image.tag` | string | `""` | Defaults to the chart's appVersion. |
| `controller.logLevel` | string | `"info"` | Log level: debug, info or error. |
| `controller.nodeSelector` | object | `{"kubernetes.io/os":"linux"}` | Controller pods run on Linux nodes. Add your own constraints here. |
| `controller.podAnnotations` | object | `{}` | Extra annotations on controller pods. |
| `controller.podDisruptionBudget.enabled` | bool | `true` | Limit voluntary disruptions when more than one replica runs. |
| `controller.podDisruptionBudget.maxUnavailable` | int | `1` | Controller pods a voluntary disruption may take down at once. |
| `controller.podLabels` | object | `{}` | Extra labels on controller pods. |
| `controller.ports.health` | int | `8081` | Port for the controller's liveness and readiness probes. |
| `controller.ports.metrics` | int | `8443` | Port for the controller's metrics, which require an authorized Kubernetes identity. |
| `controller.priorityClassName` | string | `"system-cluster-critical"` | The controller keeps egress working, so it is scheduled ahead of ordinary workloads. |
| `controller.replicas` | int | `2` | Two replicas with leader election keep a controller ready to act when one is evicted. |
| `controller.resources` | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | Controller container resources. Memory grows with the number of nodes and pods the controller watches. |
| `controller.resync` | string | `"30s"` | How often the controller re-reads the cloud when nothing changes. |
| `controller.serviceAccount.annotations` | object | `{}` | Annotations, for example eks.amazonaws.com/role-arn for IRSA. EKS Pod Identity needs none. |
| `controller.serviceAccount.name` | string | `""` | ServiceAccount name. Defaults to `<release>-controller`. |
| `controller.tolerations` | list | `[]` | Tolerations for controller pods. |
| `controller.topologySpreadConstraints` | list | `[]` | Defaults spread replicas over zones and nodes. |
| `crds.install` | bool | `true` | Install and upgrade the CustomResourceDefinitions with the chart. |
| `crds.keep` | bool | `true` | Keep the CRDs, and every pool and policy, when the release is uninstalled. |
| `doctor.enabled` | bool | `true` | Install the `helm test` that runs `natterjack doctor` in the cluster and fails unless the installation is ready to carry traffic. The test adds read-only RBAC only while it runs. |
| `doctor.image.digest` | string | `""` | Pin by digest; takes precedence over the tag. |
| `doctor.image.repository` | string | `"ghcr.io/tessarac-llc/natterjack"` | Image of the `natterjack` command-line tool. |
| `doctor.image.tag` | string | `""` | Defaults to the chart's appVersion. |
| `doctor.resources` | object | `{"limits":{"memory":"128Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Doctor container resources. |
| `doctor.timeout` | string | `"60s"` | Time the checks may take. |
| `images.pullPolicy` | string | `"IfNotPresent"` | Pull policy for every image. |
| `images.pullSecrets` | list | `[]` | Image pull secrets, by name, for every component. |
| `namespace.create` | bool | `false` | Create the release namespace with the Pod Security "privileged" label the agent needs. When false, the chart checks that the existing namespace carries the label and fails with a clear message if it does not. |
