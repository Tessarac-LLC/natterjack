# Natterjack

Highly available, zone-aware egress gateways for Kubernetes that replace cloud NAT gateways.

![Version: 0.0.0-dev](https://img.shields.io/badge/Version-0.0.0--dev-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

Natterjack runs a controller and a node agent. The controller assigns egress
slots (an elastic network interface with an Elastic IP on AWS) to nodes in each
zone. The agents send selected pod traffic out through those slots. Only the
controller holds cloud credentials.

## Install

```sh
helm install natterjack oci://ghcr.io/tessarac-llc/charts/natterjack \
  --namespace natterjack --create-namespace \
  --set clusterName=<cluster> --set controller.aws.region=<region>
```

Before installing:

- Create the egress slots and the controller's IAM role. The Terraform module
  in [`deploy/terraform/aws`](../../deploy/terraform/aws) does both, and opens
  UDP `agent.tunnelPort` (6081 by default) and `agent.wireguardPort` (51871 by
  default) between nodes. With IRSA, set
  `controller.serviceAccount.annotations` to the role it outputs.
- Set `net.ipv4.conf.all.rp_filter` to 0 or 2 on every node. EKS AMIs already
  do. The agent refuses to steer traffic on a node in strict mode and says so.

## What the chart installs

| Object | Why |
| --- | --- |
| CRDs: `EgressPool`, `EgressPolicy`, `ClusterEgressPolicy` | The API. Kept on uninstall unless `crds.keep=false`. |
| Controller Deployment, two replicas | Leader election through the `natterjack-controller` Lease. |
| Agent DaemonSet on every Linux node | Privileged with host networking: it programs nftables, routes, rules, GENEVE links and conntrack, and pins the gateway network namespace under `agent.stateDir`. |
| ClusterRoles and Roles | Exactly the API calls each binary makes. |
| ValidatingAdmissionPolicies | An agent may change only its own pod's status. The controller may change only `natterjack.io/` labels and annotations, and only on agent pods. |

The release namespace must allow privileged pods. With `namespace.create=true`
the chart creates the namespace with the Pod Security `privileged` label.
Otherwise it refuses to install into a namespace that enforces a stricter
level. Do not combine `namespace.create=true` with Helm's `--create-namespace`.

Uninstalling removes every kernel object the agents created. The CRDs stay.

## Requirements

Kubernetes: `>=1.34.0-0`

## Values

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
| `agent.markMask` | string | `"0x00ff0000"` | Packet mark bits the agent owns: one contiguous run of at least four bits that no other component on the node uses. |
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
| `agent.rulePriority` | int | `7700` | Priority of the agent's policy routing rules. |
| `agent.selfTest.interval` | string | `"30s"` | How often a gateway tests its slot. |
| `agent.selfTest.url` | string | `"https://checkip.amazonaws.com"` | URL that answers with the caller's public IPv4 address. |
| `agent.serviceAccount.name` | string | `""` | ServiceAccount name. Defaults to `<release>-agent`. |
| `agent.stateDir` | string | `"/run/natterjack"` | Host directory for the gateway namespace mount and the mark table. It must be on a filesystem a reboot empties (a tmpfs under /run). |
| `agent.steering` | string | `"auto"` | How pod traffic is steered. `nftables` steers in the host's netfilter hooks. `ebpf` also puts tcx programs first on the node's uplinks, for CNIs that move pod traffic past netfilter (Cilium with eBPF host routing, Calico's eBPF data plane); it needs Linux 6.6 or later. `auto` picks `ebpf` on nodes running such a CNI. |
| `agent.tolerations` | list | `[{"operator":"Exists"}]` | The agent tolerates every taint by default so it runs on every node. |
| `agent.tunnelPort` | int | `6081` | GENEVE UDP port between nodes. Node security groups must allow it between nodes. |
| `agent.updateStrategy.maxUnavailable` | int | `1` | Agents restarted at once during an upgrade. Each restart moves that node's gateway role to another node in its zone. |
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
