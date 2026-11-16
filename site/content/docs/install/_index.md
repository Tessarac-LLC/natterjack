---
title: Installing on AWS
linkTitle: Install
weight: 15
description: Create slots with Terraform, install the chart, check it, and move traffic off a NAT gateway.
---

## Before you start

- An EKS cluster on Kubernetes 1.34 or later, with nodes on Linux 5.18 or
  later. Amazon Linux 2023 and Bottlerocket qualify; Amazon Linux 2 does not.
  See [Compatibility](../compatibility/).
- A public subnet in each zone that has nodes, routing `0.0.0.0/0` to an
  internet gateway.
- The `eks-pod-identity-agent` add-on, unless you use IAM roles for service
  accounts (IRSA).
- `net.ipv4.conf.all.rp_filter` set to 0 or 2 on every node. EKS AMIs already
  do; the agent refuses to steer on a node in strict mode and says so.

## 1. Create the slots and the controller's role

The Terraform module in
[`deploy/terraform/aws`](https://github.com/Tessarac-LLC/natterjack/tree/main/deploy/terraform/aws)
creates, for one cluster:

- `slots_per_subnet` slots (default 2) in each public subnet you give: an ENI
  with an Elastic IP, the source/destination check off, the Natterjack tags,
  and a security group with no inbound rules;
- the controller's IAM role, which may attach and detach only this cluster's
  slots, and only on this cluster's instances;
- optionally, the rule that lets the agent tunnel (UDP 6081) and WireGuard
  (UDP 51871) pass between nodes, and each zone's bootstrap route (see
  [step 5](#5-move-traffic-off-the-nat-gateway)).

```hcl
module "natterjack" {
  source = "github.com/Tessarac-LLC/natterjack//deploy/terraform/aws?ref=v1.0.0"

  cluster_name            = "prod-east"
  slot_subnets            = zipmap(module.vpc.azs, module.vpc.public_subnets)
  node_security_group_ids = [module.eks.node_security_group_id]
}
```

Two slots in a zone give it a second gateway, so a failed gateway's traffic
stays in the zone. The `public_ips` output lists the addresses selected
traffic leaves from; give them to anyone who allow-lists you.

With IRSA, set `identity = "irsa"` and `oidc_provider_arn`. The module's
README lists every input.

## 2. Install the chart

```sh
helm install natterjack oci://ghcr.io/tessarac-llc/charts/natterjack \
  --version 1.0.0 --namespace natterjack --create-namespace \
  --set clusterName=prod-east --set controller.aws.region=us-east-1
```

`clusterName` must match the module's `cluster_name`. With IRSA, also set
the role the module outputs:

```sh
--set-string 'controller.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=<controller_role_arn>'
```

The agent runs privileged, so the namespace must allow privileged pods. If
your cluster enforces Pod Security on new namespaces, install with
`--set namespace.create=true` and without `--create-namespace`: the chart then
creates the namespace with the `privileged` label. The chart refuses to
install into a namespace that enforces a stricter level.

Every value is described in the
[Helm values reference](https://github.com/Tessarac-LLC/natterjack/blob/main/charts/natterjack/README.md#values).
Before installing from a release, you can [verify](../security/verify/) the
chart and images.

## 3. Create a pool

```yaml
apiVersion: natterjack.io/v1alpha1
kind: EgressPool
metadata:
  name: default
spec: {}
```

With no settings, the pool claims every slot of the cluster that has no
`natterjack.io/pool` tag, and runs a gateway for each on any Linux node in
its zone. [Concepts](../concepts/#egresspool) describes every field. Within a
minute:

```sh
kubectl get egresspool default
```

shows `Ready` true and each slot `Active`.

## 4. Check the installation

```sh
helm test natterjack --namespace natterjack --logs
```

runs [`natterjack doctor`](../doctor/), which must report `GO`. It checks the
controller, every agent, the admission policies and the controller's cloud
access, and names anything to fix.

## 5. Move traffic off the NAT gateway

Nothing is steered until a policy selects it. Start with one namespace:

```yaml
apiVersion: natterjack.io/v1alpha1
kind: EgressPolicy
metadata:
  name: all
  namespace: shop
spec:
  poolName: default
  podSelector: {}
```

Check from a pod there that its public address is one of `public_ips`:

```sh
kubectl -n shop run ip --rm -it --restart=Never --image=curlimages/curl -- \
  curl -s https://checkip.amazonaws.com
```

Then select everything, including the nodes' own traffic:

```yaml
apiVersion: natterjack.io/v1alpha1
kind: ClusterEgressPolicy
metadata:
  name: everything
spec:
  poolName: default
  namespaceSelector: {}
  nodeTraffic: true
```

Nodes still need a way out before their agent runs, to pull images and join
the cluster. The module's `bootstrap_route_table_ids` points each private
subnet's default route at its zone's first slot, in place of the NAT
gateway:

```hcl
  bootstrap_route_table_ids = zipmap(module.vpc.azs, module.vpc.private_route_table_ids)
```

The route names the ENI, so it stays valid when the controller moves the slot
to another node. While that slot has no gateway, for instance during its
repair after a node failure, nodes in the zone that have no agent yet cannot
reach the internet; running agents steer around it.

Apply the routes, run `natterjack doctor` again, and delete the NAT gateways
once traffic has left through the slots for a while.

## A new cluster with no NAT gateway

On an existing cluster, install Natterjack before removing the NAT gateway,
as above: everything Natterjack needs comes through the NAT until its
gateways run.

A cluster created without a NAT gateway has a chicken-and-egg problem. Until
the controller runs, no slot is attached, so the bootstrap route leads
nowhere. The nodes must join, and pull Natterjack's images, without the
internet:

1. **VPC endpoints** in the private subnets: the S3 gateway endpoint, and
   interface endpoints for `ec2`, `ecr.api`, `ecr.dkr`, `sts`, `eks`, and
   `eks-auth` (Pod Identity). Add `ssm`, `ssmmessages` and `ec2messages` to
   reach nodes with Session Manager.
2. **Images in the VPC's reach.** Copy the chart and images to ECR in the
   cluster's account and region, after [verifying](../security/verify/) them
   on GHCR. A copy keeps each image's digest, which the chart pins:

   ```sh
   for i in natterjack-controller natterjack-agent natterjack; do
     crane copy ghcr.io/tessarac-llc/$i:v1.0.0 <account>.dkr.ecr.<region>.amazonaws.com/$i:v1.0.0
   done
   crane copy ghcr.io/tessarac-llc/charts/natterjack:1.0.0 <account>.dkr.ecr.<region>.amazonaws.com/charts/natterjack:1.0.0
   ```

   Install from there, pointing `controller.image.repository`,
   `agent.image.repository` and `doctor.image.repository` at the copies.
3. **Then the order above**: the Terraform module (with
   `bootstrap_route_table_ids`), the chart, a pool, a `ClusterEgressPolicy`
   with `nodeTraffic: true`.

Once the first slot in a zone is attached, the bootstrap route works, and
nodes that start later reach the internet before their agent runs. Natterjack's
own end-to-end test builds a cluster this way:
[`test/eks`](https://github.com/Tessarac-LLC/natterjack/tree/main/test/eks).

## Uninstalling

Put a default route back on the private subnets first if you removed the NAT
gateway. Then delete the policies and pools. The controller detaches every
slot that no pool claims; wait until none is attached before uninstalling:

```sh
kubectl delete clusteregresspolicies --all
kubectl delete egresspolicies --all --all-namespaces
kubectl delete egresspools --all
aws ec2 describe-network-interfaces \
  --filters Name=tag:natterjack.io/cluster,Values=prod-east \
  --query 'NetworkInterfaces[].[NetworkInterfaceId,Status]' --output text
helm uninstall natterjack --namespace natterjack --wait
```

Every slot shows `available` once detached. The agents remove every kernel
object they created. The CRDs stay unless the release was installed with
`crds.keep=false`.
