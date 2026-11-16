# Natterjack on AWS

Creates everything Natterjack needs in an AWS account for one cluster:

- **Slots.** In each public subnet you give, `slots_per_subnet` ENIs, each
  with its own Elastic IP, source/destination check off, the
  `natterjack.io/egress`, `natterjack.io/cluster` and
  `node.k8s.amazonaws.com/no_manage` tags, and a security group with no
  inbound rules. The controller attaches them to nodes; the module never
  does.
- **The controller's IAM role**, allowed to read EC2 networking and to attach
  or detach only this cluster's slots, and only on this cluster's instances.
  It is trusted by EKS Pod Identity (default) or, with `identity = "irsa"`,
  by the controller's ServiceAccount through the cluster's OIDC provider.
- **Optionally**, the agent tunnel rule between nodes
  (`node_security_group_ids`) and each zone's bootstrap route
  (`bootstrap_route_table_ids`), which sends a private subnet's default route
  to the zone's first slot so nodes reach the internet before their agent
  runs.

## Usage

```hcl
module "natterjack" {
  source = "github.com/Tessarac-LLC/natterjack//deploy/terraform/aws?ref=v1.0.0"

  cluster_name            = "prod-east"
  slot_subnets            = zipmap(module.vpc.azs, module.vpc.public_subnets)
  node_security_group_ids = [module.eks.node_security_group_id]

  # Optional: replace the NAT gateway's default route in each zone.
  bootstrap_route_table_ids = zipmap(module.vpc.azs, module.vpc.private_route_table_ids)
}
```

Both maps are keyed by zone name. Terraform needs the keys when it plans, and
subnets created in the same apply have no ID until then.

Then install the chart with the same cluster name:

```sh
helm install natterjack oci://ghcr.io/tessarac-llc/charts/natterjack \
  --namespace natterjack --create-namespace \
  --set clusterName=prod-east --set controller.aws.region=us-east-1
```

With EKS Pod Identity, install the `eks-pod-identity-agent` add-on first. With
IRSA, also set
`controller.serviceAccount.annotations."eks\.amazonaws\.com/role-arn"` to the
`controller_role_arn` output.

`public_ips` lists the addresses selected traffic leaves from.

## Keeping Terraform and the controller apart

The controller moves slot ENIs between nodes. The module declares no
`attachment` and ignores the attribute, so `terraform plan` stays empty while
the controller works. Do not add an attachment for a slot ENI elsewhere.

Adding an inbound rule to the slot security group, turning the
source/destination check back on, or removing a tag makes the controller
quarantine the slot and report why.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.10 |
| aws | >= 6.0 |

## Providers

| Name | Version |
| ---- | ------- |
| aws | >= 6.0 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_eip.slot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip_association.slot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip_association) | resource |
| [aws_eks_pod_identity_association.controller](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_pod_identity_association) | resource |
| [aws_iam_role.controller](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.controller](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_network_interface.slot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_interface) | resource |
| [aws_route.bootstrap](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_security_group.slot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_egress_rule.slot_ipv4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.tunnel](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.wireguard](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_subnet.slot](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/subnet) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| cluster\_name | Kubernetes cluster name. The same value as the chart's clusterName; slots are tagged with it and IAM is scoped to it. | `string` | n/a | yes |
| slot\_subnets | Public subnets to create slots in, keyed by zone name, at most one per zone. Each must route 0.0.0.0/0 to an internet gateway. Slot ENIs can only attach to nodes in the same zone. The keys must be known when Terraform plans, so use zone names rather than subnet IDs: subnets created in the same apply have no ID yet. | `map(string)` | n/a | yes |
| bootstrap\_route\_table\_ids | Private route tables, keyed by zone name as in slot\_subnets, whose 0.0.0.0/0 route should point at that zone's first slot. Nodes then reach the internet before their agent runs. Leave empty if the cluster keeps another default route. | `map(string)` | `{}` | no |
| identity | How the controller gets AWS credentials: "pod-identity" (EKS Pod Identity; the eks-pod-identity-agent add-on must be installed) or "irsa" (IAM roles for service accounts). | `string` | `"pod-identity"` | no |
| namespace | Namespace the chart is installed in. | `string` | `"natterjack"` | no |
| node\_security\_group\_ids | Security groups of the cluster's nodes. The module allows the agent tunnels (UDP) from each of these groups to each. Empty to manage the rules yourself. | `list(string)` | `[]` | no |
| oidc\_provider\_arn | ARN of the cluster's IAM OIDC provider. Required when identity is "irsa". | `string` | `null` | no |
| permissions\_boundary | ARN of a permissions boundary for the controller's IAM role, for accounts that require one on every role. Null for none. | `string` | `null` | no |
| service\_account | The controller's ServiceAccount name. The chart default is `<release>-controller`, so `natterjack-controller` for a release named natterjack. | `string` | `"natterjack-controller"` | no |
| slots\_per\_subnet | Slots (ENI with an Elastic IP) per subnet. Two give a zone a warm replacement: the controller fails over by moving an attached slot or using a spare. | `number` | `2` | no |
| tags | Tags added to every resource the module creates. Cannot override the natterjack.io and no\_manage tags. | `map(string)` | `{}` | no |
| tunnel\_port | UDP port of the agent tunnel. Must match the chart's agent.tunnelPort. | `number` | `6081` | no |
| wireguard\_port | UDP port of the agent WireGuard tunnel, used by pools with tunnel WireGuard. Must match the chart's agent.wireguardPort and differ from tunnel\_port. | `number` | `51871` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| controller\_role\_arn | IAM role for the controller. With identity "irsa", set it as the chart's controller.serviceAccount.annotations."eks.amazonaws.com/role-arn". |
| public\_ips | The addresses the cluster's selected traffic leaves from. Give these to anyone who allow-lists your egress. |
| slot\_security\_group\_id | Security group on every slot. It has no inbound rules; adding one makes the controller quarantine the slots. |
| slots | Every slot: ENI ID, zone and public IP. |
<!-- END_TF_DOCS -->
