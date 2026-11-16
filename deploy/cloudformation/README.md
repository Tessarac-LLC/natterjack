# Natterjack on AWS with CloudFormation

Two templates create what the [Terraform module](../terraform/aws) creates,
for accounts that deploy with CloudFormation:

| Template | Stacks | Creates |
| --- | --- | --- |
| [`controller.yaml`](controller.yaml) | one per cluster | The controller's IAM role, which may attach and detach only this cluster's slots and only on this cluster's instances; its EKS Pod Identity association; optionally, the node rules for the agent tunnel (UDP 6081) and WireGuard (UDP 51871). |
| [`slots.yaml`](slots.yaml) | one per zone | The zone's slots: ENIs with their own Elastic IPs, the source/destination check off, the tags the controller and the VPC CNI read, and a security group that admits nothing from the internet; optionally, the zone's bootstrap route. |

The role's policy matches the module's statement for statement. Both
templates are linted in CI with `make cfn-check`.

## Requirements

- An EKS cluster with the `eks-pod-identity-agent` add-on. For IAM roles for
  service accounts (IRSA), use the Terraform module, or give the role a web
  identity trust yourself.
- A public subnet in each zone that has nodes.
- `slots.yaml` uses the `AWS::LanguageExtensions` transform, so its stacks
  need the `CAPABILITY_AUTO_EXPAND` capability.

## Deploy

```sh
aws cloudformation deploy --stack-name natterjack-prod-east-controller \
  --template-file controller.yaml --capabilities CAPABILITY_IAM \
  --parameter-overrides ClusterName=prod-east NodeSecurityGroupId=sg-0123456789abcdef0

for zone in a b c; do
  aws cloudformation deploy --stack-name "natterjack-prod-east-slots-$zone" \
    --template-file slots.yaml --capabilities CAPABILITY_AUTO_EXPAND \
    --parameter-overrides ClusterName=prod-east VpcId=vpc-0123456789abcdef0 \
      SubnetId="<public subnet in zone $zone>"
done
```

Then install the chart with `clusterName=prod-east`, as in
[Installing](https://natterjack.io/docs/install/#2-install-the-chart). Each
slots stack's `PublicIp0`, `PublicIp1`, … outputs are the addresses selected
traffic leaves from.

### Parameters

`controller.yaml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `ClusterName` | | The EKS cluster's name, as the chart's `clusterName`. |
| `Namespace` | `natterjack` | Namespace the chart is installed in. |
| `ServiceAccount` | `natterjack-controller` | The controller's ServiceAccount. |
| `NodeSecurityGroupId` | | Security group shared by the nodes. When set, nodes in it may reach each other on the tunnel and WireGuard ports. |
| `TunnelPort` | `6081` | The chart's `agent.tunnelPort`. |
| `WireGuardPort` | `51871` | The chart's `agent.wireguardPort`. |
| `PermissionsBoundary` | | ARN of a permissions boundary for the role. |

`slots.yaml`:

| Parameter | Default | Description |
| --- | --- | --- |
| `ClusterName` | | The EKS cluster's name. |
| `VpcId` | | The cluster's VPC. |
| `SubnetId` | | A public subnet in this zone. |
| `SlotIndexes` | `0,1` | One entry per slot, from 0. Two slots give the zone a second gateway. |
| `BootstrapRouteTableId` | | A private route table in this zone whose `0.0.0.0/0` route should point at slot 0. |
| `BootstrapSourceCidr` | | Required with a route table: the source the slots admit, the VPC's CIDR or the block behind that route table. |

## The bootstrap route

With `BootstrapRouteTableId`, the zone's private subnets reach the internet
through slot 0 before their nodes' agents run, in place of a NAT gateway.
AWS filters traffic routed through an ENI by its security groups, so the
slots then admit `BootstrapSourceCidr`. Give a CIDR inside the VPC: the
controller quarantines a slot whose security group admits anything else.

A route table holds one `0.0.0.0/0` route. Remove the NAT gateway's route
first, then update the stack with the route table; see
[Moving off a NAT gateway](https://natterjack.io/docs/migrate/).

## Removing

Delete the pools and wait until no slot is attached (see
[Uninstalling](https://natterjack.io/docs/install/#uninstalling)), then delete
the slots stacks and the controller stack. Deleting a slots stack releases
its Elastic IPs.
