---
title: Moving off a NAT gateway
linkTitle: Migrate
weight: 16
description: Replace an existing cluster's managed NAT gateways with Natterjack, with or without keeping their public addresses.
---

The NAT gateway keeps carrying traffic until a policy selects it, so the
move happens one namespace at a time and can be undone at every step until
the NAT gateways are deleted.

## 1. Take stock

List the NAT gateways, their addresses, and the route tables that use them:

```sh
aws ec2 describe-nat-gateways --filter Name=vpc-id,Values=<vpc> Name=state,Values=available \
  --query 'NatGateways[].[NatGatewayId,SubnetId,NatGatewayAddresses[0].AllocationId,NatGatewayAddresses[0].PublicIp]' \
  --output table
aws ec2 describe-route-tables --filters Name=vpc-id,Values=<vpc> \
  --query 'RouteTables[?Routes[?NatGatewayId]].[RouteTableId,Associations[0].SubnetId,Routes[?DestinationCidrBlock==`0.0.0.0/0`].NatGatewayId|[0]]' \
  --output table
```

Then find out who allow-lists those addresses: partners' firewalls, SaaS IP
restrictions, database access lists. That decides the path in step 4.

## 2. Install alongside the NAT gateways

Follow [Installing](../install/), steps 1 to 4, without
`bootstrap_route_table_ids`: the private route tables keep their route to
the NAT gateway for now. The slots get new addresses, listed by the module's
`public_ips` output. Nothing changes for any workload yet.

## 3. Move traffic, one namespace at a time

Select a namespace whose destinations do not allow-list you:

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

Check that its pods leave from a slot's address, and watch the pool:

```sh
kubectl -n shop run ip --rm -it --restart=Never --image=curlimages/curl -- \
  curl -s https://checkip.amazonaws.com
kubectl get egresspool default
```

Widen the selection namespace by namespace, then to the whole cluster and
the nodes with a `ClusterEgressPolicy` that sets `nodeTraffic: true`.

**To undo** any of this, delete the policy. The agents stop steering what it
selected, and that traffic follows the route table to
the NAT gateway again. Established connections through a slot end, as they
would on any change of public address.

## 4. Keep or replace the public addresses

**New addresses (no downtime).** Ask everyone who allow-lists you to add the
module's `public_ips` alongside the NAT gateways' addresses before step 3
reaches their traffic, and to remove the old ones after step 5.

**Same addresses (a short window per zone).** A NAT gateway's address can
leave it only when the gateway is deleted, so each zone has a few minutes in
which allow-listed destinations see the slot's interim address. For each
zone, at a quiet time:

1. If Terraform created the address, remove it from that configuration's
   state so that deleting the NAT gateway does not release it, for example
   `terraform state rm 'module.vpc.aws_eip.nat[0]'`. Deleting a NAT gateway
   never releases its address by itself.
2. Delete the zone's NAT gateway and wait for it to reach `deleted`.
3. Give the address to the zone's first slot, and apply:

   ```hcl
   slot_eip_allocation_ids = {
     "us-east-1a/0" = "eipalloc-0123456789abcdef0"
   }
   ```

   The slot's interim address is released, and the slot sends from the
   NAT gateway's address as soon as AWS associates it. Until the
   controller's next sync, up to 30 seconds later, the gateway's self-test
   may find the new address unexpected and hand the zone's new flows to
   another zone's gateway; they return once the controller records the
   address. Terraform never releases an adopted address, even on
   `destroy`.

## 5. Point the private subnets at the slots

Once every node's traffic leaves through the slots, a node still needs a way
out before its agent runs. Remove the NAT gateways and their routes, for
example with `enable_nat_gateway = false` on the
[terraform-aws-modules VPC module](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws),
and apply. Then set the module's `bootstrap_route_table_ids` and apply again:

```hcl
bootstrap_route_table_ids = zipmap(module.vpc.azs, module.vpc.private_route_table_ids)
```

Use two applies: a route table holds one `0.0.0.0/0` route, and Terraform
does not order the old route's deletion before the new one's creation across
modules. Between the two, running nodes are unaffected; a node that starts
then cannot reach the internet until the second apply.

Run [`natterjack doctor`](../doctor/) and confirm it reports `GO`.

## Rolling back after the NAT gateways are gone

Create a NAT gateway in each zone (re-enable it in the VPC configuration),
remove `bootstrap_route_table_ids`, and apply. Then delete the policies;
traffic follows the route tables to the new NAT gateways. Their addresses
are new unless you give them the adopted allocations back, which first
needs those allocations removed from `slot_eip_allocation_ids`.
