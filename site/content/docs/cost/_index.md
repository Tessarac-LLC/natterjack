---
title: Cost compared with a NAT gateway
linkTitle: Cost
weight: 18
description: What a managed NAT gateway charges, what Natterjack's slots charge, and what neither changes.
---

Prices are AWS on-demand list prices for US East (N. Virginia) and US East
(Ohio), read from the AWS Price List API on 15 November 2026. NAT gateways
cost more elsewhere ($0.052 in Frankfurt, $0.062 in Tokyo); check [Amazon VPC pricing](https://aws.amazon.com/vpc/pricing/)
for yours.

## What each charges

| | Managed NAT gateway | Natterjack |
| --- | --- | --- |
| Per zone, per hour | $0.045 for the gateway, plus $0.005 for its public IPv4 address | $0.005 for each slot's public IPv4 address (two slots per zone by default) |
| Per GB that leaves through it | $0.045 processing | none |
| Data transfer out to the internet | AWS's usual rates | the same rates |
| Compute | included | the gateway runs on nodes you already pay for |

Data transfer out to the internet costs the same with either, so the tables
below leave it out. Neither moves traffic between zones: each zone's traffic
leaves through its own zone's gateway.

## Three zones, a month (730 hours)

| Leaving the VPC per month | NAT gateways | Natterjack (2 slots per zone) | Saved |
| --- | ---: | ---: | ---: |
| 1 TB | $154.50 | $21.90 | $132.60 |
| 10 TB | $559.50 | $21.90 | $537.60 |
| 100 TB | $4,609.50 | $21.90 | $4,587.60 |
| 1 PB | $45,109.50 | $21.90 | $45,087.60 |

NAT gateways: 3 × ($0.045 + $0.005) × 730 hours, plus $0.045 for each GB
(1 TB is counted as 1,000 GB). Natterjack: 6 addresses × $0.005 × 730 hours.

## What Natterjack costs that the table does not show

- **Node capacity.** A gateway forwards in the kernel, but the packets still
  use the gateway node's CPU and its network allowance, and slot ENIs use
  interface slots on the node. [Sizing](../sizing/) shows how much a
  gateway can carry on each instance size.
- **VPC endpoints for a cluster built without a NAT gateway.** Such a
  cluster needs interface endpoints so that nodes can join and pull images
  before any gateway runs (see
  [Installing](../install/#a-new-cluster-with-no-nat-gateway)). An interface
  endpoint costs $0.01 per zone per hour and $0.01 per GB; the six the
  install guide lists cost $131.40 a month across three zones. The S3
  gateway endpoint is free. A cluster that installs Natterjack before
  removing its NAT gateway needs none of them.
- **Operating it.** Natterjack is software you run and upgrade. A managed
  NAT gateway is not.

## When a NAT gateway is still cheaper

Without traffic, three NAT gateways cost $109.50 a month and Natterjack's
slots $21.90. If a new cluster needs the interface endpoints above only for
Natterjack, their $131.40 outweighs that difference until the cluster sends
about 1 TB a month through the NAT gateways' processing charge.
