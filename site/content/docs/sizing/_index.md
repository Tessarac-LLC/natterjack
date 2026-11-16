---
title: Sizing gateways
linkTitle: Sizing
weight: 17
description: How much traffic one gateway carries on each EC2 instance size, what else limits it, and how many gateways a zone needs.
---

A gateway is an ordinary node that also forwards selected traffic out of its
slot. How much it can carry is set by AWS, not by Natterjack: the agent
forwards in the kernel, and the node's network allowance runs out long before
its CPU does.

## What limits one gateway

- **The instance's network bandwidth.** EC2 gives each instance type a
  baseline bandwidth. Sizes up to `4xlarge` can burst above it for minutes at
  a time on network credits, then fall back to the baseline.
- **The internet gateway.** Traffic from one instance through an internet
  gateway is limited to 5 Gbps on instances with fewer than 32 vCPUs, and to
  half the instance's bandwidth on larger ones
  ([AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-network-bandwidth.html)).
- **One flow.** A single TCP or UDP flow through an internet gateway is
  limited to 5 Gbps whatever the instance. Bulk transfers that need more must
  use several connections.
- **Network interfaces.** Each gateway needs one free interface on its node.
  The VPC CNI uses the others for pods, so a node at its interface limit
  cannot be a gateway: the controller sets it aside for ten minutes and the
  slot reports `no free network interface slot` (see
  [Troubleshooting](../troubleshooting/)).

The gateway's work also uses the node's own allowance. Pods on a gateway node
share its bandwidth with the traffic it forwards for the zone.

## Bandwidth by instance size

Sustained gigabits per second one gateway can send to the internet, from the
EC2 API's figures and the internet gateway limits above. Where a size can
burst higher, the burst is in brackets.

| Family | large | xlarge | 2xlarge | 4xlarge | 8xlarge | 12xlarge | 16xlarge | 24xlarge | 5 Gbps sustained from |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `t3` | 0.51 (5) | 1.02 (5) | 2.05 (5) | — | — | — | — | — | — |
| `t4g` | 0.51 (5) | 1.02 (5) | 2.05 (5) | — | — | — | — | — | — |
| `m6i` | 0.78 (5) | 1.56 (5) | 3.13 (5) | 5 | 5 | 9.38 | 12.5 | 18.75 | `4xlarge` |
| `m6g` | 0.75 (5) | 1.25 (5) | 2.5 (5) | 5 | 5 | 10 | 12.5 | — | `4xlarge` |
| `m7i` | 0.78 (5) | 1.56 (5) | 3.13 (5) | 5 | 5 | 9.38 | 12.5 | 18.75 | `4xlarge` |
| `m7g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | — | `4xlarge` |
| `m8g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | 20 | `4xlarge` |
| `c7i` | 0.78 (5) | 1.56 (5) | 3.13 (5) | 5 | 5 | 9.38 | 12.5 | 18.75 | `4xlarge` |
| `c7g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | — | `4xlarge` |
| `c8g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | 20 | `4xlarge` |
| `r7i` | 0.78 (5) | 1.56 (5) | 3.13 (5) | 5 | 5 | 9.38 | 12.5 | 18.75 | `4xlarge` |
| `r7g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | — | `4xlarge` |
| `r8g` | 0.94 (5) | 1.88 (5) | 3.75 (5) | 5 | 5 | 11.25 | 15 | 20 | `4xlarge` |

In short: below `4xlarge`, a gateway sustains under 5 Gbps but bursts to 5;
from `4xlarge` to `8xlarge` it sustains 5; from `12xlarge` up it sustains
half the instance's bandwidth. To produce the table for other families or
another region:

```sh
REGION=eu-central-1 hack/aws-bandwidth.sh m7i m7g c8g
```

## Measured

The EKS end-to-end test measures one gateway of each architecture with
iperf3: eight parallel TCP streams for 20 seconds, from a pod on another
node in the zone to a server outside the VPC, through the gateway's slot and
the internet gateway. Results from 16 November 2026, `us-east-2`:

| Gateway | Architecture | Egress (Gbps) | Ingress (Gbps) |
| --- | --- | ---: | ---: |
| `m7i.large` | amd64 | 4.78 | 4.78 |
| `m7g.large` | arm64 | 4.78 | 4.78 |

Both reach the internet gateway's 5 Gbps limit, less TCP and IP overhead,
in both directions: the gateway, not its CPU, is what AWS caps. A 20-second
run measures the burst rate. Over minutes a `large` gateway falls back to
the baseline in the table above. The test writes these figures to
`bench.json`, so each run can be checked against them.

## How many gateways a zone needs

A zone's selected traffic is spread across its gateways by flow, so a zone
with `n` gateways carries up to `n` times one gateway's figure. Size for the
zone's peak, then add one:

- **Spread.** Each slot is one gateway. `slots_per_subnet` in the Terraform
  module, and `maxGatewaysPerZone` in the pool, set how many a zone runs.
- **Headroom for failure.** When a gateway fails, its flows move to the
  zone's other gateways within seconds and the slot is repaired on another
  node. With one gateway, the zone's traffic leaves through another zone
  meanwhile. Two gateways per zone keep it in the zone.
- **Dedicated nodes.** With heavy egress, run gateways on their own node
  group: label it, set the pool's `gatewayNodeSelector`, and taint it so that
  only the agent runs there. See [Concepts](../concepts/#egresspool).

A managed NAT gateway scales to 100 Gbps on its own. For a zone that needs
more than a few gateways' worth, compare the [cost](../cost/) of the larger
nodes with the NAT gateway's per-gigabyte charge.
