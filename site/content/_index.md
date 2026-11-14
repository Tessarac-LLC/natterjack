+++
title = "Natterjack"
description = "Highly available, zone-aware egress gateways for Kubernetes that replace cloud NAT gateways."
+++

{{< blocks/cover title="Natterjack" image_anchor="top" height="med" color="dark" >}}
<p class="lead mt-4">Highly available egress for Kubernetes, on the nodes you already run.<br>Replace managed NAT gateways and their per-gigabyte charge, without opening your private subnets.</p>
<a class="btn btn-lg btn-primary me-3 mb-4" href="{{< relref "/docs" >}}">
  Read the docs <i class="fas fa-arrow-alt-circle-right ms-2"></i>
</a>
<a class="btn btn-lg btn-secondary me-3 mb-4" href="https://github.com/Tessarac-LLC/natterjack">
  GitHub <i class="fab fa-github ms-2 "></i>
</a>
{{< /blocks/cover >}}

{{% blocks/lead color="primary" %}}
A managed NAT gateway charges by the hour **and** for every gigabyte it
processes. Natterjack moves that job onto egress gateways that run as pods on
your existing nodes: active-active within each availability zone, zone-local
by default, and failing over in under a second.
{{% /blocks/lead %}}

{{% blocks/section color="white" type="row" %}}

{{% blocks/feature icon="fa-solid fa-coins" title="No per-gigabyte processing charge" %}}
Traffic leaves through Elastic IPs on interfaces your infrastructure-as-code
already owns. No new nodes, no new load balancers, a handful of small pods.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-layer-group" title="Active-active, zone-aware" %}}
Every gateway in a zone carries traffic at once. Flows prefer gateways in their
own zone, so they never pay for cross-zone transfer unless a zone has none left.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-bolt" title="Sub-second failover" %}}
Health is probed every 100 ms over the tunnel. When a gateway dies, only its
flows move; established connections on healthy gateways are untouched.
{{% /blocks/feature %}}

{{% /blocks/section %}}

{{% blocks/section color="light" type="row" %}}

{{% blocks/feature icon="fa-solid fa-shield-halved" title="Secure without extra configuration" %}}
Each egress interface lives in an isolated network namespace that drops all
inbound connections and never forwards into your cluster, even when the
surrounding infrastructure is misconfigured.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-code-branch" title="Your IaC stays in charge" %}}
Interfaces, addresses and routes are declared in Terraform or CloudFormation.
Natterjack discovers them by tag and never creates, retags or deletes them,
so there is no drift to fight.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-network-wired" title="Works with your CNI and mesh" %}}
Built on the Linux kernel's own NAT and tunnelling, with an eBPF fast path for
eBPF-based CNIs. Designed to sit underneath Istio, Linkerd and Cilium meshes.
{{% /blocks/feature %}}

{{% /blocks/section %}}

{{% blocks/lead color="dark" %}}
Open source under Apache-2.0. Every release is signed, ships with an SBOM and
build provenance, and is built from a reviewed commit on `main`.
{{% /blocks/lead %}}
