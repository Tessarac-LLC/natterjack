// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
// Copyright 2026 Tessarac, LLC.

// The eBPF fast path. Data planes such as Cilium's eBPF host routing and
// Calico's eBPF mode move pod traffic from the pod's device straight to the
// node's uplink, so the host's netfilter hooks never see it and the agent's
// nftables rules cannot steer it. These programs sit first on the uplink:
// a packet from a steered pod to a destination that is not excluded is sent
// back into the host's network stack through the agent's divert device,
// where the same nftables rules as in nftables mode pick its gateway,
// translate it and send it into the tunnel.
//
// Replies to connections that came in from outside reach the pod the same
// way, without the host's conntrack seeing them, so the reply would look
// like a new flow and be steered. The ingress program records every
// connection that comes in to a steered pod, and the egress program leaves
// its replies alone.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// tcx return codes (linux/bpf.h on recent kernels; repeated so older
// headers build).
#define NJ_TCX_NEXT -1
#define NJ_TCX_PASS 0

// Set by the agent at load time.
volatile const __u32 divert_ifindex = 0;
volatile const __u8 divert_mac[ETH_ALEN] = {};

// Steered pod addresses on this node.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nj_steered SEC(".maps");

struct prefix {
	__u32 len;
	__u32 addr;
};

// Destinations never steered: the cluster, the VPC and configured private
// ranges.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct prefix);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nj_excluded SEC(".maps");

// A connection that came in to a steered pod, as its first packet saw it:
// remote address and port, pod address and port.
struct flow {
	__u32 remote;
	__u32 pod;
	__u16 remote_port;
	__u16 pod_port;
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct flow);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nj_inbound SEC(".maps");

// Packets diverted, for the agent's metrics.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nj_diverted SEC(".maps");

// parse reads the IPv4 header and, unless the packet is a later fragment,
// the ports. It returns 0 for a packet the programs do not handle.
static __always_inline int parse(struct __sk_buff *skb, struct iphdr *ip, __u16 *sport, __u16 *dport)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;
	struct iphdr *h = (void *)(eth + 1);
	if ((void *)(h + 1) > end || h->ihl < 5)
		return 0;
	*ip = *h;
	*sport = 0;
	*dport = 0;
	if (h->frag_off & bpf_htons(0x1fff))
		return 1; // a later fragment: no ports
	if (h->protocol != IPPROTO_TCP && h->protocol != IPPROTO_UDP)
		return 1;
	__u16 *ports = (void *)h + h->ihl * 4;
	if ((void *)(ports + 2) > end)
		return 1;
	*sport = ports[0];
	*dport = ports[1];
	return 1;
}

static __always_inline int excluded(__u32 addr)
{
	struct prefix key = {.len = 32, .addr = addr};

	return bpf_map_lookup_elem(&nj_excluded, &key) != NULL;
}

SEC("tc")
int nj_egress(struct __sk_buff *skb)
{
	struct iphdr ip;
	__u16 sport, dport;

	// A packet the divert device already sent through the stack, which
	// nftables left unsteered, goes out as it is.
	if (skb->ingress_ifindex == divert_ifindex)
		return NJ_TCX_NEXT;
	if (!parse(skb, &ip, &sport, &dport))
		return NJ_TCX_NEXT;
	if (!bpf_map_lookup_elem(&nj_steered, &ip.saddr))
		return NJ_TCX_NEXT;
	if (excluded(ip.daddr))
		return NJ_TCX_NEXT;
	struct flow reply = {
		.remote = ip.daddr, .pod = ip.saddr,
		.remote_port = dport, .pod_port = sport, .proto = ip.protocol,
	};
	if (bpf_map_lookup_elem(&nj_inbound, &reply))
		return NJ_TCX_NEXT;

	// Byte by byte: a memcpy would drop the volatile and let the compiler
	// fold in the zero the constant starts as.
	__u8 mac[ETH_ALEN];
#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++)
		mac[i] = divert_mac[i];
	if (bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 0))
		return NJ_TCX_NEXT;
	// The packet starts again in the host's stack, where nftables reads the
	// mark to pick its gateway. A data plane's own mark, such as the security
	// identity Cilium keeps in the upper bits, would pick one for it.
	skb->mark = 0;
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&nj_diverted, &zero);
	if (n)
		*n += 1;
	return bpf_redirect(divert_ifindex, BPF_F_INGRESS);
}

SEC("tc")
int nj_ingress(struct __sk_buff *skb)
{
	struct iphdr ip;
	__u16 sport, dport;

	if (!parse(skb, &ip, &sport, &dport))
		return NJ_TCX_NEXT;
	if (!bpf_map_lookup_elem(&nj_steered, &ip.daddr))
		return NJ_TCX_NEXT;
	if (excluded(ip.saddr))
		return NJ_TCX_NEXT;
	struct flow in = {
		.remote = ip.saddr, .pod = ip.daddr,
		.remote_port = sport, .pod_port = dport, .proto = ip.protocol,
	};
	if (!bpf_map_lookup_elem(&nj_inbound, &in)) {
		__u8 one = 1;
		bpf_map_update_elem(&nj_inbound, &in, &one, BPF_NOEXIST);
	}
	return NJ_TCX_NEXT;
}

// The kernel reads GPL here; the source is also under Apache-2.0.
char LICENSE[] SEC("license") = "GPL";
