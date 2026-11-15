// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
// Copyright 2026 Tessarac, LLC.

// The probe responder. Every source node probes every gateway through the
// tunnel and stops using one that goes quiet, moving its flows. Answering in
// the kernel, on the gateway namespace's end of the link from the host,
// keeps the answers coming while the agent restarts: the program stays
// attached after the agent exits, and the next agent replaces it.
//
// A probe is answered only while the agent last found the slot serving, the
// sender is a node of the cluster, and the gateway namespace still has a
// route out: when the slot interface goes, its routes go with it and the
// probes go unanswered even with no agent running.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
// The magic word and an 8-byte sequence number.
#define PROBE_LEN 12

// Set by the agent at load time, in network byte order.
volatile const __u32 probe_addr = 0;
volatile const __u16 probe_port = 0;
// Any address outside the cluster: probes are answered while it routes.
volatile const __u32 route_check = 0;

// Whether the slot serves: one __u32, nonzero while it does.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} nj_probe_serving SEC(".maps");

// The cluster's node addresses.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} nj_probe_nodes SEC(".maps");

static __always_inline int routes_out(struct __sk_buff *skb, struct iphdr *ip)
{
	struct bpf_fib_lookup fib = {};
	fib.family = AF_INET;
	fib.l4_protocol = IPPROTO_UDP;
	fib.tot_len = bpf_ntohs(ip->tot_len);
	fib.ifindex = skb->ingress_ifindex;
	fib.ipv4_src = ip->saddr;
	fib.ipv4_dst = route_check;
	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	return rc == BPF_FIB_LKUP_RET_SUCCESS || rc == BPF_FIB_LKUP_RET_NO_NEIGH;
}

SEC("tc")
int nj_respond(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u8 *probe = (void *)(udp + 1);

	if ((void *)(udp + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP) || ip->ihl != 5 ||
	    ip->protocol != IPPROTO_UDP || ip->daddr != probe_addr || udp->dest != probe_port ||
	    (ip->frag_off & bpf_htons(0x3fff)))
		return TC_ACT_OK;
	// From here on it is for the responder: answered here or dropped.
	if ((void *)(probe + PROBE_LEN) > end || udp->len != bpf_htons(sizeof(*udp) + PROBE_LEN) ||
	    probe[0] != 'N' || probe[1] != 'J' || probe[2] != 'P' || probe[3] != '1')
		return TC_ACT_SHOT;
	__u32 zero = 0;
	__u32 *serving = bpf_map_lookup_elem(&nj_probe_serving, &zero);
	if (!serving || !*serving || !bpf_map_lookup_elem(&nj_probe_nodes, &ip->saddr) || !routes_out(skb, ip))
		return TC_ACT_SHOT;

	// Send it back as it came. Swapping addresses and ports leaves both
	// checksums valid.
	__u8 mac[ETH_ALEN];
	__builtin_memcpy(mac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac, ETH_ALEN);
	__u32 addr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = addr;
	__u16 port = udp->source;
	udp->source = udp->dest;
	udp->dest = port;
	return bpf_redirect(skb->ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
