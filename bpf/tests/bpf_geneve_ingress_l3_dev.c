// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* An L2-less native device. */
#define ETH_HLEN		0
#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1

#include "lib/bpf_host.h"

/* The packets are addressed to the direct routing addresses, so only the
 * missing L2 header keeps them from being natively decapsulated.
 */
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_two_addr })

#define TEST_VNI		0x456789
#define TEST_SPORT		51515

/* Push UDP, Geneve and an inner IPv4 Ethernet frame behind the outer IP
 * header.
 */
static __always_inline int push_geneve(struct pktgen *builder)
{
	struct ethhdr *inner_eth;
	struct genevehdr *geneve;
	struct udphdr *udp;
	void *data;

	udp = pktgen__push_default_udphdr(builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(TEST_SPORT);
	udp->dest = bpf_htons(6081);

	geneve = pktgen__push_default_genevehdr(builder);
	if (!geneve)
		return TEST_ERROR;
	geneve->vni[0] = (__u8)(TEST_VNI >> 16);
	geneve->vni[1] = (__u8)(TEST_VNI >> 8);
	geneve->vni[2] = (__u8)TEST_VNI;

	/* Of the inner frame, only the Ethernet header matters here. */
	inner_eth = pktgen__push_ethhdr(builder);
	if (!inner_eth)
		return TEST_ERROR;
	ethhdr__set_macs(inner_eth, (__u8 *)mac_one, (__u8 *)mac_two);
	inner_eth->h_proto = bpf_htons(ETH_P_IP);

	data = pktgen__push_data(builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(builder);
	return 0;
}

/* The test harness only runs packets with an Ethernet header: strip it
 * here, as an L3 device would deliver the packet.
 */
static __always_inline int strip_l2(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* bpf_skb_adjust_room() keeps the first __ETH_HLEN bytes and removes
	 * the ones behind them: move the start of the L3 header in front.
	 */
	if (data + __ETH_HLEN + __ETH_HLEN > data_end)
		return TEST_ERROR;
	memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	return skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC,
			       BPF_F_ADJ_ROOM_FIXED_GSO);
}

/* D12, D17(1): Geneve received on an L2-less device is left to the kernel
 * tunnel device, unchanged.
 */
PKTGEN(PROG_TYPE, "geneve_l3_dev_v4_not_intercepted")
int geneve_l3_dev_v4_not_intercepted_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *ip4;

	pktgen__init(&builder, ctx);

	ip4 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				       v4_node_one, v4_node_two);
	if (!ip4)
		return TEST_ERROR;

	return push_geneve(&builder);
}

SETUP(PROG_TYPE, "geneve_l3_dev_v4_not_intercepted")
int geneve_l3_dev_v4_not_intercepted_setup(struct __ctx_buff *ctx)
{
	if (strip_l2(ctx))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_l3_dev_v4_not_intercepted")
int geneve_l3_dev_v4_not_intercepted_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct iphdr *ip4 = data + sizeof(*status_code);
	struct udphdr *udp = (void *)(ip4 + 1);

	test_init();

	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->daddr == v4_node_two);
	assert(udp->dest == bpf_htons(6081));
	assert((void *)(udp + 1) + sizeof(struct genevehdr) + sizeof(struct ethhdr) +
	       sizeof(default_data) == data_end);

	test_finish();
}

/* D12, D17(1): as geneve_l3_dev_v4_not_intercepted, for an outer IPv6
 * header.
 */
PKTGEN(PROG_TYPE, "geneve_l3_dev_v6_not_intercepted")
int geneve_l3_dev_v6_not_intercepted_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *ip6;

	pktgen__init(&builder, ctx);

	ip6 = pktgen__push_ipv6_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				       (__u8 *)v6_node_one, (__u8 *)v6_node_two);
	if (!ip6)
		return TEST_ERROR;

	return push_geneve(&builder);
}

SETUP(PROG_TYPE, "geneve_l3_dev_v6_not_intercepted")
int geneve_l3_dev_v6_not_intercepted_setup(struct __ctx_buff *ctx)
{
	if (strip_l2(ctx))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_l3_dev_v6_not_intercepted")
int geneve_l3_dev_v6_not_intercepted_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code = data;
	struct ipv6hdr *ip6 = data + sizeof(*status_code);
	struct udphdr *udp = (void *)(ip6 + 1);

	test_init();

	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(ip6->nexthdr == IPPROTO_UDP);
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert(udp->dest == bpf_htons(6081));
	assert((void *)(udp + 1) + sizeof(struct genevehdr) + sizeof(struct ethhdr) +
	       sizeof(default_data) == data_end);

	test_finish();
}
