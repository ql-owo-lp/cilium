// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* IPv4 only: no IPv6 datapath to hand decapsulated IPv6 packets to. */
#define ENABLE_IPV4		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1

#include "lib/bpf_host.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })

#define TUNNEL_SRC		v4_node_one
#define TUNNEL_DST		v4_node_two
#define TEST_VNI		0x456789
#define TEST_SPORT		51515

static __u32 overlay_count;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY)
int test_from_overlay_receiver(struct __ctx_buff *ctx __maybe_unused)
{
	overlay_count++;
	return CTX_ACT_OK;
}

static __always_inline int encap(struct __ctx_buff *ctx)
{
	return geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
			     bpf_htons(TEST_SPORT), NULL, 0);
}

/* D12: Geneve carrying an inner family that is not enabled is left to the
 * kernel tunnel device, unchanged.
 */
PKTGEN(PROG_TYPE, "geneve_ipv4_only_bypass_inner_v6")
int geneve_ipv4_only_bypass_inner_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "geneve_ipv4_only_bypass_inner_v6")
int geneve_ipv4_only_bypass_inner_v6_setup(struct __ctx_buff *ctx)
{
	overlay_count = 0;
	if (encap(ctx))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_ipv4_only_bypass_inner_v6")
int geneve_ipv4_only_bypass_inner_v6_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *inner_eth;
	struct genevehdr *geneve;
	struct udphdr *udp;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	status_code = data;
	ip4 = data + sizeof(*status_code) + ETH_HLEN;
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	inner_eth = (void *)(geneve + 1);
	if ((void *)(inner_eth + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_count == 0);
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->daddr == TUNNEL_DST);
	assert(udp->dest == bpf_htons(6081));
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IPV6));

	test_finish();
}

/* The same Geneve packet carrying IPv4 is decapsulated natively, so the
 * bypass above is due to the inner protocol alone.
 */
PKTGEN(PROG_TYPE, "geneve_ipv4_only_decap_inner_v4")
int geneve_ipv4_only_decap_inner_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "geneve_ipv4_only_decap_inner_v4")
int geneve_ipv4_only_decap_inner_v4_setup(struct __ctx_buff *ctx)
{
	overlay_count = 0;
	if (encap(ctx))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_ipv4_only_decap_inner_v4")
int geneve_ipv4_only_decap_inner_v4_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	status_code = data;
	ip4 = data + sizeof(*status_code) + ETH_HLEN;
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner IPv4 header out of bounds");

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_count == 1);
	assert(ip4->daddr == v4_pod_two);

	test_finish();
}
