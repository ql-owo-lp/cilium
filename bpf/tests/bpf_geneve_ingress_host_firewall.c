// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_HOST_FIREWALL	1

#include "lib/bpf_host.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_two_addr })

#define TUNNEL_SRC_V4		v4_node_one
#define TUNNEL_DST_V4		v4_node_two
#define TUNNEL_SRC_V6		{ .addr = v6_node_one_addr }
#define TUNNEL_DST_V6		{ .addr = v6_node_two_addr }
#define TEST_VNI		0x456789
#define TEST_SPORT		51515

static __u32 overlay_count;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY)
int test_from_overlay_receiver(struct __ctx_buff *ctx __maybe_unused)
{
	overlay_count++;
	return CTX_ACT_OK;
}

static __always_inline int build_inner_v4(struct __ctx_buff *ctx)
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

/* The tunnel source is a remote node, the tunnel destination this host. */
static __always_inline void setup_nodes(void)
{
	const union v6addr remote_v6 = TUNNEL_SRC_V6;
	const union v6addr local_v6 = TUNNEL_DST_V6;

	ipcache_v4_add_entry(TUNNEL_SRC_V4, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v4_add_entry(TUNNEL_DST_V4, 0, HOST_ID, 0, 0);
	ipcache_v6_add_entry(&remote_v6, 0, REMOTE_NODE_ID, 0, 0);
	ipcache_v6_add_entry(&local_v6, 0, HOST_ID, 0, 0);
}

static __always_inline int receive_v4(struct __ctx_buff *ctx)
{
	overlay_count = 0;
	if (geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			  bpf_htons(TEST_SPORT), NULL, 0))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

static __always_inline int receive_v6(struct __ctx_buff *ctx)
{
	const union v6addr saddr = TUNNEL_SRC_V6;
	const union v6addr daddr = TUNNEL_DST_V6;

	overlay_count = 0;
	if (geneve_encap6(ctx, &saddr, &daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			  NULL, 0))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

static __always_inline __u32 status_code(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return TEST_ERROR;
	return *(__u32 *)data;
}

/* D3, L3-04: the host firewall is applied to the outer header: a host
 * policy that only admits UDP/6081 from remote nodes lets the packet through
 * to decapsulation.
 */
PKTGEN(PROG_TYPE, "geneve_host_firewall_v4_allow")
int geneve_host_firewall_v4_allow_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_host_firewall_v4_allow")
int geneve_host_firewall_v4_allow_setup(struct __ctx_buff *ctx)
{
	setup_nodes();
	policy_add_ingress_allow_l3_l4_entry(REMOTE_NODE_ID, IPPROTO_UDP,
					     bpf_htons(6081), 0);
	return receive_v4(ctx);
}

CHECK(PROG_TYPE, "geneve_host_firewall_v4_allow")
int geneve_host_firewall_v4_allow_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay_count == 1);

	policy_delete_ingress_l3_l4_entry(REMOTE_NODE_ID, IPPROTO_UDP,
					  bpf_htons(6081), 0);
	test_finish();
}

/* D3, L3-04: the host firewall drops the Geneve packet of a remote node on
 * its outer header, before it is decapsulated.
 */
PKTGEN(PROG_TYPE, "geneve_host_firewall_v4_deny")
int geneve_host_firewall_v4_deny_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_host_firewall_v4_deny")
int geneve_host_firewall_v4_deny_setup(struct __ctx_buff *ctx)
{
	setup_nodes();
	policy_add_ingress_deny_l4_entry(IPPROTO_UDP, bpf_htons(6081), 0);
	metrics_del_entry((__u8)-DROP_POLICY_DENY, METRIC_INGRESS);
	return receive_v4(ctx);
}

CHECK(PROG_TYPE, "geneve_host_firewall_v4_deny")
int geneve_host_firewall_v4_deny_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_POLICY_DENY,
		.dir = METRIC_INGRESS,
	};
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4 = data + sizeof(__u32) + ETH_HLEN;
	struct udphdr *udp = (void *)(ip4 + 1);

	test_init();

	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert(overlay_count == 0);
	assert_metrics_count(key, 1);
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(udp->dest == bpf_htons(6081));

	policy_delete_entry(false, 0, IPPROTO_UDP, bpf_htons(6081), 0);
	test_finish();
}

/* D3, L3-04: as geneve_host_firewall_v4_allow, for an outer IPv6 header. */
PKTGEN(PROG_TYPE, "geneve_host_firewall_v6_allow")
int geneve_host_firewall_v6_allow_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_host_firewall_v6_allow")
int geneve_host_firewall_v6_allow_setup(struct __ctx_buff *ctx)
{
	setup_nodes();
	policy_add_ingress_allow_l3_l4_entry(REMOTE_NODE_ID, IPPROTO_UDP,
					     bpf_htons(6081), 0);
	return receive_v6(ctx);
}

CHECK(PROG_TYPE, "geneve_host_firewall_v6_allow")
int geneve_host_firewall_v6_allow_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay_count == 1);

	policy_delete_ingress_l3_l4_entry(REMOTE_NODE_ID, IPPROTO_UDP,
					  bpf_htons(6081), 0);
	test_finish();
}

/* D3, L3-04: as geneve_host_firewall_v4_deny, for an outer IPv6 header. */
PKTGEN(PROG_TYPE, "geneve_host_firewall_v6_deny")
int geneve_host_firewall_v6_deny_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_host_firewall_v6_deny")
int geneve_host_firewall_v6_deny_setup(struct __ctx_buff *ctx)
{
	setup_nodes();
	policy_add_ingress_deny_l4_entry(IPPROTO_UDP, bpf_htons(6081), 0);
	metrics_del_entry((__u8)-DROP_POLICY_DENY, METRIC_INGRESS);
	return receive_v6(ctx);
}

CHECK(PROG_TYPE, "geneve_host_firewall_v6_deny")
int geneve_host_firewall_v6_deny_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = TUNNEL_DST_V6;
	struct metrics_key key = {
		.reason = (__u8)-DROP_POLICY_DENY,
		.dir = METRIC_INGRESS,
	};
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6 = data + sizeof(__u32) + ETH_HLEN;
	struct udphdr *udp = (void *)(ip6 + 1);

	test_init();

	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert(overlay_count == 0);
	assert_metrics_count(key, 1);
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert(udp->dest == bpf_htons(6081));

	policy_delete_entry(false, 0, IPPROTO_UDP, bpf_htons(6081), 0);
	test_finish();
}
