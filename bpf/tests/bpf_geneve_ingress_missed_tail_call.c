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

#include "lib/bpf_host.h"
#include "lib/metrics.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_two_addr })

#define TEST_VNI		0x456789
#define TEST_SPORT		51515

/* cilium_calls_bpf_overlay is left empty, as when bpf_host is attached
 * before bpf_overlay has populated it.
 */

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

static __always_inline __u32 status_code(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return TEST_ERROR;
	return *(__u32 *)data;
}

/* L1-15, L3-09: without bpf_overlay's program, tail_geneve_decap4 drops
 * the decapsulated packet instead of passing it on.
 */
PKTGEN(PROG_TYPE, "geneve_decap4_missed_tail_call_drops")
int geneve_decap4_missed_tail_call_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_decap4_missed_tail_call_drops")
int geneve_decap4_missed_tail_call_drops_setup(struct __ctx_buff *ctx)
{
	metrics_del_entry((__u8)-DROP_MISSED_TAIL_CALL, METRIC_INGRESS);
	if (geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
			  bpf_htons(TEST_SPORT), NULL, 0))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_decap4_missed_tail_call_drops")
int geneve_decap4_missed_tail_call_drops_check(const struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);
	struct metrics_key key = {
		.reason = (__u8)-DROP_MISSED_TAIL_CALL,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(meta);
	assert(meta->magic == 0);

	test_finish();
}

/* L1-15, L3-09: as above, for tail_geneve_decap6. */
PKTGEN(PROG_TYPE, "geneve_decap6_missed_tail_call_drops")
int geneve_decap6_missed_tail_call_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_decap6_missed_tail_call_drops")
int geneve_decap6_missed_tail_call_drops_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };

	metrics_del_entry((__u8)-DROP_MISSED_TAIL_CALL, METRIC_INGRESS);
	if (geneve_encap6(ctx, &saddr, &daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			  NULL, 0))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_decap6_missed_tail_call_drops")
int geneve_decap6_missed_tail_call_drops_check(const struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);
	struct metrics_key key = {
		.reason = (__u8)-DROP_MISSED_TAIL_CALL,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(meta);
	assert(meta->magic == 0);

	test_finish();
}

/* Egress counterpart: if cilium_calls_bpf_overlay[GENEVE_CALL_TO_OVERLAY] is
 * empty, geneve_encap_and_redirect() drops with DROP_MISSED_TAIL_CALL and
 * clears the egress metadata slot magic.
 */
PKTGEN(PROG_TYPE, "geneve_encap_missed_tail_call_drops")
int geneve_encap_missed_tail_call_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_encap_missed_tail_call_drops")
int geneve_encap_missed_tail_call_drops_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = v4_node_two,
		.sec_identity = TEST_VNI,
		.flag_has_tunnel_ep = true,
	};

	return geneve_encap_and_redirect(ctx, &ep, TEST_VNI, NOT_VTEP_DST,
					 NULL, 0);
}

CHECK(PROG_TYPE, "geneve_encap_missed_tail_call_drops")
int geneve_encap_missed_tail_call_drops_check(const struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	test_init();

	assert((int)status_code(ctx) == DROP_MISSED_TAIL_CALL);
	assert(meta);
	assert(meta->magic == 0);

	test_finish();
}
