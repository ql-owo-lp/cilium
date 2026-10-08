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

/* bpf_csum_level(BPF_CSUM_LEVEL_QUERY) without CHECKSUM_UNNECESSARY. */
#ifndef EACCES
# define EACCES			13
#endif

#define TUNNEL_SRC_V4		v4_node_one
#define TUNNEL_DST_V4		v4_node_two
#define TUNNEL_SRC_V6		{ .addr = v6_node_one_addr }
#define TUNNEL_DST_V6		{ .addr = v6_node_two_addr }
#define TEST_VNI		0x456789
#define TEST_SPORT		51515

#define UNKNOWN_OPT_CLASS	0x9999
#define UNKNOWN_OPT_VALUE	0x11223344

struct test_opt {
	struct geneve_opt_hdr hdr;
	__be32 value;
} __packed;

/* What bpf_overlay would get from bpf_host after native decapsulation. */
static struct {
	__u32 count;
	int csum_level;
	__u8 opt_len;
	struct test_opt opt;
} overlay;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY)
int test_from_overlay_receiver(struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	overlay.count++;
	overlay.csum_level = csum_level(ctx, BPF_CSUM_LEVEL_QUERY);
	if (meta && meta->magic == GENEVE_META_MAGIC) {
		overlay.opt_len = meta->opt_len;
		__bpf_memcpy_builtin(&overlay.opt, meta->raw_opts,
				     sizeof(overlay.opt));
	}
	return CTX_ACT_OK;
}

static int setup_csum_level;

static __always_inline void reset_overlay(void)
{
	__bpf_memzero(&overlay, sizeof(overlay));
	setup_csum_level = 0;
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

static __always_inline int build_inner_v6(struct __ctx_buff *ctx)
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

/* Set the ECN field of the IPv4 header behind the Ethernet header: the
 * inner one before encapsulation, the outer one after.
 */
static __always_inline int set_ecn4(struct __ctx_buff *ctx, __u8 ecn)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4 = data + ETH_HLEN;

	if ((void *)(ip4 + 1) > data_end)
		return TEST_ERROR;
	ip4->tos = (__u8)((ip4->tos & ~GENEVE_ECN_MASK) | ecn);
	ip4->check = 0;
	ip4->check = geneve_ipv4_csum(ip4);
	return 0;
}

/* As set_ecn4(), for an IPv6 header. */
static __always_inline int set_ecn6(struct __ctx_buff *ctx, __u8 ecn)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv6hdr *ip6 = data + ETH_HLEN;

	if ((void *)(ip6 + 1) > data_end)
		return TEST_ERROR;
	ip6->flow_lbl[0] = (__u8)((ip6->flow_lbl[0] & ~(GENEVE_ECN_MASK << 4)) |
				  (ecn << 4));
	return 0;
}

static __always_inline int encap4(struct __ctx_buff *ctx, const struct test_opt *opt)
{
	return geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			     bpf_htons(TEST_SPORT), (const __u8 *)opt,
			     opt ? sizeof(*opt) : 0);
}

static __always_inline __u32 status_code(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return TEST_ERROR;
	return *(__u32 *)data;
}

/* The decapsulated inner IPv4 header, behind the status code. */
static __always_inline const struct iphdr *
inner_ip4(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	const struct iphdr *ip4 = data + sizeof(__u32) + ETH_HLEN;

	if ((void *)(ip4 + 1) > data_end)
		return NULL;
	return ip4;
}

/* D11: the device verified the outer UDP checksum and the inner L4 one
 * (CHECKSUM_UNNECESSARY, csum_level 1). Removing the outer UDP header
 * consumes one level, as the kernel's UDP receive path does.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_csum_level_consumed")
int geneve_pipeline_csum_level_consumed_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_csum_level_consumed")
int geneve_pipeline_csum_level_consumed_setup(struct __ctx_buff *ctx)
{
	reset_overlay();
	if (encap4(ctx, NULL))
		return TEST_ERROR;
	csum_level(ctx, BPF_CSUM_LEVEL_INC);
	csum_level(ctx, BPF_CSUM_LEVEL_INC);
	setup_csum_level = csum_level(ctx, BPF_CSUM_LEVEL_QUERY);
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_csum_level_consumed")
int geneve_pipeline_csum_level_consumed_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(setup_csum_level == 1);
	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);
	assert(overlay.csum_level == 0);

	test_finish();
}

/* D11: when only the outer UDP checksum was verified, the inner L4
 * checksum is not taken as verified after decapsulation.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_csum_level_outer_only")
int geneve_pipeline_csum_level_outer_only_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_csum_level_outer_only")
int geneve_pipeline_csum_level_outer_only_setup(struct __ctx_buff *ctx)
{
	reset_overlay();
	if (encap4(ctx, NULL))
		return TEST_ERROR;
	csum_level(ctx, BPF_CSUM_LEVEL_INC);
	setup_csum_level = csum_level(ctx, BPF_CSUM_LEVEL_QUERY);
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_csum_level_outer_only")
int geneve_pipeline_csum_level_outer_only_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(setup_csum_level == 0);
	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);
	assert(overlay.csum_level == -EACCES);

	test_finish();
}

/* D11: nothing verified (CHECKSUM_NONE): decapsulation is unaffected and
 * nothing is marked as verified.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_csum_level_none")
int geneve_pipeline_csum_level_none_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_csum_level_none")
int geneve_pipeline_csum_level_none_setup(struct __ctx_buff *ctx)
{
	reset_overlay();
	if (encap4(ctx, NULL))
		return TEST_ERROR;
	setup_csum_level = csum_level(ctx, BPF_CSUM_LEVEL_QUERY);
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_csum_level_none")
int geneve_pipeline_csum_level_none_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(setup_csum_level == -EACCES);
	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);
	assert(overlay.csum_level == -EACCES);

	test_finish();
}

/* D16: a CE mark on the outer header is propagated to an ECN-capable
 * inner IPv4 header, whose header checksum stays valid.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_ecn_ce_v4")
int geneve_pipeline_ecn_ce_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_ecn_ce_v4")
int geneve_pipeline_ecn_ce_v4_setup(struct __ctx_buff *ctx)
{
	reset_overlay();
	if (set_ecn4(ctx, GENEVE_ECN_ECT_0) || encap4(ctx, NULL) ||
	    set_ecn4(ctx, GENEVE_ECN_CE))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_ecn_ce_v4")
int geneve_pipeline_ecn_ce_v4_check(const struct __ctx_buff *ctx)
{
	const struct iphdr *ip4;

	test_init();

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);

	ip4 = inner_ip4(ctx);
	if (!ip4)
		test_fatal("inner IPv4 header out of bounds");
	assert(ip4->daddr == v4_pod_two);
	assert((ip4->tos & GENEVE_ECN_MASK) == GENEVE_ECN_CE);
	assert(geneve_ipv4_csum(ip4) == 0);

	test_finish();
}

/* D16: a CE mark cannot be propagated to an inner header that is not
 * ECN-capable; RFC 6040 requires the packet to be dropped.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_ecn_ce_not_ect_drops")
int geneve_pipeline_ecn_ce_not_ect_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_ecn_ce_not_ect_drops")
int geneve_pipeline_ecn_ce_not_ect_drops_setup(struct __ctx_buff *ctx)
{
	reset_overlay();
	metrics_del_entry((__u8)-DROP_INVALID, METRIC_INGRESS);
	if (set_ecn4(ctx, GENEVE_ECN_NOT_ECT) || encap4(ctx, NULL) ||
	    set_ecn4(ctx, GENEVE_ECN_CE))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_ecn_ce_not_ect_drops")
int geneve_pipeline_ecn_ce_not_ect_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_INVALID,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert(overlay.count == 0);
	assert_metrics_count(key, 1);

	test_finish();
}

/* D16: as geneve_pipeline_ecn_ce_v4, for an inner IPv6 header in an outer
 * IPv6 one.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_ecn_ce_v6")
int geneve_pipeline_ecn_ce_v6_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_ecn_ce_v6")
int geneve_pipeline_ecn_ce_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = TUNNEL_SRC_V6;
	const union v6addr daddr = TUNNEL_DST_V6;

	reset_overlay();
	if (set_ecn6(ctx, GENEVE_ECN_ECT_0))
		return TEST_ERROR;
	if (geneve_encap6(ctx, &saddr, &daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			  NULL, 0))
		return TEST_ERROR;
	if (set_ecn6(ctx, GENEVE_ECN_CE))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_ecn_ce_v6")
int geneve_pipeline_ecn_ce_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_pod_two_addr };
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	const struct ipv6hdr *ip6 = data + sizeof(__u32) + ETH_HLEN;

	test_init();

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);

	if ((void *)(ip6 + 1) > data_end)
		test_fatal("inner IPv6 header out of bounds");
	assert(ipv6_addr_equals((const union v6addr *)&ip6->daddr, &expected_dst));
	assert(((ip6->flow_lbl[0] >> 4) & GENEVE_ECN_MASK) == GENEVE_ECN_CE);

	test_finish();
}

/* RFC 8926 section 3.5.2: a packet with a critical option this node does
 * not understand is dropped before it reaches bpf_overlay.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_unknown_critical_opt_drops")
int geneve_pipeline_unknown_critical_opt_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_unknown_critical_opt_drops")
int geneve_pipeline_unknown_critical_opt_drops_setup(struct __ctx_buff *ctx)
{
	const struct test_opt opt = {
		.hdr = {
			.opt_class = bpf_htons(UNKNOWN_OPT_CLASS),
			.type = GENEVE_OPT_TYPE_CRIT | 0x01,
			.length = 1,
		},
		.value = bpf_htonl(UNKNOWN_OPT_VALUE),
	};

	reset_overlay();
	metrics_del_entry((__u8)-DROP_GENEVE_OPT_INVALID, METRIC_INGRESS);
	if (encap4(ctx, &opt))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_unknown_critical_opt_drops")
int geneve_pipeline_unknown_critical_opt_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_GENEVE_OPT_INVALID,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert(overlay.count == 0);
	assert_metrics_count(key, 1);

	test_finish();
}

/* RFC 8926: an unknown option that is not critical is accepted and handed
 * to bpf_overlay in the ingress slot.
 */
PKTGEN(PROG_TYPE, "geneve_pipeline_unknown_opt_kept")
int geneve_pipeline_unknown_opt_kept_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_pipeline_unknown_opt_kept")
int geneve_pipeline_unknown_opt_kept_setup(struct __ctx_buff *ctx)
{
	const struct test_opt opt = {
		.hdr = {
			.opt_class = bpf_htons(UNKNOWN_OPT_CLASS),
			.type = 0x01,
			.length = 1,
		},
		.value = bpf_htonl(UNKNOWN_OPT_VALUE),
	};

	reset_overlay();
	if (encap4(ctx, &opt))
		return TEST_ERROR;
	return netdev_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_pipeline_unknown_opt_kept")
int geneve_pipeline_unknown_opt_kept_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(overlay.count == 1);
	assert(overlay.opt_len == sizeof(struct test_opt));
	assert(overlay.opt.hdr.opt_class == bpf_htons(UNKNOWN_OPT_CLASS));
	assert(overlay.opt.hdr.type == 0x01);
	assert(overlay.opt.hdr.length == 1);
	assert(overlay.opt.value == bpf_htonl(UNKNOWN_OPT_VALUE));

	test_finish();
}
