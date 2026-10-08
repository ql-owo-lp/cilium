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
#define IS_BPF_HOST		1

#include "lib/common.h"
#include "lib/geneve.h"
#include "lib/geneve_encap.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

/* B4 (L1-04, L2-02, L2-09): the per-CPU ingress slot is only valid (magic
 * set) once geneve_decap4/6() decapsulated the packet it describes. A packet
 * dropped at any stage must leave it invalid, although the previous packet on
 * this CPU left it valid, and a successful decapsulation must not keep
 * anything of the previous packet.
 */

#define TEST_VNI	0x345678
#define STALE_VNI	0x0abcde
#define TEST_SPORT	50000

/* An unknown, non-critical option: accepted, and staged in the slot. */
#define TEST_OPT_CLASS	0xff01
#define TEST_OPT_TYPE	0x01
#define TEST_OPT_DATA	0x11223344

struct test_opt {
	struct geneve_opt_hdr hdr;
	__be32 data;
} __packed;

/* Headers as built by geneve_encap4/6() with one struct test_opt. */
struct outer4 {
	struct ethhdr eth;
	struct geneve_encaphdr4 hdr;
	struct test_opt opt;
	struct ethhdr inner_eth;
} __packed;

struct outer6 {
	struct ethhdr eth;
	struct geneve_encaphdr6 hdr;
	struct test_opt opt;
	struct ethhdr inner_eth;
} __packed;

enum drop_stage {
	STAGE_NEXTHDR,		/* IPv6 only */
	STAGE_CSUM_L3,		/* IPv4 only */
	STAGE_VERSION,
	STAGE_CONTROL,
	STAGE_UDP_LEN,
	STAGE_CRIT_OPT,
	STAGE_INNER_PROTO,
	STAGE_ECN,
	STAGE_MAX,
};

struct stage_result {
	int ret;
	__u32 magic;
};

static struct stage_result results[STAGE_MAX];
static bool ecn_drop_after_strip;

/* Copy of the slot after a successful decapsulation. */
static struct {
	int ret;
	__u32 magic;
	__u32 vni;
	__u8 family;
	__u8 opt_len;
	__u32 opts[2];
	__be32 saddr4;
	__be32 daddr4;
	union v6addr saddr6;
	union v6addr daddr6;
} staged;

static __always_inline void init_test_opt(struct test_opt *opt)
{
	opt->hdr.opt_class = bpf_htons(TEST_OPT_CLASS);
	opt->hdr.type = TEST_OPT_TYPE;
	opt->hdr.length = sizeof(opt->data) >> 2;
	opt->hdr.rsvd = 0;
	opt->data = bpf_htonl(TEST_OPT_DATA);
}

/* Leave the slot as a previous packet with another tunnel key, outer family,
 * addresses and options would have.
 */
static __always_inline int arm_stale_slot(__u8 family)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return -1;

	memset(meta, 0xff, sizeof(*meta));
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = STALE_VNI;
	meta->family = family;
	meta->opt_len = sizeof(struct test_opt);
	return 0;
}

static __always_inline int record_stage(struct stage_result *res, int ret)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return -1;
	res->ret = ret;
	res->magic = meta->magic;
	return 0;
}

static __always_inline int record_staged(int ret)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return -1;
	staged.ret = ret;
	staged.magic = meta->magic;
	staged.vni = meta->vni;
	staged.family = meta->family;
	staged.opt_len = meta->opt_len;
	staged.opts[0] = ((const __u32 *)meta->raw_opts)[0];
	staged.opts[1] = ((const __u32 *)meta->raw_opts)[1];
	staged.saddr4 = meta->ip4.saddr;
	staged.daddr4 = meta->ip4.daddr;
	ipv6_addr_copy(&staged.saddr6, &meta->ip6.saddr);
	ipv6_addr_copy(&staged.daddr6, &meta->ip6.daddr);
	return 0;
}

/* The slot holds exactly the struct test_opt of the packet. */
static __always_inline bool staged_opt_ok(void)
{
	const struct test_opt *opt = (const void *)staged.opts;

	return staged.opt_len == sizeof(*opt) &&
	       opt->hdr.opt_class == bpf_htons(TEST_OPT_CLASS) &&
	       opt->hdr.type == TEST_OPT_TYPE &&
	       opt->hdr.length == sizeof(opt->data) >> 2 &&
	       opt->data == bpf_htonl(TEST_OPT_DATA);
}

static __always_inline int
decap4_stage(struct __ctx_buff *ctx, enum drop_stage stage)
{
	if (arm_stale_slot(AF_INET6))
		return -1;
	return record_stage(&results[stage], geneve_decap4(ctx));
}

static __always_inline int
decap6_stage(struct __ctx_buff *ctx, enum drop_stage stage)
{
	if (arm_stale_slot(AF_INET))
		return -1;
	return record_stage(&results[stage], geneve_decap6(ctx));
}

static __always_inline struct outer4 *outer4_hdr(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct outer4 *outer = data;

	if ((void *)(outer + 1) > data_end)
		return NULL;
	return outer;
}

static __always_inline struct outer6 *outer6_hdr(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct outer6 *outer = data;

	if ((void *)(outer + 1) > data_end)
		return NULL;
	return outer;
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

static __always_inline int encap4(struct __ctx_buff *ctx, bool with_opt)
{
	struct test_opt opt;

	init_test_opt(&opt);
	return geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
			     bpf_htons(TEST_SPORT), with_opt ? (const __u8 *)&opt : NULL,
			     with_opt ? sizeof(opt) : 0);
}

static __always_inline int encap6(struct __ctx_buff *ctx, bool with_opt)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	struct test_opt opt;

	init_test_opt(&opt);
	return geneve_encap6(ctx, &saddr, &daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			     with_opt ? (const __u8 *)&opt : NULL,
			     with_opt ? sizeof(opt) : 0);
}

static __always_inline bool setup_ok(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	return data + sizeof(__u32) <= data_end && *(__u32 *)data == 0;
}

/* B4: every IPv4 decapsulation failure invalidates a stale slot. */
PKTGEN(PROG_TYPE, "geneve_decap4_drop_invalidates_slot")
int geneve_decap4_drop_invalidates_slot_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_decap4_drop_invalidates_slot")
int geneve_decap4_drop_invalidates_slot_setup(struct __ctx_buff *ctx)
{
	__u64 inner_len = ctx_full_len(ctx);
	struct outer4 *outer;

	if (encap4(ctx, true))
		return TEST_ERROR;

	/* Each stage breaks one field, decapsulates and restores the field. */
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.ip.check ^= bpf_htons(1);
	if (decap4_stage(ctx, STAGE_CSUM_L3))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.ip.check ^= bpf_htons(1);

	outer->hdr.geneve.ver = 1;
	if (decap4_stage(ctx, STAGE_VERSION))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.geneve.ver = GENEVE_VERSION;

	outer->hdr.geneve.control = 1;
	if (decap4_stage(ctx, STAGE_CONTROL))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.geneve.control = 0;

	/* UDP length beyond the IP payload */
	outer->hdr.udp.len = bpf_htons(bpf_ntohs(outer->hdr.udp.len) + 4);
	if (decap4_stage(ctx, STAGE_UDP_LEN))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.udp.len = bpf_htons(bpf_ntohs(outer->hdr.udp.len) - 4);

	/* Unknown option class with the critical bit */
	outer->opt.hdr.type |= GENEVE_OPT_TYPE_CRIT;
	if (decap4_stage(ctx, STAGE_CRIT_OPT))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->opt.hdr.type &= (__u8)~GENEVE_OPT_TYPE_CRIT;

	outer->inner_eth.h_proto = bpf_htons(ETH_P_ARP);
	if (decap4_stage(ctx, STAGE_INNER_PROTO))
		return TEST_ERROR;
	outer = outer4_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->inner_eth.h_proto = bpf_htons(ETH_P_IP);

	/* Last: CE on the outer header of a Not-ECT packet (RFC 6040) is only
	 * detected once the encapsulation has been stripped.
	 */
	outer->hdr.ip.tos = GENEVE_ECN_CE;
	outer->hdr.ip.check = 0;
	outer->hdr.ip.check = geneve_ipv4_csum(&outer->hdr.ip);
	if (decap4_stage(ctx, STAGE_ECN))
		return TEST_ERROR;
	ecn_drop_after_strip = ctx_full_len(ctx) == inner_len;

	return 0;
}

CHECK(PROG_TYPE, "geneve_decap4_drop_invalidates_slot")
int geneve_decap4_drop_invalidates_slot_check(const struct __ctx_buff *ctx)
{
	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	TEST("outer_ipv4_csum", {
		assert(results[STAGE_CSUM_L3].ret == DROP_CSUM_L3);
		assert(results[STAGE_CSUM_L3].magic == 0);
	});
	TEST("geneve_version", {
		assert(results[STAGE_VERSION].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_VERSION].magic == 0);
	});
	TEST("geneve_control", {
		assert(results[STAGE_CONTROL].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_CONTROL].magic == 0);
	});
	TEST("udp_len_overrun", {
		assert(results[STAGE_UDP_LEN].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_UDP_LEN].magic == 0);
	});
	TEST("unknown_critical_opt", {
		assert(results[STAGE_CRIT_OPT].ret == DROP_GENEVE_OPT_INVALID);
		assert(results[STAGE_CRIT_OPT].magic == 0);
	});
	TEST("inner_proto", {
		assert(results[STAGE_INNER_PROTO].ret == DROP_UNKNOWN_L3);
		assert(results[STAGE_INNER_PROTO].magic == 0);
	});
	TEST("ecn_after_strip", {
		assert(results[STAGE_ECN].ret == DROP_INVALID);
		assert(ecn_drop_after_strip);
		assert(results[STAGE_ECN].magic == 0);
	});

	test_finish();
}

/* B4: a successful IPv4 decapsulation replaces every field of a stale slot. */
PKTGEN(PROG_TYPE, "geneve_decap4_success_replaces_slot")
int geneve_decap4_success_replaces_slot_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_decap4_success_replaces_slot")
int geneve_decap4_success_replaces_slot_setup(struct __ctx_buff *ctx)
{
	if (encap4(ctx, true) || arm_stale_slot(AF_INET6))
		return TEST_ERROR;
	if (record_staged(geneve_decap4(ctx)))
		return TEST_ERROR;
	return 0;
}

CHECK(PROG_TYPE, "geneve_decap4_success_replaces_slot")
int geneve_decap4_success_replaces_slot_check(const struct __ctx_buff *ctx)
{
	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	assert(staged.ret == 0);
	assert(staged.magic == GENEVE_META_MAGIC);
	assert(staged.vni == TEST_VNI);
	assert(staged.family == AF_INET);
	assert(staged.saddr4 == v4_node_one);
	assert(staged.daddr4 == v4_node_two);
	assert(staged_opt_ok());

	test_finish();
}

/* B4: options of a stale slot do not survive a packet without options. */
PKTGEN(PROG_TYPE, "geneve_decap4_success_without_opts_clears_opts")
int geneve_decap4_success_without_opts_clears_opts_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_decap4_success_without_opts_clears_opts")
int geneve_decap4_success_without_opts_clears_opts_setup(struct __ctx_buff *ctx)
{
	if (encap4(ctx, false) || arm_stale_slot(AF_INET6))
		return TEST_ERROR;
	if (record_staged(geneve_decap4(ctx)))
		return TEST_ERROR;
	return 0;
}

CHECK(PROG_TYPE, "geneve_decap4_success_without_opts_clears_opts")
int geneve_decap4_success_without_opts_clears_opts_check(const struct __ctx_buff *ctx)
{
	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	assert(staged.ret == 0);
	assert(staged.magic == GENEVE_META_MAGIC);
	assert(staged.opt_len == 0);

	test_finish();
}

/* B4: every IPv6 decapsulation failure invalidates a stale slot. */
PKTGEN(PROG_TYPE, "geneve_decap6_drop_invalidates_slot")
int geneve_decap6_drop_invalidates_slot_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6(ctx);
}

SETUP(PROG_TYPE, "geneve_decap6_drop_invalidates_slot")
int geneve_decap6_drop_invalidates_slot_setup(struct __ctx_buff *ctx)
{
	__u64 inner_len = ctx_full_len(ctx);
	struct outer6 *outer;

	if (encap6(ctx, true))
		return TEST_ERROR;

	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.ip6.nexthdr = IPPROTO_TCP;
	if (decap6_stage(ctx, STAGE_NEXTHDR))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.ip6.nexthdr = IPPROTO_UDP;

	outer->hdr.geneve.ver = 1;
	if (decap6_stage(ctx, STAGE_VERSION))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.geneve.ver = GENEVE_VERSION;

	outer->hdr.geneve.control = 1;
	if (decap6_stage(ctx, STAGE_CONTROL))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.geneve.control = 0;

	outer->hdr.udp.len = bpf_htons(bpf_ntohs(outer->hdr.udp.len) + 4);
	if (decap6_stage(ctx, STAGE_UDP_LEN))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->hdr.udp.len = bpf_htons(bpf_ntohs(outer->hdr.udp.len) - 4);

	outer->opt.hdr.type |= GENEVE_OPT_TYPE_CRIT;
	if (decap6_stage(ctx, STAGE_CRIT_OPT))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->opt.hdr.type &= (__u8)~GENEVE_OPT_TYPE_CRIT;

	outer->inner_eth.h_proto = bpf_htons(ETH_P_ARP);
	if (decap6_stage(ctx, STAGE_INNER_PROTO))
		return TEST_ERROR;
	outer = outer6_hdr(ctx);
	if (!outer)
		return TEST_ERROR;
	outer->inner_eth.h_proto = bpf_htons(ETH_P_IPV6);

	/* The ECN field is in bits 5:4 of the second byte. */
	outer->hdr.ip6.flow_lbl[0] = (outer->hdr.ip6.flow_lbl[0] & 0xcf) |
				     (GENEVE_ECN_CE << 4);
	if (decap6_stage(ctx, STAGE_ECN))
		return TEST_ERROR;
	ecn_drop_after_strip = ctx_full_len(ctx) == inner_len;

	return 0;
}

CHECK(PROG_TYPE, "geneve_decap6_drop_invalidates_slot")
int geneve_decap6_drop_invalidates_slot_check(const struct __ctx_buff *ctx)
{
	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	TEST("outer_ipv6_nexthdr", {
		assert(results[STAGE_NEXTHDR].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_NEXTHDR].magic == 0);
	});
	TEST("geneve_version", {
		assert(results[STAGE_VERSION].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_VERSION].magic == 0);
	});
	TEST("geneve_control", {
		assert(results[STAGE_CONTROL].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_CONTROL].magic == 0);
	});
	TEST("udp_len_overrun", {
		assert(results[STAGE_UDP_LEN].ret == DROP_GENEVE_HDR_INVALID);
		assert(results[STAGE_UDP_LEN].magic == 0);
	});
	TEST("unknown_critical_opt", {
		assert(results[STAGE_CRIT_OPT].ret == DROP_GENEVE_OPT_INVALID);
		assert(results[STAGE_CRIT_OPT].magic == 0);
	});
	TEST("inner_proto", {
		assert(results[STAGE_INNER_PROTO].ret == DROP_UNKNOWN_L3);
		assert(results[STAGE_INNER_PROTO].magic == 0);
	});
	TEST("ecn_after_strip", {
		assert(results[STAGE_ECN].ret == DROP_INVALID);
		assert(ecn_drop_after_strip);
		assert(results[STAGE_ECN].magic == 0);
	});

	test_finish();
}

/* B4: a successful IPv6 decapsulation replaces every field of a stale slot. */
PKTGEN(PROG_TYPE, "geneve_decap6_success_replaces_slot")
int geneve_decap6_success_replaces_slot_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6(ctx);
}

SETUP(PROG_TYPE, "geneve_decap6_success_replaces_slot")
int geneve_decap6_success_replaces_slot_setup(struct __ctx_buff *ctx)
{
	if (encap6(ctx, true) || arm_stale_slot(AF_INET))
		return TEST_ERROR;
	if (record_staged(geneve_decap6(ctx)))
		return TEST_ERROR;
	return 0;
}

CHECK(PROG_TYPE, "geneve_decap6_success_replaces_slot")
int geneve_decap6_success_replaces_slot_check(const struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };

	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	assert(staged.ret == 0);
	assert(staged.magic == GENEVE_META_MAGIC);
	assert(staged.vni == TEST_VNI);
	assert(staged.family == AF_INET6);
	assert(ipv6_addr_equals(&staged.saddr6, &saddr));
	assert(ipv6_addr_equals(&staged.daddr6, &daddr));
	assert(staged_opt_ok());

	test_finish();
}

/* B4: options of a stale slot do not survive a packet without options. */
PKTGEN(PROG_TYPE, "geneve_decap6_success_without_opts_clears_opts")
int geneve_decap6_success_without_opts_clears_opts_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6(ctx);
}

SETUP(PROG_TYPE, "geneve_decap6_success_without_opts_clears_opts")
int geneve_decap6_success_without_opts_clears_opts_setup(struct __ctx_buff *ctx)
{
	if (encap6(ctx, false) || arm_stale_slot(AF_INET))
		return TEST_ERROR;
	if (record_staged(geneve_decap6(ctx)))
		return TEST_ERROR;
	return 0;
}

CHECK(PROG_TYPE, "geneve_decap6_success_without_opts_clears_opts")
int geneve_decap6_success_without_opts_clears_opts_check(const struct __ctx_buff *ctx)
{
	test_init();

	if (!setup_ok(ctx))
		test_fatal("setup failed");

	assert(staged.ret == 0);
	assert(staged.magic == GENEVE_META_MAGIC);
	assert(staged.opt_len == 0);

	test_finish();
}
