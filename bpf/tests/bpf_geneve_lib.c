// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Unit tests for the native BPF Geneve library (lib/geneve.h) in Ethernet
 * mode, with the default outer UDP source port range. Only lib/geneve.h and
 * the headers it depends on are included, not the datapath integration.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_BPF_GENEVE	1

/* get_hash_recalc() returns mock_skb_hash. */
static __u32 mock_skb_hash;

static __always_inline __u32
mock_get_hash_recalc(struct __sk_buff *ctx __maybe_unused)
{
	return mock_skb_hash;
}

#define get_hash_recalc mock_get_hash_recalc

/* get_prandom_u32() returns a fixed sequence, prandom_last is the value it
 * returned last.
 */
static __u32 prandom_last;

static __always_inline __u32 mock_get_prandom_u32(void)
{
	prandom_last += 0x13572468;
	return prandom_last;
}

#define get_prandom_u32 mock_get_prandom_u32

/* bpf_skb_adjust_room() records its arguments and fails with
 * adjust_room_ret if that is set.
 */
static __u32 adjust_room_calls;
static __s32 adjust_room_len_diff;
static __u32 adjust_room_mode;
static __u64 adjust_room_flags;
static int adjust_room_ret;
/* The kernel refuses to encapsulate an skb twice (-EALREADY). For a nested
 * encapsulation, request the room without the encapsulation flags, which
 * only describe the new headers for GSO.
 */
static bool adjust_room_nested;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *ctx, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	adjust_room_calls++;
	adjust_room_len_diff = len_diff;
	adjust_room_mode = mode;
	adjust_room_flags = flags;
	if (adjust_room_ret)
		return adjust_room_ret;
	if (adjust_room_nested)
		flags &= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
	return skb_adjust_room(ctx, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

#include "lib/common.h"
#include "lib/geneve.h"
#include "lib/tailcall.h"

ASSIGN_CONFIG(__u16, tunnel_port, 6081)

#define TEST_VNI	0xabcdef
#define TEST_SPORT	50000
/* DSCP EF in the upper six bits of the IPv4 TOS / IPv6 traffic class. */
#define TOS_DSCP_EF	0xb8
#define TEST_FLOWLABEL	0xabcde
/* Option class of another vendor, and a non-critical type. */
#define TEST_OPT_CLASS	0x0102
#define TEST_OPT_TYPE	0x01

#define INNER_V4_LEN	(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + \
			 sizeof(default_data))
#define INNER_V6_LEN	(ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + \
			 sizeof(default_data))

/* Bytes that the encapsulation with a DSR option inserts. */
#define ENCAP4_ROOM	(sizeof(struct geneve_encaphdr4) + sizeof(struct geneve_dsr_opt4) + \
			 ETH_HLEN)
#define ENCAP6_ROOM	(sizeof(struct geneve_encaphdr6) + sizeof(struct geneve_dsr_opt6) + \
			 ETH_HLEN)

/* bpf_skb_adjust_room() flags of an Ethernet mode encapsulation. */
#define ENCAP_FLAGS_ETH(l3_flag)					\
	(BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET |	\
	 BPF_F_ADJ_ROOM_ENCAP_L4_UDP | (l3_flag) |			\
	 BPF_F_ADJ_ROOM_ENCAP_L2_ETH | BPF_F_ADJ_ROOM_ENCAP_L2(ETH_HLEN))

/* Option area, sized like geneve_metadata.raw_opts. */
static struct geneve_opt_hdr opts[GENEVE_OPT_MAX_COUNT + 1];

static struct geneve_dsr_opt4 dsr_opt4;
static struct geneve_dsr_opt6 dsr_opt6;

/* Copy of the packet before the operation under test, and scratch space
 * for packet_equals().
 */
static __u64 pkt_before[16];
static __u64 pkt_scratch[16];

static __always_inline void mock_reset(void)
{
	adjust_room_calls = 0;
	adjust_room_len_diff = 0;
	adjust_room_mode = 0;
	adjust_room_flags = 0;
	adjust_room_ret = 0;
	adjust_room_nested = false;
}

/* Write the header of a TLV with @words data words at option word @idx. */
static __always_inline void
put_opt(__u32 idx, __u16 opt_class, __u8 type, __u8 words)
{
	opts[idx].opt_class = bpf_htons(opt_class);
	opts[idx].type = type;
	opts[idx].rsvd = 0;
	opts[idx].length = words;
}

/* IPv4 TCP packet with IPv4 TOS @tos. */
static __always_inline int build_inner_ipv4(struct __ctx_buff *ctx, __u8 tos)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct iphdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      v4_pod_one, v4_pod_two);
	if (!l3)
		return TEST_ERROR;
	l3->tos = tos;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* IPv6 TCP packet with traffic class @tclass and flow label @flowlabel. */
static __always_inline int
build_inner_ipv6(struct __ctx_buff *ctx, __u8 tclass, __u32 flowlabel)
{
	struct pktgen builder;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)v6_pod_one, (__u8 *)v6_pod_two);
	if (!l3)
		return TEST_ERROR;
	l3->priority = tclass >> 4;
	l3->flow_lbl[0] = (__u8)((tclass << 4) | ((flowlabel >> 16) & 0x0f));
	l3->flow_lbl[1] = (__u8)(flowlabel >> 8);
	l3->flow_lbl[2] = (__u8)flowlabel;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Whether the @len bytes at offset @off of the packet equal @expected. */
static __always_inline bool
packet_equals(const struct __ctx_buff *ctx, __u32 off, const void *expected,
	      __u32 len)
{
	if (ctx_load_bytes(ctx, off, pkt_scratch, len) < 0)
		return false;
	return !memcmp(pkt_scratch, expected, len);
}

/* L1-09: low = high = 0 selects 1-65535, the range of a geneve device
 * without a port range, mapped with the arithmetic of the kernel's
 * udp_flow_src_port(): hash ^= hash << 16;
 * port = (((u64)hash * (max - min)) >> 32) + min. The expected ports were
 * computed with that formula.
 */
CHECK("tc", "geneve_src_port_default_range")
int geneve_src_port_default_range_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("matches_udp_flow_src_port", {
		assert(geneve_src_port(0) == bpf_htons(1));
		assert(geneve_src_port(1) == bpf_htons(1));
		assert(geneve_src_port(0x12345678) == bpf_htons(17484));
		assert(geneve_src_port(0xffffffff) == bpf_htons(1));
		assert(geneve_src_port(0x80000000) == bpf_htons(32768));
	});

	TEST("stays_within_1_65534", {
		/* The port grows with the folded hash: folded hash 0 yields
		 * the lowest port, which is not 0, and 0xffffffff (hash
		 * 0x0000ffff) the highest one, max - 1 as in the kernel.
		 */
		assert(geneve_src_port(0x00000000) == bpf_htons(1));
		assert(geneve_src_port(0x0000ffff) == bpf_htons(65534));
	});

	test_finish();
}

/* L1-09: the source port is derived from the flow hash that the kernel
 * geneve device uses, or from the VNI and the remote endpoint for packets
 * without one.
 */
CHECK("tc", "geneve_flow_hash")
int geneve_flow_hash_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("uses_skb_hash", {
		mock_skb_hash = 0x9e3779b9;
		assert(geneve_flow_hash(ctx, TEST_VNI, v4_node_two) == 0x9e3779b9);
	});

	TEST("hashes_vni_and_remote_without_skb_hash", {
		mock_skb_hash = 0;
		assert(geneve_flow_hash(ctx, TEST_VNI, v4_node_two) ==
		       jhash_2words(TEST_VNI, v4_node_two, 0));
	});

	test_finish();
}

/* L1-10/L1-24: RFC 6040 normal mode, as the kernel geneve device without
 * "tos inherit": the outer header carries the inner ECN field but not the
 * DSCP, and decapsulation follows RFC 6040 section 4.2.
 */
CHECK("tc", "geneve_rfc6040_ecn")
int geneve_rfc6040_ecn_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("encap_copies_ecn_not_dscp", {
		assert(geneve_outer_tos(TOS_DSCP_EF | GENEVE_ECN_NOT_ECT) == GENEVE_ECN_NOT_ECT);
		assert(geneve_outer_tos(TOS_DSCP_EF | GENEVE_ECN_ECT_1) == GENEVE_ECN_ECT_1);
		assert(geneve_outer_tos(TOS_DSCP_EF | GENEVE_ECN_ECT_0) == GENEVE_ECN_ECT_0);
	});

	TEST("encap_sends_ce_as_ect0", {
		assert(geneve_outer_tos(TOS_DSCP_EF | GENEVE_ECN_CE) == GENEVE_ECN_ECT_0);
	});

	TEST("decap_outer_not_ect_keeps_inner", {
		assert(geneve_ecn_decap(GENEVE_ECN_NOT_ECT, GENEVE_ECN_NOT_ECT) ==
		       GENEVE_ECN_NOT_ECT);
		assert(geneve_ecn_decap(GENEVE_ECN_NOT_ECT, GENEVE_ECN_ECT_0) == GENEVE_ECN_ECT_0);
		assert(geneve_ecn_decap(GENEVE_ECN_NOT_ECT, GENEVE_ECN_ECT_1) == GENEVE_ECN_ECT_1);
		assert(geneve_ecn_decap(GENEVE_ECN_NOT_ECT, GENEVE_ECN_CE) == GENEVE_ECN_CE);
	});

	TEST("decap_outer_ect0_keeps_inner", {
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_0, GENEVE_ECN_NOT_ECT) ==
		       GENEVE_ECN_NOT_ECT);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_0, GENEVE_ECN_ECT_0) == GENEVE_ECN_ECT_0);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_0, GENEVE_ECN_ECT_1) == GENEVE_ECN_ECT_1);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_0, GENEVE_ECN_CE) == GENEVE_ECN_CE);
	});

	TEST("decap_outer_ect1_turns_ect0_into_ect1", {
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_1, GENEVE_ECN_NOT_ECT) ==
		       GENEVE_ECN_NOT_ECT);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_1, GENEVE_ECN_ECT_0) == GENEVE_ECN_ECT_1);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_1, GENEVE_ECN_ECT_1) == GENEVE_ECN_ECT_1);
		assert(geneve_ecn_decap(GENEVE_ECN_ECT_1, GENEVE_ECN_CE) == GENEVE_ECN_CE);
	});

	TEST("decap_outer_ce_marks_ect_inner", {
		assert(geneve_ecn_decap(GENEVE_ECN_CE, GENEVE_ECN_ECT_0) == GENEVE_ECN_CE);
		assert(geneve_ecn_decap(GENEVE_ECN_CE, GENEVE_ECN_ECT_1) == GENEVE_ECN_CE);
		assert(geneve_ecn_decap(GENEVE_ECN_CE, GENEVE_ECN_CE) == GENEVE_ECN_CE);
	});

	TEST("decap_outer_ce_drops_not_ect_inner", {
		assert(geneve_ecn_decap(GENEVE_ECN_CE, GENEVE_ECN_NOT_ECT) == -1);
	});

	test_finish();
}

/* RFC 8926 option validation. L1-23: the only critical option that Cilium
 * understands is its DSR option; packets with other critical options must
 * be dropped (RFC 8926 section 3.5.2).
 */
CHECK("tc", "geneve_validate_opts")
int geneve_validate_opts_check(struct __ctx_buff *ctx __maybe_unused)
{
	const __u8 *buf = (const __u8 *)opts;
	__u32 i;

	test_init();

	TEST("empty_accepted", {
		assert(geneve_validate_opts(buf, 0));
	});

	TEST("max_len_accepted", {
		for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++)
			put_opt(i, TEST_OPT_CLASS, TEST_OPT_TYPE, 0);
		assert(geneve_validate_opts(buf, GENEVE_OPT_MAX_LEN));
	});

	TEST("over_max_len_rejected", {
		/* Two well-formed options of 128 bytes each, which the TLV
		 * walk alone would accept.
		 */
		put_opt(0, TEST_OPT_CLASS, TEST_OPT_TYPE, 31);
		put_opt(32, TEST_OPT_CLASS, TEST_OPT_TYPE, 31);
		assert(!geneve_validate_opts(buf, GENEVE_OPT_MAX_LEN + 4));
	});

	TEST("overrun_rejected", {
		/* The last of 63 options runs 4 bytes past the option area. */
		for (i = 0; i < GENEVE_OPT_MAX_COUNT - 1; i++)
			put_opt(i, TEST_OPT_CLASS, TEST_OPT_TYPE, 0);
		put_opt(GENEVE_OPT_MAX_COUNT - 1, TEST_OPT_CLASS, TEST_OPT_TYPE, 1);
		assert(!geneve_validate_opts(buf, GENEVE_OPT_MAX_LEN));
	});

	TEST("trailing_bytes_rejected", {
		put_opt(0, TEST_OPT_CLASS, TEST_OPT_TYPE, 0);
		assert(!geneve_validate_opts(buf, sizeof(struct geneve_opt_hdr) + 2));
	});

	TEST("unknown_critical_class_rejected", {
		/* Behind a valid option: every option is checked. */
		put_opt(0, TEST_OPT_CLASS, TEST_OPT_TYPE, 0);
		put_opt(1, TEST_OPT_CLASS, GENEVE_OPT_TYPE_CRIT | TEST_OPT_TYPE, 0);
		assert(!geneve_validate_opts(buf, 2 * sizeof(struct geneve_opt_hdr)));
	});

	TEST("dsr_class_unknown_critical_type_rejected", {
		put_opt(0, DSR_GENEVE_OPT_CLASS, GENEVE_OPT_TYPE_CRIT | 0x02, 0);
		assert(!geneve_validate_opts(buf, sizeof(struct geneve_opt_hdr)));
	});

	TEST("dsr_option_accepted", {
		put_opt(0, DSR_GENEVE_OPT_CLASS, DSR_GENEVE_OPT_TYPE, DSR_IPV4_GENEVE_OPT_LEN);
		assert(geneve_validate_opts(buf, sizeof(struct geneve_dsr_opt4)));
	});

	TEST("unknown_non_critical_accepted", {
		put_opt(0, TEST_OPT_CLASS, TEST_OPT_TYPE, 1);
		assert(geneve_validate_opts(buf, 2 * sizeof(struct geneve_opt_hdr)));
	});

	test_finish();
}

/* F3: geneve_find_opt() finds options anywhere in a full option area and
 * never returns an option that is shorter than requested or extends past
 * the option area.
 */
CHECK("tc", "geneve_find_opt")
int geneve_find_opt_check(struct __ctx_buff *ctx __maybe_unused)
{
	const __u32 min_len = sizeof(struct geneve_opt_hdr);
	const __u8 *buf = (const __u8 *)opts;
	__u32 i;

	test_init();

	/* 63 options fill the option area, option i has class 0x0200 + i
	 * and type i.
	 */
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++)
		put_opt(i, (__u16)(0x0200 + i), (__u8)i, 0);

	TEST("first_found", {
		assert(geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200), 0,
				       min_len) == &opts[0]);
	});

	TEST("middle_found", {
		assert(geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 31), 31,
				       min_len) == &opts[31]);
	});

	TEST("last_found", {
		assert(geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 62), 62,
				       min_len) == &opts[62]);
	});

	TEST("missing_not_found", {
		assert(!geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 63), 63,
					min_len));
		/* Known class, other type. */
		assert(!geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 5), 6,
					min_len));
	});

	TEST("shorter_than_min_len_not_found", {
		assert(!geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 31), 31,
					min_len + 4));
	});

	TEST("over_max_len_not_found", {
		assert(!geneve_find_opt(buf, GENEVE_OPT_MAX_LEN + 4, bpf_htons(0x0200), 0,
					min_len));
	});

	TEST("truncated_not_found", {
		/* The last option claims 4 bytes past the option area. */
		put_opt(GENEVE_OPT_MAX_COUNT - 1, 0x0200 + 62, 62, 1);
		assert(!geneve_find_opt(buf, GENEVE_OPT_MAX_LEN, bpf_htons(0x0200 + 62), 62,
					min_len));
	});

	test_finish();
}

/* geneve_hdr_init() / geneve_hdr_vni(). L1-23: the O and C bits stay
 * clear, as the kernel geneve device leaves them for collect_md metadata.
 */
CHECK("tc", "geneve_hdr")
int geneve_hdr_check(struct __ctx_buff *ctx __maybe_unused)
{
	struct genevehdr hdr;

	test_init();

	TEST("init_fields", {
		memset(&hdr, 0xff, sizeof(hdr));
		geneve_hdr_init(&hdr, bpf_htons(ETH_P_TEB), TEST_VNI, GENEVE_OPT_MAX_COUNT);
		assert(hdr.ver == 0);
		assert(hdr.opt_len == GENEVE_OPT_MAX_COUNT);
		assert(!hdr.control);
		assert(!hdr.critical);
		assert(!hdr.rsvd);
		assert(hdr.protocol_type == bpf_htons(ETH_P_TEB));
		assert(hdr.vni[0] == 0xab && hdr.vni[1] == 0xcd && hdr.vni[2] == 0xef);
		assert(!hdr.reserved);
	});

	TEST("vni_roundtrip", {
		geneve_hdr_init(&hdr, bpf_htons(ETH_P_TEB), 0, 0);
		assert(geneve_hdr_vni(&hdr) == 0);
		geneve_hdr_init(&hdr, bpf_htons(ETH_P_TEB), 1, 0);
		assert(geneve_hdr_vni(&hdr) == 1);
		geneve_hdr_init(&hdr, bpf_htons(ETH_P_TEB), TEST_VNI, 0);
		assert(geneve_hdr_vni(&hdr) == TEST_VNI);
		geneve_hdr_init(&hdr, bpf_htons(ETH_P_TEB), 0xffffff, 0);
		assert(geneve_hdr_vni(&hdr) == 0xffffff);
	});

	test_finish();
}

/* geneve_ipv4_csum() for a header with the well-known checksum 0xb861:
 * 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7.
 */
CHECK("tc", "geneve_ipv4_csum")
int geneve_ipv4_csum_check(struct __ctx_buff *ctx __maybe_unused)
{
	struct iphdr ip4 = {
		.version = 4,
		.ihl = 5,
		.tot_len = bpf_htons(0x0073),
		.frag_off = bpf_htons(IP_DF),
		.ttl = 64,
		.protocol = IPPROTO_UDP,
		.saddr = bpf_htonl(0xc0a80001),
		.daddr = bpf_htonl(0xc0a800c7),
	};

	test_init();

	TEST("computes_checksum", {
		assert(geneve_ipv4_csum(&ip4) == bpf_htons(0xb861));
	});

	TEST("verifies_to_zero", {
		ip4.check = bpf_htons(0xb861);
		assert(geneve_ipv4_csum(&ip4) == 0);
	});

	test_finish();
}

/* geneve_encap_room(): the room in front of the inner L3 header includes
 * the inner Ethernet header in Ethernet mode.
 */
CHECK("tc", "geneve_encap_room")
int geneve_encap_room_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("includes_inner_eth", {
		assert(sizeof(struct geneve_encaphdr4) == 36);
		assert(sizeof(struct geneve_encaphdr6) == 56);
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr4), 0) == 36 + ETH_HLEN);
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr4), 12) ==
		       36 + 12 + ETH_HLEN);
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr6), GENEVE_OPT_MAX_LEN) ==
		       56 + GENEVE_OPT_MAX_LEN + ETH_HLEN);
	});

	test_finish();
}

/* Values that are shared with code outside lib/geneve.h. */
CHECK("tc", "geneve_constants")
int geneve_constants_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("abi_values", {
		/* The agent probes for this flag by its value, 1 << 10. */
		assert(BPF_F_ADJ_ROOM_DECAP_L4_UDP == (1ULL << 10));
		/* The Geneve tail calls fit into cilium_calls. */
		assert(CILIUM_CALL_GENEVE_ENCAP4 < CILIUM_CALL_SIZE);
		assert(CILIUM_CALL_GENEVE_ENCAP6 < CILIUM_CALL_SIZE);
		assert(CILIUM_CALL_GENEVE_DECAP4 < CILIUM_CALL_SIZE);
		assert(CILIUM_CALL_GENEVE_DECAP6 < CILIUM_CALL_SIZE);
		/* The monitor names drop reasons 208-210. */
		assert(DROP_GENEVE_HDR_INVALID == -208);
		assert(DROP_GENEVE_OPT_INVALID == -209);
		assert(DROP_GENEVE_ENCAP_FAILED == -210);
	});

	test_finish();
}

/* B4: the tc_index markers that bind the per-CPU metadata slots to a packet
 * are separate bits that neither affect each other nor the other tc_index
 * flags.
 */
CHECK("tc", "geneve_tc_index_markers")
int geneve_tc_index_markers_check(struct __ctx_buff *ctx)
{
	const __u32 others = TC_INDEX_F_FROM_INGRESS_PROXY | TC_INDEX_F_FROM_EGRESS_PROXY |
			     TC_INDEX_F_SKIP_NODEPORT | TC_INDEX_F_SKIP_HEALTH_CHECK;
	const __u32 markers = TC_INDEX_F_BPF_GENEVE_DECAP | TC_INDEX_F_BPF_GENEVE_ENCAP |
			      TC_INDEX_F_BPF_GENEVE_FALLBACK;

	test_init();

	TEST("independent_of_other_flags", {
		ctx->tc_index = others;
		assert(!ctx_bpf_geneve_decap_is_set(ctx));
		assert(!ctx_bpf_geneve_encap_is_set(ctx));
		assert(!ctx_bpf_geneve_fallback_is_set(ctx));

		ctx_bpf_geneve_decap_set(ctx);
		ctx_bpf_geneve_encap_set(ctx);
		ctx_bpf_geneve_fallback_set(ctx);
		assert(ctx->tc_index == (others | markers));

		ctx_bpf_geneve_decap_clear(ctx);
		ctx_bpf_geneve_encap_clear(ctx);
		ctx_bpf_geneve_fallback_clear(ctx);
		assert(ctx->tc_index == others);
	});

	TEST("independent_of_each_other", {
		ctx->tc_index = 0;
		ctx_bpf_geneve_decap_set(ctx);
		assert(ctx_bpf_geneve_decap_is_set(ctx));
		assert(!ctx_bpf_geneve_encap_is_set(ctx));
		assert(!ctx_bpf_geneve_fallback_is_set(ctx));

		ctx_bpf_geneve_encap_set(ctx);
		ctx_bpf_geneve_fallback_set(ctx);
		ctx_bpf_geneve_decap_clear(ctx);
		assert(!ctx_bpf_geneve_decap_is_set(ctx));
		assert(ctx_bpf_geneve_encap_is_set(ctx));
		assert(ctx_bpf_geneve_fallback_is_set(ctx));

		ctx_bpf_geneve_encap_clear(ctx);
		assert(!ctx_bpf_geneve_encap_is_set(ctx));
		assert(ctx_bpf_geneve_fallback_is_set(ctx));

		ctx_bpf_geneve_fallback_clear(ctx);
		assert(!ctx->tc_index);
	});

	test_finish();
}

/* geneve_encap4(): the frame that the kernel geneve device sends in
 * collect_md mode.
 */
PKTGEN("tc", "geneve_encap4")
int geneve_encap4_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv4(ctx, TOS_DSCP_EF | GENEVE_ECN_CE);
}

CHECK("tc", "geneve_encap4")
int geneve_encap4_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct genevehdr *geneve;
	struct udphdr *udp;
	struct iphdr *ip4;
	struct ethhdr *eth;
	int ret;

	test_init();

	mock_reset();
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &dsr_opt4);
	if (ctx_full_len(ctx) != INNER_V4_LEN ||
	    ctx_load_bytes(ctx, 0, pkt_before, INNER_V4_LEN) < 0)
		test_fatal("unexpected inner packet");

	ret = geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI, bpf_htons(TEST_SPORT),
			    (const __u8 *)&dsr_opt4, sizeof(dsr_opt4));
	if (ret)
		test_fatal("geneve_encap4() failed: %d", ret);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	eth = data;
	ip4 = data + ETH_HLEN;
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated packet too short");

	TEST("adjust_room", {
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)ENCAP4_ROOM);
		assert(adjust_room_mode == BPF_ADJ_ROOM_MAC);
		assert(adjust_room_flags == ENCAP_FLAGS_ETH(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4));
	});

	TEST("outer_eth_copies_inner", {
		assert(!memcmp(eth->h_dest, (__u8 *)mac_two, ETH_ALEN));
		assert(!memcmp(eth->h_source, (__u8 *)mac_one, ETH_ALEN));
		assert(eth->h_proto == bpf_htons(ETH_P_IP));
	});

	TEST("outer_ipv4", {
		assert(ip4->version == 4);
		assert(ip4->ihl == 5);
		assert(ip4->tot_len == bpf_htons(INNER_V4_LEN + ENCAP4_ROOM - ETH_HLEN));
		assert(ip4->ttl == 64);
		assert(ip4->protocol == IPPROTO_UDP);
		assert(ip4->saddr == v4_node_one);
		assert(ip4->daddr == v4_node_two);
		assert(!csum_fold(csum_diff(NULL, 0, ip4, sizeof(*ip4), 0)));
	});

	TEST("outer_ipv4_tos_is_ecn_only", {
		/* L1-10/L1-24: inner DSCP EF + CE is sent as ECT(0). */
		assert(ip4->tos == GENEVE_ECN_ECT_0);
	});

	TEST("outer_ipv4_df_clear", {
		/* U1: DF clear, as on the kernel path. */
		assert(ip4->frag_off == 0);
	});

	TEST("outer_udp", {
		assert(udp->source == bpf_htons(TEST_SPORT));
		assert(udp->dest == bpf_htons(6081));
		assert(udp->len == bpf_htons(INNER_V4_LEN + ENCAP4_ROOM - ETH_HLEN -
					     sizeof(struct iphdr)));
		assert(udp->check == 0);
	});

	TEST("geneve_header", {
		/* L1-23: the C bit stays clear despite the critical DSR option. */
		assert(geneve->ver == 0);
		assert(geneve->opt_len == sizeof(dsr_opt4) / 4);
		assert(!geneve->control);
		assert(!geneve->critical);
		assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
		assert(geneve_hdr_vni(geneve) == TEST_VNI);
	});

	TEST("options_copied", {
		assert(packet_equals(ctx, ETH_HLEN + sizeof(struct geneve_encaphdr4),
				     &dsr_opt4, sizeof(dsr_opt4)));
	});

	TEST("inner_frame_follows_options", {
		assert(ctx_full_len(ctx) == INNER_V4_LEN + ENCAP4_ROOM);
		assert(packet_equals(ctx, ENCAP4_ROOM, pkt_before, INNER_V4_LEN));
	});

	test_finish();
}

/* D31: every packet gets a fresh outer IPv4 ID from get_prandom_u32(), as
 * iptunnel_xmit() selects one on the kernel path, instead of a fixed ID.
 */
PKTGEN("tc", "geneve_encap4_fresh_id")
int geneve_encap4_fresh_id_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv4(ctx, 0);
}

CHECK("tc", "geneve_encap4_fresh_id")
int geneve_encap4_fresh_id_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 first_rand;
	__be16 first_id;

	test_init();

	mock_reset();

	TEST("id_per_packet", {
		if (geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				  bpf_htons(TEST_SPORT), NULL, 0))
			test_fatal("first geneve_encap4() failed");
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + ETH_HLEN;
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("packet too short");
		first_id = ip4->id;
		first_rand = prandom_last;

		adjust_room_nested = true;
		if (geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				  bpf_htons(TEST_SPORT), NULL, 0))
			test_fatal("second geneve_encap4() failed");
		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);
		ip4 = data + ETH_HLEN;
		if ((void *)(ip4 + 1) > data_end)
			test_fatal("packet too short");

		assert(first_id == bpf_htons((__u16)first_rand));
		assert(ip4->id == bpf_htons((__u16)prandom_last));
		assert(ip4->id != first_id);
	});

	test_finish();
}

/* geneve_encap6(). */
PKTGEN("tc", "geneve_encap6")
int geneve_encap6_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv6(ctx, TOS_DSCP_EF | GENEVE_ECN_ECT_1, TEST_FLOWLABEL);
}

CHECK("tc", "geneve_encap6")
int geneve_encap6_check(struct __ctx_buff *ctx)
{
	const union v6addr outer_saddr = { .addr = v6_node_one_addr };
	const union v6addr outer_daddr = { .addr = v6_node_two_addr };
	const union v6addr svc_addr = { .addr = v6_svc_one_addr };
	void *data, *data_end;
	struct genevehdr *geneve;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct ethhdr *eth;
	int ret;

	test_init();

	mock_reset();
	set_geneve_dsr_opt6(tcp_svc_one, &svc_addr, &dsr_opt6);
	if (ctx_full_len(ctx) != INNER_V6_LEN ||
	    ctx_load_bytes(ctx, 0, pkt_before, INNER_V6_LEN) < 0)
		test_fatal("unexpected inner packet");

	ret = geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			    (const __u8 *)&dsr_opt6, sizeof(dsr_opt6));
	if (ret)
		test_fatal("geneve_encap6() failed: %d", ret);

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	eth = data;
	ip6 = data + ETH_HLEN;
	udp = (void *)(ip6 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated packet too short");

	TEST("adjust_room", {
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)ENCAP6_ROOM);
		assert(adjust_room_mode == BPF_ADJ_ROOM_MAC);
		assert(adjust_room_flags == ENCAP_FLAGS_ETH(BPF_F_ADJ_ROOM_ENCAP_L3_IPV6));
	});

	TEST("outer_eth_copies_inner", {
		assert(!memcmp(eth->h_dest, (__u8 *)mac_two, ETH_ALEN));
		assert(!memcmp(eth->h_source, (__u8 *)mac_one, ETH_ALEN));
		assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	});

	TEST("outer_ipv6", {
		assert(ip6->version == 6);
		assert(ip6->payload_len == bpf_htons(INNER_V6_LEN + ENCAP6_ROOM - ETH_HLEN -
						     sizeof(struct ipv6hdr)));
		assert(ip6->nexthdr == IPPROTO_UDP);
		assert(ip6->hop_limit == 64);
		assert(!memcmp(&ip6->saddr, &outer_saddr, sizeof(outer_saddr)));
		assert(!memcmp(&ip6->daddr, &outer_daddr, sizeof(outer_daddr)));
	});

	TEST("outer_ipv6_traffic_class_is_ecn_only", {
		/* L1-10/L1-24: inner DSCP EF + ECT(1) is sent as ECT(1). */
		assert(ip6->priority == 0);
		assert((ip6->flow_lbl[0] >> 4) == GENEVE_ECN_ECT_1);
	});

	TEST("outer_ipv6_flow_label_zero", {
		/* The inner flow label is not copied, as on the kernel path. */
		assert(!(ip6->flow_lbl[0] & 0x0f));
		assert(!ip6->flow_lbl[1]);
		assert(!ip6->flow_lbl[2]);
	});

	TEST("outer_udp_zero_checksum", {
		/* B6: zero UDP checksum over IPv6, the documented deviation
		 * from the kernel path (RFC 8926 section 3.3).
		 */
		assert(udp->check == 0);
		assert(udp->source == bpf_htons(TEST_SPORT));
		assert(udp->dest == bpf_htons(6081));
		assert(udp->len == ip6->payload_len);
	});

	TEST("geneve_header", {
		assert(geneve->ver == 0);
		assert(geneve->opt_len == sizeof(dsr_opt6) / 4);
		assert(!geneve->control);
		assert(!geneve->critical);
		assert(geneve->protocol_type == bpf_htons(ETH_P_TEB));
		assert(geneve_hdr_vni(geneve) == TEST_VNI);
	});

	TEST("options_copied", {
		assert(packet_equals(ctx, ETH_HLEN + sizeof(struct geneve_encaphdr6),
				     &dsr_opt6, sizeof(dsr_opt6)));
	});

	TEST("inner_frame_follows_options", {
		assert(ctx_full_len(ctx) == INNER_V6_LEN + ENCAP6_ROOM);
		assert(packet_equals(ctx, ENCAP6_ROOM, pkt_before, INNER_V6_LEN));
	});

	test_finish();
}

/* U1: with any error other than DROP_GENEVE_ENCAP_FAILED the packet is left
 * unmodified, so that the caller can still hand it to the tunnel device.
 * That includes failures of bpf_skb_adjust_room().
 */
PKTGEN("tc", "geneve_encap_error_unmodified")
int geneve_encap_error_unmodified_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv4(ctx, 0);
}

static __always_inline bool packet_unmodified(const struct __ctx_buff *ctx)
{
	return ctx_full_len(ctx) == INNER_V4_LEN &&
	       packet_equals(ctx, 0, pkt_before, INNER_V4_LEN);
}

CHECK("tc", "geneve_encap_error_unmodified")
int geneve_encap_error_unmodified_check(struct __ctx_buff *ctx)
{
	const union v6addr outer_saddr = { .addr = v6_node_one_addr };
	const union v6addr outer_daddr = { .addr = v6_node_two_addr };
	const __u8 *opt = (const __u8 *)opts;

	test_init();

	if (ctx_full_len(ctx) != INNER_V4_LEN ||
	    ctx_load_bytes(ctx, 0, pkt_before, INNER_V4_LEN) < 0)
		test_fatal("unexpected inner packet");

	TEST("encap4_opt_len_over_max", {
		mock_reset();
		assert(geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				     bpf_htons(TEST_SPORT), opt,
				     GENEVE_OPT_MAX_LEN + 4) == DROP_INVALID);
		assert(adjust_room_calls == 0);
		assert(packet_unmodified(ctx));
	});

	TEST("encap4_opt_len_not_multiple_of_4", {
		mock_reset();
		assert(geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				     bpf_htons(TEST_SPORT), opt, 6) == DROP_INVALID);
		assert(adjust_room_calls == 0);
		assert(packet_unmodified(ctx));
	});

	TEST("encap4_adjust_room_failure", {
		mock_reset();
		adjust_room_ret = -ENOTSUPP;
		assert(geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				     bpf_htons(TEST_SPORT), NULL, 0) == DROP_INVALID);
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)(sizeof(struct geneve_encaphdr4) + ETH_HLEN));
		assert(adjust_room_flags == ENCAP_FLAGS_ETH(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4));
		assert(packet_unmodified(ctx));
	});

	TEST("encap6_opt_len_over_max", {
		mock_reset();
		assert(geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI,
				     bpf_htons(TEST_SPORT), opt,
				     GENEVE_OPT_MAX_LEN + 4) == DROP_INVALID);
		assert(adjust_room_calls == 0);
		assert(packet_unmodified(ctx));
	});

	TEST("encap6_opt_len_not_multiple_of_4", {
		mock_reset();
		assert(geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI,
				     bpf_htons(TEST_SPORT), opt, 6) == DROP_INVALID);
		assert(adjust_room_calls == 0);
		assert(packet_unmodified(ctx));
	});

	TEST("encap6_adjust_room_failure", {
		mock_reset();
		adjust_room_ret = -ENOTSUPP;
		assert(geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI,
				     bpf_htons(TEST_SPORT), NULL, 0) == DROP_INVALID);
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)(sizeof(struct geneve_encaphdr6) + ETH_HLEN));
		assert(adjust_room_flags == ENCAP_FLAGS_ETH(BPF_F_ADJ_ROOM_ENCAP_L3_IPV6));
		assert(packet_unmodified(ctx));
	});

	test_finish();
}

/* Offset of the option area in an IPv4 Geneve packet. */
#define OPTS_OFF	(ETH_HLEN + sizeof(struct geneve_encaphdr4))
#define OPTS_WORDS	64

/* Option bytes to store, the packet's option area after the store, and the
 * option bytes loaded back.
 */
static __u32 opts_src[OPTS_WORDS];
static __u32 opts_stored[OPTS_WORDS];
static __u32 opts_loaded[OPTS_WORDS];
static __u32 opts_zero[OPTS_WORDS];

PKTGEN("tc", "geneve_opts_load_store")
int geneve_opts_load_store_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	/* Room up to the end of a 256 byte option area, never parsed. */
	if (!pktgen__push_data_room(&builder, OPTS_OFF - ETH_HLEN + sizeof(opts_stored)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* geneve_store_opts() / geneve_load_opts() copy option areas of every
 * valid length through the packet, in power-of-two chunks, without touching
 * the bytes behind them.
 */
CHECK("tc", "geneve_opts_load_store")
int geneve_opts_load_store_check(struct __ctx_buff *ctx)
{
	__u32 len, i, diff;

	test_init();

	for (i = 0; i < OPTS_WORDS; i++)
		opts_src[i] = 0x01010101 * (i + 1);

	TEST("roundtrip_every_length", {
		for (len = 4; len <= GENEVE_OPT_MAX_LEN; len += 4) {
			if (ctx_store_bytes(ctx, OPTS_OFF, opts_zero, sizeof(opts_zero), 0) < 0 ||
			    geneve_store_opts(ctx, OPTS_OFF, (const __u8 *)opts_src, len) < 0 ||
			    ctx_load_bytes(ctx, OPTS_OFF, opts_stored, sizeof(opts_stored)) < 0) {
				test_error("storing %u bytes failed", len);
				break;
			}

			for (i = 0; i < OPTS_WORDS; i++)
				opts_loaded[i] = 0xa5a5a5a5;
			if (geneve_load_opts(ctx, OPTS_OFF, (__u8 *)opts_loaded, len) < 0) {
				test_error("loading %u bytes failed", len);
				break;
			}

			diff = 0;
			for (i = 0; i < OPTS_WORDS; i++) {
				if (i < len / 4)
					diff |= (opts_stored[i] ^ opts_src[i]) |
						(opts_loaded[i] ^ opts_src[i]);
				else
					diff |= opts_stored[i] | (opts_loaded[i] ^ 0xa5a5a5a5);
			}
			if (diff) {
				test_error("%u bytes do not round-trip", len);
				break;
			}
		}
	});

	test_finish();
}
