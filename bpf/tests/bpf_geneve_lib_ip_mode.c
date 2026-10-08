// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Unit tests for the native BPF Geneve library (lib/geneve.h) in ip mode:
 * the inner Ethernet header is omitted and the Geneve protocol type carries
 * the inner ethertype. Only lib/geneve.h and the headers it depends on are
 * included, not the datapath integration.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_BPF_GENEVE	1
#define GENEVE_INNER_PROTOCOL	2 /* GENEVE_INNER_PROTO_IP */

/* get_prandom_u32() returns a fixed sequence, prandom_calls counts the calls
 * and prandom_last is the value returned last.
 */
static __u32 prandom_calls;
static __u32 prandom_last;

static __always_inline __u32 mock_get_prandom_u32(void)
{
	prandom_calls++;
	prandom_last += 0x13572468;
	return prandom_last;
}

#define get_prandom_u32 mock_get_prandom_u32

/* bpf_skb_adjust_room() records its arguments. */
static __u32 adjust_room_calls;
static __s32 adjust_room_len_diff;
static __u32 adjust_room_mode;
static __u64 adjust_room_flags;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *ctx, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	adjust_room_calls++;
	adjust_room_len_diff = len_diff;
	adjust_room_mode = mode;
	adjust_room_flags = flags;
	return skb_adjust_room(ctx, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

#include "lib/common.h"
#include "lib/geneve.h"

ASSIGN_CONFIG(__u16, tunnel_port, 6081)

#define TEST_VNI	0xabcdef
#define TEST_SPORT	50000
/* DSCP EF in the upper six bits of the IPv4 TOS / IPv6 traffic class. */
#define TOS_DSCP_EF	0xb8

#define INNER_V4_LEN	(ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + \
			 sizeof(default_data))
#define INNER_V6_LEN	(ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + \
			 sizeof(default_data))
#define ARP_LEN		(ETH_HLEN + sizeof(struct arphdreth))

/* A non-critical option of another vendor with one data word. */
struct test_opt {
	struct geneve_opt_hdr hdr;
	__be32 data;
};

/* Bytes that the encapsulation with a struct test_opt option inserts. */
#define ENCAP4_ROOM	(sizeof(struct geneve_encaphdr4) + sizeof(struct test_opt))
#define ENCAP6_ROOM	(sizeof(struct geneve_encaphdr6) + sizeof(struct test_opt))

/* bpf_skb_adjust_room() flags of an ip mode encapsulation: no
 * BPF_F_ADJ_ROOM_ENCAP_L2* bits, as there is no inner Ethernet header.
 */
#define ENCAP_FLAGS_IP(l3_flag)						\
	(BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET |	\
	 BPF_F_ADJ_ROOM_ENCAP_L4_UDP | (l3_flag))

static struct test_opt test_opt;

/* Copy of the packet, or of its L3 part, before the operation under test,
 * and scratch space for packet_equals().
 */
static __u64 pkt_before[16];
static __u64 pkt_scratch[16];

static __always_inline void mock_reset(void)
{
	prandom_calls = 0;
	adjust_room_calls = 0;
	adjust_room_len_diff = 0;
	adjust_room_mode = 0;
	adjust_room_flags = 0;
}

static __always_inline void test_opt_init(void)
{
	test_opt.hdr.opt_class = bpf_htons(0x0102);
	test_opt.hdr.type = 0x01;
	test_opt.hdr.rsvd = 0;
	test_opt.hdr.length = 1;
	test_opt.data = bpf_htonl(0x01020304);
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

/* IPv6 TCP packet with traffic class @tclass. */
static __always_inline int build_inner_ipv6(struct __ctx_buff *ctx, __u8 tclass)
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
	l3->flow_lbl[0] = (__u8)(tclass << 4);

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

/* geneve_encap_room(): ip mode inserts no inner Ethernet header. */
CHECK("tc", "geneve_encap_room_ip_mode")
int geneve_encap_room_ip_mode_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("excludes_inner_eth", {
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr4), 0) == 36);
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr4), 8) == 44);
		assert(geneve_encap_room(sizeof(struct geneve_encaphdr6), GENEVE_OPT_MAX_LEN) ==
		       56 + GENEVE_OPT_MAX_LEN);
	});

	test_finish();
}

/* geneve_encap4() in ip mode, with an IPv6 packet inside and an option. */
PKTGEN("tc", "geneve_encap4_ip_mode")
int geneve_encap4_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv6(ctx, TOS_DSCP_EF | GENEVE_ECN_ECT_1);
}

CHECK("tc", "geneve_encap4_ip_mode")
int geneve_encap4_ip_mode_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct genevehdr *geneve;
	struct udphdr *udp;
	struct iphdr *ip4;
	struct ethhdr *eth;
	int ret;

	test_init();

	mock_reset();
	test_opt_init();
	if (ctx_full_len(ctx) != INNER_V6_LEN ||
	    ctx_load_bytes(ctx, ETH_HLEN, pkt_before, INNER_V6_LEN - ETH_HLEN) < 0)
		test_fatal("unexpected inner packet");

	ret = geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI, bpf_htons(TEST_SPORT),
			    (const __u8 *)&test_opt, sizeof(test_opt));
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

	TEST("adjust_room_without_l2", {
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)ENCAP4_ROOM);
		assert(adjust_room_mode == BPF_ADJ_ROOM_MAC);
		assert(adjust_room_flags == ENCAP_FLAGS_IP(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4));
	});

	TEST("outer_eth_copies_inner", {
		assert(!memcmp(eth->h_dest, (__u8 *)mac_two, ETH_ALEN));
		assert(!memcmp(eth->h_source, (__u8 *)mac_one, ETH_ALEN));
		assert(eth->h_proto == bpf_htons(ETH_P_IP));
	});

	TEST("outer_ipv4", {
		assert(ip4->version == 4);
		assert(ip4->ihl == 5);
		assert(ip4->tot_len == bpf_htons(INNER_V6_LEN - ETH_HLEN + ENCAP4_ROOM));
		assert(ip4->ttl == 64);
		assert(ip4->protocol == IPPROTO_UDP);
		assert(ip4->saddr == v4_node_one);
		assert(ip4->daddr == v4_node_two);
		assert(!csum_fold(csum_diff(NULL, 0, ip4, sizeof(*ip4), 0)));
	});

	TEST("outer_ipv4_df_set", {
		/* U3d: DF set in ip mode, unlike in Ethernet mode. */
		assert(ip4->frag_off == bpf_htons(IP_DF));
	});

	TEST("outer_ipv4_fresh_id", {
		/* D31: a random ID in ip mode as well. */
		assert(prandom_calls == 1);
		assert(ip4->id == bpf_htons((__u16)prandom_last));
	});

	TEST("outer_ipv4_tos_is_ecn_only", {
		/* L1-10/L1-24: inner traffic class DSCP EF + ECT(1) is sent as
		 * ECT(1).
		 */
		assert(ip4->tos == GENEVE_ECN_ECT_1);
	});

	TEST("outer_udp", {
		assert(udp->source == bpf_htons(TEST_SPORT));
		assert(udp->dest == bpf_htons(6081));
		assert(udp->len == bpf_htons(INNER_V6_LEN - ETH_HLEN + ENCAP4_ROOM -
					     sizeof(struct iphdr)));
		assert(udp->check == 0);
	});

	TEST("geneve_protocol_is_inner_ethertype", {
		assert(geneve->ver == 0);
		assert(geneve->opt_len == sizeof(test_opt) / 4);
		assert(!geneve->control);
		assert(!geneve->critical);
		assert(geneve->protocol_type == bpf_htons(ETH_P_IPV6));
		assert(geneve_hdr_vni(geneve) == TEST_VNI);
	});

	TEST("options_copied", {
		assert(packet_equals(ctx, ETH_HLEN + sizeof(struct geneve_encaphdr4),
				     &test_opt, sizeof(test_opt)));
	});

	TEST("inner_l3_follows_options", {
		/* No inner Ethernet header between the option and the inner
		 * IPv6 header.
		 */
		assert(ctx_full_len(ctx) == INNER_V6_LEN + ENCAP4_ROOM);
		assert(packet_equals(ctx, ETH_HLEN + ENCAP4_ROOM, pkt_before,
				     INNER_V6_LEN - ETH_HLEN));
	});

	test_finish();
}

/* geneve_encap6() in ip mode, with an IPv4 packet inside and an option. */
PKTGEN("tc", "geneve_encap6_ip_mode")
int geneve_encap6_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_ipv4(ctx, TOS_DSCP_EF | GENEVE_ECN_CE);
}

CHECK("tc", "geneve_encap6_ip_mode")
int geneve_encap6_ip_mode_check(struct __ctx_buff *ctx)
{
	const union v6addr outer_saddr = { .addr = v6_node_one_addr };
	const union v6addr outer_daddr = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct genevehdr *geneve;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct ethhdr *eth;
	int ret;

	test_init();

	mock_reset();
	test_opt_init();
	if (ctx_full_len(ctx) != INNER_V4_LEN ||
	    ctx_load_bytes(ctx, ETH_HLEN, pkt_before, INNER_V4_LEN - ETH_HLEN) < 0)
		test_fatal("unexpected inner packet");

	ret = geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI, bpf_htons(TEST_SPORT),
			    (const __u8 *)&test_opt, sizeof(test_opt));
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

	TEST("adjust_room_without_l2", {
		assert(adjust_room_calls == 1);
		assert(adjust_room_len_diff == (__s32)ENCAP6_ROOM);
		assert(adjust_room_mode == BPF_ADJ_ROOM_MAC);
		assert(adjust_room_flags == ENCAP_FLAGS_IP(BPF_F_ADJ_ROOM_ENCAP_L3_IPV6));
	});

	TEST("outer_eth_copies_inner", {
		assert(!memcmp(eth->h_dest, (__u8 *)mac_two, ETH_ALEN));
		assert(!memcmp(eth->h_source, (__u8 *)mac_one, ETH_ALEN));
		assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	});

	TEST("outer_ipv6", {
		assert(ip6->version == 6);
		assert(ip6->payload_len == bpf_htons(INNER_V4_LEN - ETH_HLEN + ENCAP6_ROOM -
						     sizeof(struct ipv6hdr)));
		assert(ip6->nexthdr == IPPROTO_UDP);
		assert(ip6->hop_limit == 64);
		assert(!memcmp(&ip6->saddr, &outer_saddr, sizeof(outer_saddr)));
		assert(!memcmp(&ip6->daddr, &outer_daddr, sizeof(outer_daddr)));
	});

	TEST("outer_ipv6_traffic_class_is_ecn_only", {
		/* L1-10/L1-24: inner TOS DSCP EF + CE is sent as ECT(0). */
		assert(ip6->priority == 0);
		assert((ip6->flow_lbl[0] >> 4) == GENEVE_ECN_ECT_0);
	});

	TEST("outer_udp", {
		/* B6: zero UDP checksum over IPv6 in ip mode as well. */
		assert(udp->source == bpf_htons(TEST_SPORT));
		assert(udp->dest == bpf_htons(6081));
		assert(udp->len == ip6->payload_len);
		assert(udp->check == 0);
	});

	TEST("geneve_protocol_is_inner_ethertype", {
		assert(geneve->ver == 0);
		assert(geneve->opt_len == sizeof(test_opt) / 4);
		assert(!geneve->control);
		assert(!geneve->critical);
		assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
		assert(geneve_hdr_vni(geneve) == TEST_VNI);
	});

	TEST("options_copied", {
		assert(packet_equals(ctx, ETH_HLEN + sizeof(struct geneve_encaphdr6),
				     &test_opt, sizeof(test_opt)));
	});

	TEST("inner_l3_follows_options", {
		/* No inner Ethernet header between the option and the inner
		 * IPv4 header.
		 */
		assert(ctx_full_len(ctx) == INNER_V4_LEN + ENCAP6_ROOM);
		assert(packet_equals(ctx, ETH_HLEN + ENCAP6_ROOM, pkt_before,
				     INNER_V4_LEN - ETH_HLEN));
	});

	test_finish();
}

/* ip mode only carries IPv4 and IPv6. Other packets, here ARP, are rejected
 * with DROP_UNKNOWN_L3 before the packet is modified (U1: the caller can
 * still pass it on).
 */
PKTGEN("tc", "geneve_encap_ip_mode_non_ip")
int geneve_encap_ip_mode_non_ip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)mac_one, (__u8 *)mac_two);

	if (!pktgen__push_default_arphdr_ethernet(&builder))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline bool arp_unmodified(const struct __ctx_buff *ctx)
{
	return ctx_full_len(ctx) == ARP_LEN &&
	       packet_equals(ctx, 0, pkt_before, ARP_LEN);
}

CHECK("tc", "geneve_encap_ip_mode_non_ip")
int geneve_encap_ip_mode_non_ip_check(struct __ctx_buff *ctx)
{
	const union v6addr outer_saddr = { .addr = v6_node_one_addr };
	const union v6addr outer_daddr = { .addr = v6_node_two_addr };
	const struct ethhdr *eth_before = (const struct ethhdr *)pkt_before;

	test_init();

	if (ctx_full_len(ctx) != ARP_LEN ||
	    ctx_load_bytes(ctx, 0, pkt_before, ARP_LEN) < 0 ||
	    eth_before->h_proto != bpf_htons(ETH_P_ARP))
		test_fatal("unexpected ARP packet");

	TEST("encap4_rejects_non_ip", {
		mock_reset();
		assert(geneve_encap4(ctx, v4_node_one, v4_node_two, TEST_VNI,
				     bpf_htons(TEST_SPORT), NULL, 0) == DROP_UNKNOWN_L3);
		assert(adjust_room_calls == 0);
		assert(arp_unmodified(ctx));
	});

	TEST("encap6_rejects_non_ip", {
		mock_reset();
		assert(geneve_encap6(ctx, &outer_saddr, &outer_daddr, TEST_VNI,
				     bpf_htons(TEST_SPORT), NULL, 0) == DROP_UNKNOWN_L3);
		assert(adjust_room_calls == 0);
		assert(arp_unmodified(ctx));
	});

	test_finish();
}
