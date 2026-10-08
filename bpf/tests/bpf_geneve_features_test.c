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

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC_V4	v4_node_one
#define TUNNEL_DST_V4	v4_node_two
#define TEST_VNI	0x345678
#define TEST_SPORT	50000

static struct geneve_opt_hdr max_63_tlvs[63];
static __u8 observed_63_opt_len;
static bool find_63_found_first;
static bool find_63_found_mid;
static bool find_63_found_last;
static bool find_63_found_missing;

static int tlv_err_overflow_ret;
static __u32 tlv_err_overflow_magic;
static int tlv_err_unk_crit_class_ret;
static int tlv_err_unk_crit_type_ret;
static int tlv_ok_known_crit_dsr_ret;
static __u32 tlv_ok_known_crit_dsr_magic;
static int tlv_ok_unk_noncrit_ret;

static int hdr_err_ver_ret;
static int hdr_err_oam_ret;
static int hdr_err_udplen_ret;
static int hdr_err_csum_ret;

static __u8 ecn_encap4_outer_tos;
static __sum16 ecn_encap4_outer_csum;
static __u8 ecn_decap4_ce_inner_tos;
static __sum16 ecn_decap4_ce_inner_csum;
static __u8 ecn_decap4_ect1_inner_tos;
static __sum16 ecn_decap4_ect1_inner_csum;
static int ecn_decap4_not_ect_drop_ret;
static __u8 ecn_encap6_outer_tc;
static __u8 ecn_decap6_ce_inner_tc;

static __u16 sport_v4_flow1;
static __u16 sport_v4_expected1;
static __u16 sport_v4_flow2;

static __always_inline int
build_inner_v4_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  SRC_IP, DST_IP,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* 1. 63-TLV (252-byte max) roundtrip + geneve_find_opt boundary scan */
PKTGEN("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_packet(ctx);
}

SETUP("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_setup(struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta;
	int ret;

	for (int i = 0; i < 63; i++) {
		__bpf_memzero(&max_63_tlvs[i], sizeof(max_63_tlvs[i]));
		max_63_tlvs[i].opt_class = bpf_htons((__u16)(0x0200 + i));
		max_63_tlvs[i].type = (__u8)(i + 1);
		max_63_tlvs[i].length = 0;
	}

	observed_63_opt_len = 0;
	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)max_63_tlvs,
			    sizeof(max_63_tlvs));
	if (ret < 0)
		return ret;

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta)
		return TEST_ERROR;
	observed_63_opt_len = meta->opt_len;

	find_63_found_first = geneve_find_opt(meta->raw_opts, meta->opt_len,
					      bpf_htons(0x0200), 1,
					      sizeof(struct geneve_opt_hdr)) != NULL;
	find_63_found_mid = geneve_find_opt(meta->raw_opts, meta->opt_len,
					    bpf_htons(0x0200 + 31), 32,
					    sizeof(struct geneve_opt_hdr)) != NULL;
	find_63_found_last = geneve_find_opt(meta->raw_opts, meta->opt_len,
					     bpf_htons(0x0200 + 62), 63,
					     sizeof(struct geneve_opt_hdr)) != NULL;
	find_63_found_missing = geneve_find_opt(meta->raw_opts, meta->opt_len,
						bpf_htons(0x0299), 99,
						sizeof(struct geneve_opt_hdr)) != NULL;
	return 0;
}

CHECK("tc", "geneve_63_tlv_max_roundtrip")
int bpf_geneve_63_tlv_max_roundtrip_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(observed_63_opt_len == GENEVE_OPT_MAX_LEN);
	assert(find_63_found_first);
	assert(find_63_found_mid);
	assert(find_63_found_last);
	assert(!find_63_found_missing);

	test_finish();
}

/* 2. Geneve TLV length validation & RFC 8926 critical bit enforcement */
PKTGEN("tc", "geneve_tlv_validation_and_critical_bit")
int bpf_geneve_tlv_validation_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_packet(ctx);
}

SETUP("tc", "geneve_tlv_validation_and_critical_bit")
int bpf_geneve_tlv_validation_setup(struct __ctx_buff *ctx)
{
	struct {
		struct geneve_opt_hdr unk_hdr;
		__be32 unk_val;
		struct geneve_dsr_opt4 dsr;
	} __packed blob = {
		.unk_hdr = {
			.opt_class = bpf_htons(0x9999),
			.type = 0x01,
			.length = 1,
		},
		.unk_val = bpf_htonl(0x11223344),
		.dsr = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = DSR_IPV4_GENEVE_OPT_LEN,
			},
			.addr = v4_svc_one,
			.port = tcp_svc_one,
		},
	};
	const __u32 opt0_off = ETH_HLEN + sizeof(struct geneve_encaphdr4);
	const __u32 opt1_off = opt0_off + sizeof(struct geneve_opt_hdr) + sizeof(__be32);
	const struct geneve_metadata *meta;
	struct geneve_opt_hdr hdr;
	int ret;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&blob, sizeof(blob));
	if (ret < 0)
		return ret;

	/* (a) Malformed TLV length overflowing opt_len -> DROP_GENEVE_OPT_INVALID */
	hdr = blob.unk_hdr;
	hdr.length = 10; /* 40B > 20B opt_len */
	if (ctx_store_bytes(ctx, opt0_off, &hdr, sizeof(hdr), 0) < 0)
		return TEST_ERROR;

	tlv_err_overflow_ret = geneve_decap4(ctx);
	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	tlv_err_overflow_magic = meta ? meta->magic : 0xffff;

	/* (b) Unknown critical option class -> DROP_GENEVE_OPT_INVALID */
	hdr = blob.unk_hdr;
	hdr.type = GENEVE_OPT_TYPE_CRIT | 0x01;
	if (ctx_store_bytes(ctx, opt0_off, &hdr, sizeof(hdr), 0) < 0)
		return TEST_ERROR;
	tlv_err_unk_crit_class_ret = geneve_decap4(ctx);

	/* Restore TLV 0 to valid non-critical unknown option */
	hdr = blob.unk_hdr;
	if (ctx_store_bytes(ctx, opt0_off, &hdr, sizeof(hdr), 0) < 0)
		return TEST_ERROR;

	/* (c) Known DSR option class, unknown critical option type (D9) -> DROP */
	hdr = blob.dsr.hdr;
	hdr.type = GENEVE_OPT_TYPE_CRIT | 0x77;
	if (ctx_store_bytes(ctx, opt1_off, &hdr, sizeof(hdr), 0) < 0)
		return TEST_ERROR;
	tlv_err_unk_crit_type_ret = geneve_decap4(ctx);

	/* (d) Restore TLV 1 to known critical DSR_GENEVE_OPT_TYPE (with unknown
	 * non-critical TLV 0 still present) -> accepted by geneve_decap4().
	 */
	hdr = blob.dsr.hdr;
	if (ctx_store_bytes(ctx, opt1_off, &hdr, sizeof(hdr), 0) < 0)
		return TEST_ERROR;
	tlv_ok_unk_noncrit_ret = 0;
	tlv_ok_known_crit_dsr_ret = geneve_decap4(ctx);
	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	tlv_ok_known_crit_dsr_magic = meta ? meta->magic : 0;

	return 0;
}

CHECK("tc", "geneve_tlv_validation_and_critical_bit")
int bpf_geneve_tlv_validation_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(tlv_err_overflow_ret == DROP_GENEVE_OPT_INVALID);
	assert(tlv_err_overflow_magic == 0);
	assert(tlv_err_unk_crit_class_ret == DROP_GENEVE_OPT_INVALID);
	assert(tlv_err_unk_crit_type_ret == DROP_GENEVE_OPT_INVALID);
	assert(tlv_ok_unk_noncrit_ret == 0);
	assert(tlv_ok_known_crit_dsr_ret == 0);
	assert(tlv_ok_known_crit_dsr_magic == GENEVE_META_MAGIC);

	test_finish();
}

/* 3. Geneve header & outer IPv4 checksum validation */
PKTGEN("tc", "geneve_hdr_validation")
int bpf_geneve_hdr_validation_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_packet(ctx);
}

SETUP("tc", "geneve_hdr_validation")
int bpf_geneve_hdr_validation_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__be16 saved_udp_len;
	__sum16 saved_csum;
	int ret;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	/* (a) Bad Geneve version */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	geneve = data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;
	geneve->ver = 1;
	hdr_err_ver_ret = geneve_decap4(ctx);

	/* (b) OAM control frame */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	geneve = data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;
	geneve->ver = GENEVE_VERSION;
	geneve->control = 1;
	hdr_err_oam_ret = geneve_decap4(ctx);

	/* (c) Truncated udp->len */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	udp = data + ETH_HLEN + sizeof(struct iphdr);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;
	geneve->control = 0;
	saved_udp_len = udp->len;
	udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct genevehdr) - 1);
	hdr_err_udplen_ret = geneve_decap4(ctx);

	/* (d) Corrupted outer IPv4 header checksum */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + ETH_HLEN;
	udp = (void *)(ip4 + 1);
	if ((void *)(udp + 1) > data_end)
		return TEST_ERROR;
	udp->len = saved_udp_len;
	saved_csum = ip4->check;
	ip4->check ^= 0xffff;
	hdr_err_csum_ret = geneve_decap4(ctx);

	/* Restore valid checksum and decapsulate cleanly */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + ETH_HLEN;
	if ((void *)(ip4 + 1) > data_end)
		return TEST_ERROR;
	ip4->check = saved_csum;
	return geneve_decap4(ctx);
}

CHECK("tc", "geneve_hdr_validation")
int bpf_geneve_hdr_validation_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(hdr_err_ver_ret == DROP_GENEVE_HDR_INVALID);
	assert(hdr_err_oam_ret == DROP_GENEVE_HDR_INVALID);
	assert(hdr_err_udplen_ret == DROP_GENEVE_HDR_INVALID);
	assert(hdr_err_csum_ret == DROP_CSUM_L3);

	test_finish();
}

/* 4. RFC 6040 ECN propagation on encap and decap (IPv4 and IPv6) */
PKTGEN("tc", "geneve_rfc6040_ecn_encap_and_decap")
int bpf_geneve_rfc6040_ecn_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_packet(ctx);
}

SETUP("tc", "geneve_rfc6040_ecn_encap_and_decap")
int bpf_geneve_rfc6040_ecn_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4, *inner_ip4;
	int ret;

	/* Set inner IPv4 TOS = DSCP EF (0xb8) | GENEVE_ECN_CE (0x03) */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	inner_ip4 = data + ETH_HLEN;
	if ((void *)(inner_ip4 + 1) > data_end)
		return TEST_ERROR;
	inner_ip4->tos = 0xb8 | GENEVE_ECN_CE;
	inner_ip4->check = 0;
	inner_ip4->check = geneve_ipv4_csum(inner_ip4);

	/* Encap4: outer TOS must be ECN-only (DSCP cleared) and CE mapped to ECT(0) */
	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + ETH_HLEN;
	inner_ip4 = data + ETH_HLEN + sizeof(struct geneve_encaphdr4) + ETH_HLEN;
	if ((void *)(inner_ip4 + 1) > data_end)
		return TEST_ERROR;

	ecn_encap4_outer_tos = ip4->tos;
	ecn_encap4_outer_csum = geneve_ipv4_csum(ip4);

	/* Set inner to DSCP EF | ECT(0), outer to CE, and decap -> inner becomes CE */
	inner_ip4->tos = 0xb8 | GENEVE_ECN_ECT_0;
	inner_ip4->check = 0;
	inner_ip4->check = geneve_ipv4_csum(inner_ip4);
	ip4->tos = GENEVE_ECN_CE;
	ip4->check = 0;
	ip4->check = geneve_ipv4_csum(ip4);

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	inner_ip4 = data + ETH_HLEN;
	if ((void *)(inner_ip4 + 1) > data_end)
		return TEST_ERROR;
	ecn_decap4_ce_inner_tos = inner_ip4->tos;
	ecn_decap4_ce_inner_csum = geneve_ipv4_csum(inner_ip4);

	/* Set inner to DSCP EF | ECT(0) and run geneve_decap_ecn(ECT(1)) -> inner becomes ECT(1) */
	inner_ip4->tos = 0xb8 | GENEVE_ECN_ECT_0;
	inner_ip4->check = 0;
	inner_ip4->check = geneve_ipv4_csum(inner_ip4);
	if (geneve_decap_ecn(ctx, GENEVE_ECN_ECT_1, bpf_htons(ETH_P_IP)) < 0)
		return TEST_ERROR;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	inner_ip4 = data + ETH_HLEN;
	if ((void *)(inner_ip4 + 1) > data_end)
		return TEST_ERROR;
	ecn_decap4_ect1_inner_tos = inner_ip4->tos;
	ecn_decap4_ect1_inner_csum = geneve_ipv4_csum(inner_ip4);

	/* Outer CE + inner Not-ECT -> RFC 6040 §4.2 drop (DROP_INVALID) */
	inner_ip4->tos = 0xb8 | GENEVE_ECN_NOT_ECT;
	inner_ip4->check = 0;
	inner_ip4->check = geneve_ipv4_csum(inner_ip4);
	ecn_decap4_not_ect_drop_ret = geneve_decap_ecn(ctx, GENEVE_ECN_CE,
						       bpf_htons(ETH_P_IP));
	return 0;
}

CHECK("tc", "geneve_rfc6040_ecn_encap_and_decap")
int bpf_geneve_rfc6040_ecn_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(ecn_encap4_outer_tos == GENEVE_ECN_ECT_0);
	assert(ecn_encap4_outer_csum == 0);
	assert(ecn_decap4_ce_inner_tos == (0xb8 | GENEVE_ECN_CE));
	assert(ecn_decap4_ce_inner_csum == 0);
	assert(ecn_decap4_ect1_inner_tos == (0xb8 | GENEVE_ECN_ECT_1));
	assert(ecn_decap4_ect1_inner_csum == 0);
	assert(ecn_decap4_not_ect_drop_ret == DROP_INVALID);

	test_finish();
}

PKTGEN("tc", "geneve_rfc6040_ecn_ipv6")
int bpf_geneve_rfc6040_ecn_ipv6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
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

SETUP("tc", "geneve_rfc6040_ecn_ipv6")
int bpf_geneve_rfc6040_ecn_ipv6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ipv6hdr *ip6, *inner_ip6;
	int ret;

	/* Set inner IPv6 traffic class = DSCP 0x20 | GENEVE_ECN_CE */
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	inner_ip6 = data + ETH_HLEN;
	if ((void *)(inner_ip6 + 1) > data_end)
		return TEST_ERROR;
	inner_ip6->priority = 0x2;
	inner_ip6->flow_lbl[0] = (inner_ip6->flow_lbl[0] & 0x0f) | (GENEVE_ECN_CE << 4);

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	ip6 = data + ETH_HLEN;
	inner_ip6 = data + ETH_HLEN + sizeof(struct geneve_encaphdr6) + ETH_HLEN;
	if ((void *)(inner_ip6 + 1) > data_end)
		return TEST_ERROR;

	ecn_encap6_outer_tc = (__u8)((ip6->priority << 4) | (ip6->flow_lbl[0] >> 4));

	/* Set inner to ECT(0), outer to CE -> decap propagates CE into inner IPv6 */
	inner_ip6->flow_lbl[0] = (inner_ip6->flow_lbl[0] & 0x0f) | (GENEVE_ECN_ECT_0 << 4);
	ip6->flow_lbl[0] = (ip6->flow_lbl[0] & 0x0f) | (GENEVE_ECN_CE << 4);

	ret = geneve_decap6(ctx);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	inner_ip6 = data + ETH_HLEN;
	if ((void *)(inner_ip6 + 1) > data_end)
		return TEST_ERROR;
	ecn_decap6_ce_inner_tc = (__u8)((inner_ip6->priority << 4) |
					(inner_ip6->flow_lbl[0] >> 4));
	return 0;
}

CHECK("tc", "geneve_rfc6040_ecn_ipv6")
int bpf_geneve_rfc6040_ecn_ipv6_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(ecn_encap6_outer_tc == GENEVE_ECN_ECT_0);
	assert(ecn_decap6_ce_inner_tc == (0x20 | GENEVE_ECN_CE));

	test_finish();
}

/* 5. Source port hashing & range formula (geneve_src_port) */
PKTGEN("tc", "geneve_src_port_range_and_formula")
int bpf_geneve_src_port_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_packet(ctx);
}

SETUP("tc", "geneve_src_port_range_and_formula")
int bpf_geneve_src_port_setup(struct __ctx_buff *ctx __maybe_unused)
{
	__u32 hash1 = 0x12345678u;
	__u32 folded1 = hash1 ^ (hash1 << 16);
	__u32 hash2 = 0x87654321u;

	sport_v4_expected1 = (__u16)((((__u64)folded1 * (65535 - 1)) >> 32) + 1);
	sport_v4_flow1 = bpf_ntohs(geneve_src_port(hash1));
	sport_v4_flow2 = bpf_ntohs(geneve_src_port(hash2));

	return 0;
}

CHECK("tc", "geneve_src_port_range_and_formula")
int bpf_geneve_src_port_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(sport_v4_flow1 == sport_v4_expected1);
	assert(sport_v4_flow1 >= 1);
	assert(sport_v4_flow2 >= 1);
	assert(sport_v4_flow1 != sport_v4_flow2);

	test_finish();
}
