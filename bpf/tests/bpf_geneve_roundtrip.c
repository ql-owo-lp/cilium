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

static __u64 recorded_decap_flags;
static bool skip_encap_room_flags_once;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	if (len_diff < 0) {
		recorded_decap_flags = flags;
	} else if (skip_encap_room_flags_once) {
		skip_encap_room_flags_once = false;
		flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
	}
	return skb_adjust_room(skb, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

static __u32 mock_prandom_counter;

static __always_inline __u32
mock_get_prandom_u32(void)
{
	mock_prandom_counter += 0x13572468u;
	return mock_prandom_counter;
}

#undef get_prandom_u32
#define get_prandom_u32 mock_get_prandom_u32

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
#define TEST_VNI	0x234567
#define TEST_SPORT	49152

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))
#define INNER_LEN_V6	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __be16 encap_frag_off;
static __sum16 encap_csum;
static __u16 encap_tot_len;
static __u8 encap_ttl;
static __u16 encap_udp_len;
static __sum16 encap_udp_check;
static __be16 encap_proto_type;
static __be16 encap_inner_eth_proto;

static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static __be32 observed_saddr4;
static __be32 observed_daddr4;
static union v6addr observed_saddr6;
static union v6addr observed_daddr6;
static __be16 observed_protocol;

static __be16 first_ip_id;
static __be16 second_ip_id;
static __sum16 first_ip_csum;
static __sum16 second_ip_csum;

static bool multi_tlv_found[5];
static __be32 multi_tlv_val[4];
static __be32 multi_tlv_dsr_addr;
static __be16 multi_tlv_dsr_port;
static bool multi_tlv_missing_found;

PKTGEN("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_IPV4_GENEVE_OPT_LEN,
		},
		.addr = v4_svc_one,
		.port = tcp_svc_one,
	};
	const struct geneve_metadata *meta;
	void *data, *data_end;
	struct ethhdr *eth, *inner_eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	int ret;

	recorded_decap_flags = 0;
	observed_magic = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&dsr_opt,
			    sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	inner_eth = (void *)geneve + sizeof(*geneve) + sizeof(dsr_opt);
	if ((void *)(inner_eth + 1) > data_end)
		return TEST_ERROR;

	encap_frag_off = ip4->frag_off;
	encap_csum = geneve_ipv4_csum(ip4);
	encap_tot_len = bpf_ntohs(ip4->tot_len);
	encap_ttl = ip4->ttl;
	encap_udp_len = bpf_ntohs(udp->len);
	encap_udp_check = udp->check;
	encap_proto_type = geneve->protocol_type;
	encap_inner_eth_proto = inner_eth->h_proto;

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_saddr4 = meta->ip4.saddr;
		observed_daddr4 = meta->ip4.daddr;
	}
	return 0;
}

CHECK("tc", "geneve_roundtrip_v4")
int bpf_geneve_roundtrip_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;
	__u16 expected_udp_len;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	expected_udp_len = (__u16)(INNER_LEN_V4 + sizeof(struct udphdr) +
				   sizeof(struct genevehdr) +
				   sizeof(struct geneve_dsr_opt4));
	/* eth mode clears DF on outer IPv4 headers. */
	assert(encap_frag_off == 0);
	assert(encap_csum == 0);
	assert(encap_tot_len == expected_udp_len + sizeof(struct iphdr));
	assert(encap_ttl == IPDEFTTL);
	assert(encap_udp_len == expected_udp_len);
	assert(encap_udp_check == 0);
	assert(encap_proto_type == bpf_htons(ETH_P_TEB));
	assert(encap_inner_eth_proto == bpf_htons(ETH_P_IP));
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);
	assert(observed_family == AF_INET);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt4));
	assert(observed_saddr4 == TUNNEL_SRC_V4);
	assert(observed_daddr4 == TUNNEL_DST_V4);

	test_finish();
}

PKTGEN("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_roundtrip_v4_pktgen(ctx);
}

SETUP("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	const union v6addr svc_addr = { .addr = v6_svc_one_addr };
	struct geneve_dsr_opt6 dsr_opt = {};
	const struct geneve_metadata *meta;
	int ret;

	recorded_decap_flags = 0;
	observed_magic = 0;
	set_geneve_dsr_opt6(tcp_svc_one, &svc_addr, &dsr_opt);

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&dsr_opt,
			    sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	ret = geneve_decap6(ctx);
	if (ret < 0)
		return ret;

	observed_protocol = (__be16)ctx->protocol;
	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_saddr6 = meta->ip6.saddr;
		observed_daddr6 = meta->ip6.daddr;
	}
	return 0;
}

CHECK("tc", "geneve_roundtrip_v6")
int bpf_geneve_roundtrip_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_node_one_addr };
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) == 0);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV4) != 0);
	assert(observed_protocol == bpf_htons(ETH_P_IP));

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);
	assert(observed_family == AF_INET6);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt6));
	assert(ipv6_addr_equals(&observed_saddr6, &expected_src));
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));

	test_finish();
}

PKTGEN("tc", "geneve_roundtrip_v6_in_v4")
int bpf_geneve_roundtrip_v6_in_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_roundtrip_v6_in_v4")
int bpf_geneve_roundtrip_v6_in_v4_setup(struct __ctx_buff *ctx)
{
	int ret;

	recorded_decap_flags = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	observed_protocol = (__be16)ctx->protocol;
	return 0;
}

CHECK("tc", "geneve_roundtrip_v6_in_v4")
int bpf_geneve_roundtrip_v6_in_v4_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_pod_one_addr };
	const union v6addr expected_dst = { .addr = v6_pod_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) == 0);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV6) != 0);
	assert(observed_protocol == bpf_htons(ETH_P_IPV6));

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("inner ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert((void *)eth + INNER_LEN_V6 == data_end);

	test_finish();
}

/* Verify that geneve_encap4 sets a non-zero per-packet IPv4 ID in eth mode (DF=0)
 * and updates the outer IPv4 header checksum accordingly (D31).
 */
PKTGEN("tc", "geneve_ipv4_id_per_packet")
int bpf_geneve_ipv4_id_per_packet_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_roundtrip_v4_pktgen(ctx);
}

SETUP("tc", "geneve_ipv4_id_per_packet")
int bpf_geneve_ipv4_id_per_packet_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	int ret;

	mock_prandom_counter = 0x10002000u;
	first_ip_id = 0;
	second_ip_id = 0;
	first_ip_csum = 0xffff;
	second_ip_csum = 0xffff;
	skip_encap_room_flags_once = true;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		return TEST_ERROR;

	first_ip_id = ip4->id;
	first_ip_csum = geneve_ipv4_csum(ip4);

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		return TEST_ERROR;

	second_ip_id = ip4->id;
	second_ip_csum = geneve_ipv4_csum(ip4);
	return 0;
}

CHECK("tc", "geneve_ipv4_id_per_packet")
int bpf_geneve_ipv4_id_per_packet_check(const struct __ctx_buff *ctx)
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
	assert(first_ip_id != 0);
	assert(second_ip_id != 0);
	assert(first_ip_id != second_ip_id);
	assert(first_ip_csum == 0);
	assert(second_ip_csum == 0);

	test_finish();
}

struct custom_tlv4 {
	struct geneve_opt_hdr hdr;
	__be32 val;
};

struct multi_tlv_blob {
	struct custom_tlv4 tlv0;
	struct custom_tlv4 tlv1;
	struct geneve_dsr_opt4 dsr;
	struct custom_tlv4 tlv2;
	struct custom_tlv4 tlv3;
};

PKTGEN("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_roundtrip_v4_pktgen(ctx);
}

SETUP("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_setup(struct __ctx_buff *ctx)
{
	struct multi_tlv_blob blob = {
		.tlv0 = {
			.hdr = { .opt_class = bpf_htons(0x0101), .type = 1, .length = 1 },
			.val = bpf_htonl(0xaaaa0001),
		},
		.tlv1 = {
			.hdr = { .opt_class = bpf_htons(0x0102), .type = 2, .length = 1 },
			.val = bpf_htonl(0xbbbb0002),
		},
		.dsr = {
			.hdr = {
				.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
				.type = DSR_GENEVE_OPT_TYPE,
				.length = DSR_IPV4_GENEVE_OPT_LEN,
			},
			.addr = v4_svc_one,
			.port = tcp_svc_one,
		},
		.tlv2 = {
			.hdr = { .opt_class = bpf_htons(0x0103), .type = 3, .length = 1 },
			.val = bpf_htonl(0xcccc0003),
		},
		.tlv3 = {
			.hdr = { .opt_class = bpf_htons(0x0104), .type = 4, .length = 1 },
			.val = bpf_htonl(0xdddd0004),
		},
	};
	const struct geneve_metadata *meta;
	const struct custom_tlv4 *c;
	const struct geneve_dsr_opt4 *d;
	int ret;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&blob,
			    sizeof(blob));
	if (ret < 0)
		return ret;

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta || meta->opt_len != sizeof(blob))
		return TEST_ERROR;

	c = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(0x0101), 1, sizeof(*c));
	multi_tlv_found[0] = c != NULL;
	if (c)
		multi_tlv_val[0] = c->val;

	c = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(0x0102), 2, sizeof(*c));
	multi_tlv_found[1] = c != NULL;
	if (c)
		multi_tlv_val[1] = c->val;

	d = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(DSR_GENEVE_OPT_CLASS),
			    DSR_GENEVE_OPT_TYPE, sizeof(*d));
	multi_tlv_found[2] = d != NULL;
	if (d) {
		multi_tlv_dsr_addr = d->addr;
		multi_tlv_dsr_port = d->port;
	}

	c = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(0x0103), 3, sizeof(*c));
	multi_tlv_found[3] = c != NULL;
	if (c)
		multi_tlv_val[2] = c->val;

	c = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(0x0104), 4, sizeof(*c));
	multi_tlv_found[4] = c != NULL;
	if (c)
		multi_tlv_val[3] = c->val;

	c = geneve_find_opt(meta->raw_opts, meta->opt_len,
			    bpf_htons(0x9999), 9, sizeof(*c));
	multi_tlv_missing_found = c != NULL;
	return 0;
}

CHECK("tc", "geneve_multi_tlv_roundtrip")
int bpf_geneve_multi_tlv_roundtrip_check(const struct __ctx_buff *ctx)
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
	assert(multi_tlv_found[0]);
	assert(multi_tlv_found[1]);
	assert(multi_tlv_found[2]);
	assert(multi_tlv_found[3]);
	assert(multi_tlv_found[4]);
	assert(multi_tlv_val[0] == bpf_htonl(0xaaaa0001));
	assert(multi_tlv_val[1] == bpf_htonl(0xbbbb0002));
	assert(multi_tlv_dsr_addr == v4_svc_one);
	assert(multi_tlv_dsr_port == tcp_svc_one);
	assert(multi_tlv_val[2] == bpf_htonl(0xcccc0003));
	assert(multi_tlv_val[3] == bpf_htonl(0xdddd0004));
	assert(!multi_tlv_missing_found);

	test_finish();
}
