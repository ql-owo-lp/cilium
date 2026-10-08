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
#define GENEVE_INNER_PROTOCOL	2 /* GENEVE_INNER_PROTO_IP */
#define IS_BPF_HOST		1

static __u64 recorded_decap_flags;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	if (len_diff < 0) {
		recorded_decap_flags = flags;
		flags &= ~BPF_F_ADJ_ROOM_DECAP_L4_UDP;
	}
	return skb_adjust_room(skb, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

#include "lib/common.h"
#include "lib/geneve.h"
#include "lib/geneve_encap.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TEST_VNI	0x654321
#define TEST_SPORT	53535

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))
#define INNER_LEN_V6	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static union v6addr observed_saddr;
static union v6addr observed_daddr;
static __be16 observed_protocol;

PKTGEN("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };

	return geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			     bpf_htons(TEST_SPORT), NULL, 0);
}

CHECK("tc", "geneve_encap_v6")
int bpf_geneve_encap_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_node_one_addr };
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct iphdr *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u16 expected_udp_len;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("outer ip6 out of bounds");

	expected_udp_len = (__u16)(INNER_LEN_V4 - ETH_HLEN +
				   sizeof(struct geneve_encaphdr6) -
				   sizeof(struct ipv6hdr));

	assert(ip6->version == 6);
	assert(ip6->priority == 0);
	assert(ip6->flow_lbl[0] == 0);
	assert(ip6->flow_lbl[1] == 0);
	assert(ip6->flow_lbl[2] == 0);
	assert(ip6->nexthdr == IPPROTO_UDP);
	assert(ip6->hop_limit == IPDEFTTL);
	assert(ip6->payload_len == bpf_htons(expected_udp_len));
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));

	udp = (void *)ip6 + sizeof(*ip6);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("outer udp out of bounds");

	assert(udp->source == bpf_htons(TEST_SPORT));
	assert(udp->dest == bpf_htons(6081));
	assert(udp->len == bpf_htons(expected_udp_len));
	assert(udp->check == 0);

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");

	assert(geneve->ver == GENEVE_VERSION);
	assert(geneve->opt_len == 0);
	assert(geneve->control == 0);
	assert(geneve->critical == 0);
	assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
	assert(geneve_hdr_vni(geneve) == TEST_VNI);

	/* Inner IPv4 header immediately follows Geneve header in ip mode. */
	inner_ip4 = (void *)(geneve + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->saddr == SRC_IP);
	assert(inner_ip4->daddr == DST_IP);

	assert((__u64)((void *)data_end - (void *)eth) ==
	       INNER_LEN_V4 + sizeof(struct geneve_encaphdr6));

	test_finish();
}

PKTGEN("tc", "geneve_encap_v6_inner_v6")
int bpf_geneve_encap_v6_inner_v6_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_encap_v6_inner_v6")
int bpf_geneve_encap_v6_inner_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };

	return geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			     bpf_htons(TEST_SPORT), NULL, 0);
}

CHECK("tc", "geneve_encap_v6_inner_v6")
int bpf_geneve_encap_v6_inner_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_inner_src = { .addr = v6_pod_one_addr };
	const union v6addr expected_inner_dst = { .addr = v6_pod_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6, *inner_ip6;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u16 expected_udp_len;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	ip6 = (void *)eth + sizeof(*eth);
	if ((void *)ip6 + sizeof(*ip6) > data_end)
		test_fatal("outer ip6 out of bounds");

	expected_udp_len = (__u16)(INNER_LEN_V6 - ETH_HLEN +
				   sizeof(struct geneve_encaphdr6) -
				   sizeof(struct ipv6hdr));
	assert(ip6->payload_len == bpf_htons(expected_udp_len));

	udp = (void *)ip6 + sizeof(*ip6);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("outer udp out of bounds");
	assert(udp->len == bpf_htons(expected_udp_len));
	assert(udp->check == 0);

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");
	assert(geneve->protocol_type == bpf_htons(ETH_P_IPV6));

	inner_ip6 = (void *)(geneve + 1);
	if ((void *)(inner_ip6 + 1) > data_end)
		test_fatal("inner ip6 out of bounds");
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->saddr, &expected_inner_src));
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->daddr, &expected_inner_dst));

	test_finish();
}

PKTGEN("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v6_pktgen(ctx);
}

SETUP("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	const union v6addr svc_addr = { .addr = v6_svc_one_addr };
	struct geneve_dsr_opt6 dsr_opt = {};
	const struct geneve_metadata *meta;
	int ret;

	recorded_decap_flags = 0;
	observed_magic = 0;
	observed_vni = 0;
	observed_family = 0;
	observed_opt_len = 0;

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
		observed_saddr = meta->ip6.saddr;
		observed_daddr = meta->ip6.daddr;
	}
	return 0;
}

CHECK("tc", "geneve_encap_decap_v6_ip_mode")
int bpf_geneve_encap_decap_v6_ip_mode_check(const struct __ctx_buff *ctx)
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
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) != 0);
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
	assert(ipv6_addr_equals(&observed_saddr, &expected_src));
	assert(ipv6_addr_equals(&observed_daddr, &expected_dst));

	test_finish();
}
