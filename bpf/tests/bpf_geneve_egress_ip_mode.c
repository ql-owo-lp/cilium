// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native Geneve egress in ip mode (GENEVE_INNER_PROTO_IP) through the full
 * pipeline: the outer IPv4 header has DF set and a fresh ID (U1, D31), the
 * inner Ethernet header is omitted.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "lib/socket.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_NODEPORT		1
#define GENEVE_INNER_PROTOCOL	2 /* GENEVE_INNER_PROTO_IP */

#define UPLINK_IFINDEX		10
#define SRC_IP			v4_pod_one
#define DST_IP			v4_pod_two
#define TUNNEL_SRC_V4		v4_node_one
#define TUNNEL_DST_V4		v4_node_two
#define TEST_SECLABEL		0x1122

#define INNER_L3_LEN	(sizeof(struct iphdr) + sizeof(struct tcphdr) + \
			 sizeof(default_data))

static __u32 mock_prandom;

static __always_inline __u32 mock_get_prandom_u32(void)
{
	mock_prandom += 0x9e3779b9;
	return mock_prandom;
}

#undef get_prandom_u32
#define get_prandom_u32 mock_get_prandom_u32

static __u32 fib_calls;
static __u16 recorded_fib_tot_len;

static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_calls++;
	recorded_fib_tot_len = params->tot_len;

	params->ifindex = UPLINK_IFINDEX;
	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_three, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_four, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#undef fib_lookup
#define fib_lookup mock_fib_lookup

static __u32 redirect_ifindex;
static __u32 redirect_neigh_calls;

static __always_inline int
mock_redirect_neigh(int ifindex, struct bpf_redir_neigh *params __maybe_unused,
		    int plen __maybe_unused, __u32 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_neigh_calls++;
	return CTX_ACT_REDIRECT;
}

#undef redirect_neigh
#define redirect_neigh mock_redirect_neigh

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = TUNNEL_SRC_V4 })

static __be16 first_ip_id;

/* U1/D31: through the pipeline, DF set and an ID from get_prandom_u32(). */
PKTGEN("tc", "geneve_pipeline_v4_ip_mode")
int geneve_pipeline_v4_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
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

/* __encap_and_redirect_with_nodeid -> tail_geneve_to_overlay ->
 * tail_handle_nat_fwd_ipv4 -> tail_handle_snat_fwd_ipv4 ->
 * tail_geneve_encap4 -> redirect_neigh.
 */
SETUP("tc", "geneve_pipeline_v4_ip_mode")
int geneve_pipeline_v4_ip_mode_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	fib_calls = 0;
	recorded_fib_tot_len = 0;
	redirect_ifindex = 0;
	redirect_neigh_calls = 0;

	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v4_ip_mode")
int geneve_pipeline_v4_ip_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4, *inner_ip4;
	struct genevehdr *geneve;
	__u32 *status_code;
	struct ethhdr *eth;
	struct udphdr *udp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	/* No inner Ethernet header in the encapsulation. */
	assert(fib_calls == 1);
	assert(recorded_fib_tot_len ==
	       sizeof(struct geneve_encaphdr4) + INNER_L3_LEN);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	inner_ip4 = (void *)(geneve + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("encapsulated headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);
	/* U1: DF set in ip mode. D31: the ID comes from get_prandom_u32(). */
	assert(ip4->frag_off == bpf_htons(IP_DF));
	assert(ip4->id == bpf_htons((__u16)mock_prandom));
	assert(geneve_ipv4_csum(ip4) == 0);
	assert(udp->dest == bpf_htons(6081));
	assert(udp->len == bpf_htons(sizeof(*udp) + sizeof(*geneve) + INNER_L3_LEN));
	assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
	assert(geneve->opt_len == 0);
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);
	assert(inner_ip4->saddr == SRC_IP);
	assert(inner_ip4->daddr == DST_IP);
	assert((void *)inner_ip4 + INNER_L3_LEN == data_end);

	first_ip_id = ip4->id;

	test_finish();
}

/* D31: the next packet of the flow gets another ID (runs after
 * geneve_pipeline_v4_ip_mode, which records the first one).
 */
PKTGEN("tc", "geneve_pipeline_v4_ip_mode_second_packet")
int geneve_pipeline_v4_ip_mode_second_packet_pktgen(struct __ctx_buff *ctx)
{
	return geneve_pipeline_v4_ip_mode_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v4_ip_mode_second_packet")
int geneve_pipeline_v4_ip_mode_second_packet_setup(struct __ctx_buff *ctx)
{
	return geneve_pipeline_v4_ip_mode_setup(ctx);
}

CHECK("tc", "geneve_pipeline_v4_ip_mode_second_packet")
int geneve_pipeline_v4_ip_mode_second_packet_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct iphdr *ip4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	ip4 = (void *)status_code + sizeof(*status_code) + ETH_HLEN;
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(ip4->frag_off == bpf_htons(IP_DF));
	assert(ip4->id == bpf_htons((__u16)mock_prandom));
	assert(first_ip_id != 0);
	assert(ip4->id != first_ip_id);
	assert(geneve_ipv4_csum(ip4) == 0);

	test_finish();
}
