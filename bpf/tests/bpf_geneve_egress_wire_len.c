// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* geneve_wire_len() for GSO packets of various shapes (L1-18): the outer
 * length of the largest segment is derived from the real inner L3 and L4
 * header lengths, and packets with other L4 protocols are accounted with
 * their full length. Checked on the function and on the length the FIB
 * lookup of the native egress pipeline is done with.
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

#define UPLINK_IFINDEX		10
#define SRC_IP			v4_pod_one
#define DST_IP			v4_pod_two
#define TUNNEL_DST_V4		v4_node_two
#define TEST_SECLABEL		0x1122

#define GSO_SIZE		16
/* Outer IPv4, UDP and Geneve headers plus the inner Ethernet header. */
#define ENCAP_ROOM		(sizeof(struct geneve_encaphdr4) + ETH_HLEN)
/* A TCP header with 12 bytes of options (doff 8). */
#define TCP_OPT_HDR_LEN		32
#define IPV6_HOP_LEN		8
#define ICMP_PKT_LEN		(ETH_HLEN + sizeof(struct iphdr) + \
				 sizeof(struct icmphdr) + sizeof(default_data))

static __u32 mock_gso_size;

static __always_inline __u32
mock_ctx_gso_size(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_gso_size;
}

#undef ctx_gso_size
#define ctx_gso_size mock_ctx_gso_size

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

static __u32 redirect_neigh_calls;

static __always_inline int
mock_redirect_neigh(int ifindex __maybe_unused,
		    struct bpf_redir_neigh *params __maybe_unused,
		    int plen __maybe_unused, __u32 flags __maybe_unused)
{
	redirect_neigh_calls++;
	return CTX_ACT_REDIRECT;
}

#undef redirect_neigh
#define redirect_neigh mock_redirect_neigh

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_one })

static __u32 wire_len;

/* Unit: geneve_wire_len() as tail_geneve_encap4 calls it, for a GSO packet. */
static __always_inline int
wire_len_of_gso_packet(struct __ctx_buff *ctx)
{
	mock_gso_size = GSO_SIZE;
	wire_len = geneve_wire_len(ctx, geneve_encap_room(sizeof(struct geneve_encaphdr4),
							  0));
	mock_gso_size = 0;
	return 0;
}

/* Integration: the GSO packet through __encap_and_redirect_with_nodeid ->
 * tail_geneve_to_overlay -> tail_handle_nat_fwd_ipv4/6 ->
 * tail_handle_snat_fwd_ipv4/6 -> tail_geneve_encap4.
 */
static __always_inline int
send_gso_packet(struct __ctx_buff *ctx, __be16 proto)
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
	redirect_neigh_calls = 0;
	mock_gso_size = GSO_SIZE;

	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, proto);
}

/* The packet was encapsulated natively, after a FIB lookup with @len. */
#define check_fib_tot_len(ctx, len)					\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
									\
	mock_gso_size = 0;						\
	if (__data + sizeof(__u32) > __data_end)			\
		test_fatal("status code out of bounds");		\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(redirect_neigh_calls == 1);				\
	assert(fib_calls == 1);						\
	assert(recorded_fib_tot_len == (len));				\
} while (0)

/* L1-18: IPv4 TCP with options (doff 8): the segments carry 32 bytes of
 * TCP header, not 20.
 */
static __always_inline int
build_tcp_options_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct iphdr *l3;
	void *data;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      SRC_IP, DST_IP);
	if (!l3)
		return TEST_ERROR;

	l4 = pktgen__push_rawhdr(&builder, TCP_OPT_HDR_LEN, PKT_LAYER_TCP);
	if (!l4)
		return TEST_ERROR;
	if ((void *)l4 + TCP_OPT_HDR_LEN > ctx_data_end(ctx))
		return TEST_ERROR;
	/* Options: all End of Option List. */
	__bpf_memzero(l4, TCP_OPT_HDR_LEN);
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "geneve_wire_len_tcp_options")
int geneve_wire_len_tcp_options_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp_options_packet(ctx);
}

SETUP("tc", "geneve_wire_len_tcp_options")
int geneve_wire_len_tcp_options_setup(struct __ctx_buff *ctx)
{
	return wire_len_of_gso_packet(ctx);
}

CHECK("tc", "geneve_wire_len_tcp_options")
int geneve_wire_len_tcp_options_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(wire_len == ENCAP_ROOM + sizeof(struct iphdr) + TCP_OPT_HDR_LEN +
			   GSO_SIZE);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_wire_len_tcp_options")
int geneve_pipeline_wire_len_tcp_options_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp_options_packet(ctx);
}

SETUP("tc", "geneve_pipeline_wire_len_tcp_options")
int geneve_pipeline_wire_len_tcp_options_setup(struct __ctx_buff *ctx)
{
	return send_gso_packet(ctx, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_wire_len_tcp_options")
int geneve_pipeline_wire_len_tcp_options_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fib_tot_len(ctx, ENCAP_ROOM + sizeof(struct iphdr) +
			  TCP_OPT_HDR_LEN + GSO_SIZE);

	test_finish();
}

/* L1-18: IPv4 UDP (GSO_UDP_L4): 8 bytes of L4 header per segment. */
static __always_inline int
build_udp_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
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

PKTGEN("tc", "geneve_wire_len_udp")
int geneve_wire_len_udp_pktgen(struct __ctx_buff *ctx)
{
	return build_udp_packet(ctx);
}

SETUP("tc", "geneve_wire_len_udp")
int geneve_wire_len_udp_setup(struct __ctx_buff *ctx)
{
	return wire_len_of_gso_packet(ctx);
}

CHECK("tc", "geneve_wire_len_udp")
int geneve_wire_len_udp_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(wire_len == ENCAP_ROOM + sizeof(struct iphdr) +
			   sizeof(struct udphdr) + GSO_SIZE);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_wire_len_udp")
int geneve_pipeline_wire_len_udp_pktgen(struct __ctx_buff *ctx)
{
	return build_udp_packet(ctx);
}

SETUP("tc", "geneve_pipeline_wire_len_udp")
int geneve_pipeline_wire_len_udp_setup(struct __ctx_buff *ctx)
{
	return send_gso_packet(ctx, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_wire_len_udp")
int geneve_pipeline_wire_len_udp_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fib_tot_len(ctx, ENCAP_ROOM + sizeof(struct iphdr) +
			  sizeof(struct udphdr) + GSO_SIZE);

	test_finish();
}

/* L1-18: IPv6 with a Hop-by-Hop Options header before TCP: the L3 header
 * length includes the extension header.
 */
static __always_inline int
build_ipv6_ext_hdr_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6_opt_hdr *hop;
	struct ipv6hdr *l3;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)v6_pod_one, (__u8 *)v6_pod_two);
	if (!l3)
		return TEST_ERROR;

	hop = pktgen__append_ipv6_extension_header(&builder, NEXTHDR_HOP, 0);
	if (!hop)
		return TEST_ERROR;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "geneve_wire_len_ipv6_ext_hdr")
int geneve_wire_len_ipv6_ext_hdr_pktgen(struct __ctx_buff *ctx)
{
	return build_ipv6_ext_hdr_packet(ctx);
}

SETUP("tc", "geneve_wire_len_ipv6_ext_hdr")
int geneve_wire_len_ipv6_ext_hdr_setup(struct __ctx_buff *ctx)
{
	return wire_len_of_gso_packet(ctx);
}

CHECK("tc", "geneve_wire_len_ipv6_ext_hdr")
int geneve_wire_len_ipv6_ext_hdr_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(wire_len == ENCAP_ROOM + sizeof(struct ipv6hdr) + IPV6_HOP_LEN +
			   sizeof(struct tcphdr) + GSO_SIZE);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_wire_len_ipv6_ext_hdr")
int geneve_pipeline_wire_len_ipv6_ext_hdr_pktgen(struct __ctx_buff *ctx)
{
	return build_ipv6_ext_hdr_packet(ctx);
}

SETUP("tc", "geneve_pipeline_wire_len_ipv6_ext_hdr")
int geneve_pipeline_wire_len_ipv6_ext_hdr_setup(struct __ctx_buff *ctx)
{
	return send_gso_packet(ctx, bpf_htons(ETH_P_IPV6));
}

CHECK("tc", "geneve_pipeline_wire_len_ipv6_ext_hdr")
int geneve_pipeline_wire_len_ipv6_ext_hdr_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fib_tot_len(ctx, ENCAP_ROOM + sizeof(struct ipv6hdr) +
			  IPV6_HOP_LEN + sizeof(struct tcphdr) + GSO_SIZE);

	test_finish();
}

/* L1-18: other L4 protocols (here ICMP with a gso_size): the full length. */
static __always_inline int
build_icmp_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct icmphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_icmp_packet(&builder,
					   (__u8 *)mac_one, (__u8 *)mac_two,
					   SRC_IP, DST_IP, ICMP_ECHO);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "geneve_wire_len_icmp")
int geneve_wire_len_icmp_pktgen(struct __ctx_buff *ctx)
{
	return build_icmp_packet(ctx);
}

SETUP("tc", "geneve_wire_len_icmp")
int geneve_wire_len_icmp_setup(struct __ctx_buff *ctx)
{
	return wire_len_of_gso_packet(ctx);
}

CHECK("tc", "geneve_wire_len_icmp")
int geneve_wire_len_icmp_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(wire_len == ENCAP_ROOM + ICMP_PKT_LEN - ETH_HLEN);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_wire_len_icmp")
int geneve_pipeline_wire_len_icmp_pktgen(struct __ctx_buff *ctx)
{
	return build_icmp_packet(ctx);
}

SETUP("tc", "geneve_pipeline_wire_len_icmp")
int geneve_pipeline_wire_len_icmp_setup(struct __ctx_buff *ctx)
{
	return send_gso_packet(ctx, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_wire_len_icmp")
int geneve_pipeline_wire_len_icmp_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fib_tot_len(ctx, ENCAP_ROOM + ICMP_PKT_LEN - ETH_HLEN);

	test_finish();
}
