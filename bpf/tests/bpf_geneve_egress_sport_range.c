// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native Geneve egress with --tunnel-source-port-range: the outer UDP source
 * port is taken from the configured range (L1-09), like the kernel geneve
 * device created with that range does.
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

#define SPORT_LOW		32768
#define SPORT_HIGH		61000

static __u32 recorded_hash;

/* The skb hash the program sees, which geneve_flow_hash() is based on. */
static __always_inline int
mock_get_hash_recalc(struct __sk_buff *skb)
{
	recorded_hash = (__u32)get_hash_recalc(skb);
	return (int)recorded_hash;
}

#undef get_hash_recalc
#define get_hash_recalc mock_get_hash_recalc

static __u32 fib_calls;
static __be16 recorded_fib_sport;

static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_calls++;
	recorded_fib_sport = params->sport;

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
ASSIGN_CONFIG(__u16, tunnel_src_port_low, SPORT_LOW)
ASSIGN_CONFIG(__u16, tunnel_src_port_high, SPORT_HIGH)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_one })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_one_addr })

static __always_inline void
reset_test_state(void)
{
	recorded_hash = 0;
	fib_calls = 0;
	recorded_fib_sport = 0;
	redirect_neigh_calls = 0;
}

/* Enter the native egress pipeline like bpf_lxc does for a pod-to-pod
 * packet to a remote node with an IPv4 or IPv6 tunnel endpoint.
 */
static __always_inline int
enter_pipeline(struct __ctx_buff *ctx, bool ipv6_underlay)
{
	struct remote_endpoint_info ep = {
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	if (ipv6_underlay) {
		const union v6addr daddr = { .addr = v6_node_two_addr };

		ep.tunnel_endpoint.ip6.p1 = daddr.p1;
		ep.tunnel_endpoint.ip6.p2 = daddr.p2;
		ep.tunnel_endpoint.ip6.p3 = daddr.p3;
		ep.tunnel_endpoint.ip6.p4 = daddr.p4;
		ep.flag_ipv6_tunnel_ep = true;
	} else {
		ep.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4;
	}

	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

static __always_inline int
build_packet(struct __ctx_buff *ctx)
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

/* The source port on the wire is the one geneve_src_port() maps the skb
 * hash to, within [SPORT_LOW, SPORT_HIGH), and the FIB lookup was done with
 * it too.
 */
#define check_sport(udp)						\
do {									\
	__u16 __sport = bpf_ntohs((udp)->source);			\
									\
	assert(recorded_hash != 0);					\
	assert((udp)->source == geneve_src_port(recorded_hash));	\
	assert(__sport >= SPORT_LOW && __sport < SPORT_HIGH);		\
	assert(fib_calls == 1);						\
	assert(recorded_fib_sport == (udp)->source);			\
} while (0)

/* L1-09: tail_geneve_encap4's body, with a staged egress slot. */
PKTGEN("tc", "geneve_encap4_sport_range")
int geneve_encap4_sport_range_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap4_sport_range")
int geneve_encap4_sport_range_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	__s8 ext_err = 0;

	reset_test_state();
	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = TEST_SECLABEL;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.daddr = TUNNEL_DST_V4;
	ctx_bpf_geneve_encap_set(ctx);

	return geneve_handle_encap4(ctx, &ext_err);
}

CHECK("tc", "geneve_encap4_sport_range")
int geneve_encap4_sport_range_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	udp = data + sizeof(*status_code) + ETH_HLEN + sizeof(struct iphdr);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer udp out of bounds");

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	check_sport(udp);

	test_finish();
}

/* L1-09 through the pipeline: __encap_and_redirect_with_nodeid ->
 * tail_geneve_to_overlay -> tail_handle_nat_fwd_ipv4 ->
 * tail_handle_snat_fwd_ipv4 -> tail_geneve_encap4/6.
 */
PKTGEN("tc", "geneve_pipeline_v4_sport_range")
int geneve_pipeline_v4_sport_range_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v4_sport_range")
int geneve_pipeline_v4_sport_range_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, false);
}

CHECK("tc", "geneve_pipeline_v4_sport_range")
int geneve_pipeline_v4_sport_range_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	udp = data + sizeof(*status_code) + ETH_HLEN + sizeof(struct iphdr);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer udp out of bounds");

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(udp->dest == bpf_htons(6081));
	check_sport(udp);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v6_sport_range")
int geneve_pipeline_v6_sport_range_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v6_sport_range")
int geneve_pipeline_v6_sport_range_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, true);
}

CHECK("tc", "geneve_pipeline_v6_sport_range")
int geneve_pipeline_v6_sport_range_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	udp = data + sizeof(*status_code) + ETH_HLEN + sizeof(struct ipv6hdr);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer udp out of bounds");

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(udp->dest == bpf_htons(6081));
	check_sport(udp);

	test_finish();
}
