// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native Geneve egress without a usable outer source address: no
 * BPF_FIB_LOOKUP_SRC support and no direct routing address (L1-08). Such
 * packets take the kernel tunnel device (U1) instead of being dropped.
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

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 fib_calls;
static __u32 recorded_fib_flags;

/* bpf_fib_lookup() without BPF_FIB_LOOKUP_SRC: a route, no source address. */
static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags)
{
	fib_calls++;
	recorded_fib_flags = flags;

	params->ifindex = UPLINK_IFINDEX;
	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_three, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_four, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#undef fib_lookup
#define fib_lookup mock_fib_lookup

static __u32 redirect_ifindex;
static __u16 redirect_tc_index;
static __u32 redirect_neigh_calls;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx, int ifindex,
		  __u64 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_tc_index = (__u16)ctx->tc_index;
	return CTX_ACT_REDIRECT;
}

static __always_inline int
mock_redirect_neigh(int ifindex, struct bpf_redir_neigh *params __maybe_unused,
		    int plen __maybe_unused, __u32 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_neigh_calls++;
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect
#undef redirect_neigh
#define redirect_neigh mock_redirect_neigh

static bool tunnel_key_set;
static struct bpf_tunnel_key recorded_tunnel_key;
static __u32 recorded_tunnel_key_flags;

static __always_inline int
mock_skb_set_tunnel_key(struct __sk_buff *skb __maybe_unused,
			const struct bpf_tunnel_key *from,
			__u32 size __maybe_unused, __u32 flags)
{
	__bpf_memcpy_builtin(&recorded_tunnel_key, from,
			     sizeof(recorded_tunnel_key));
	recorded_tunnel_key_flags = flags;
	tunnel_key_set = true;
	return 0;
}

#undef skb_set_tunnel_key
#define skb_set_tunnel_key mock_skb_set_tunnel_key

#include "lib/bpf_overlay.h"

/* Neither supports_fib_lookup_src nor ipv4/ipv6_direct_routing are set. */
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

static __u32 observed_slot_magic;

static __always_inline void
reset_test_state(void)
{
	fib_calls = 0;
	recorded_fib_flags = ~0U;
	redirect_ifindex = 0;
	redirect_tc_index = 0;
	redirect_neigh_calls = 0;
	tunnel_key_set = false;
	__bpf_memzero(&recorded_tunnel_key, sizeof(recorded_tunnel_key));
	recorded_tunnel_key_flags = 0;
	observed_slot_magic = ~0U;
}

static __always_inline struct geneve_metadata *
stage_egress_slot(int family)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	const union v6addr daddr = { .addr = v6_node_two_addr };

	if (!meta)
		return NULL;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = TEST_SECLABEL;
	meta->family = (__u8)family;
	meta->opt_len = 0;
	if (family == AF_INET6) {
		meta->ip6.daddr.p1 = daddr.p1;
		meta->ip6.daddr.p2 = daddr.p2;
		meta->ip6.daddr.p3 = daddr.p3;
		meta->ip6.daddr.p4 = daddr.p4;
	} else {
		meta->ip4.daddr = TUNNEL_DST_V4;
	}
	return meta;
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

/* The route lookup succeeded, but without a source address the unmodified
 * packet goes to the kernel tunnel device with the tunnel key.
 */
#define check_fallback(ctx)						\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct ethhdr *__eth = __data + sizeof(__u32);			\
	struct iphdr *__ip4 = (void *)(__eth + 1);			\
									\
	if ((void *)(__ip4 + 1) > __data_end)				\
		test_fatal("inner ip4 out of bounds");			\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(fib_calls == 1);						\
	assert(recorded_fib_flags == 0);				\
	assert(redirect_neigh_calls == 0);				\
	assert(redirect_ifindex == ENCAP_IFINDEX);			\
	assert(redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK);	\
	assert(tunnel_key_set);						\
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);		\
	assert(__eth->h_proto == bpf_htons(ETH_P_IP));			\
	assert(__ip4->saddr == SRC_IP);					\
	assert(__ip4->daddr == DST_IP);					\
	assert((void *)__eth + INNER_LEN_V4 == __data_end);		\
} while (0)

#define check_tunnel_key_v6()						\
do {									\
	const union v6addr __daddr = { .addr = v6_node_two_addr };	\
									\
	assert(recorded_tunnel_key_flags == BPF_F_TUNINFO_IPV6);	\
	assert(recorded_tunnel_key.remote_ipv6[0] == __daddr.p1);	\
	assert(recorded_tunnel_key.remote_ipv6[1] == __daddr.p2);	\
	assert(recorded_tunnel_key.remote_ipv6[2] == __daddr.p3);	\
	assert(recorded_tunnel_key.remote_ipv6[3] == __daddr.p4);	\
} while (0)

/* L1-08/U1: geneve_handle_encap4/6() hand the packet to the tunnel device. */
PKTGEN("tc", "geneve_encap4_no_saddr_fallback")
int geneve_encap4_no_saddr_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap4_no_saddr_fallback")
int geneve_encap4_no_saddr_fallback_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot(AF_INET);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	ret = geneve_handle_encap4(ctx, &ext_err);
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap4_no_saddr_fallback")
int geneve_encap4_no_saddr_fallback_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback(ctx);
	assert(recorded_tunnel_key_flags == BPF_F_ZERO_CSUM_TX);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(observed_slot_magic == 0);

	test_finish();
}

PKTGEN("tc", "geneve_encap6_no_saddr_fallback")
int geneve_encap6_no_saddr_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap6_no_saddr_fallback")
int geneve_encap6_no_saddr_fallback_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot(AF_INET6);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	ret = geneve_handle_encap6(ctx, &ext_err);
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap6_no_saddr_fallback")
int geneve_encap6_no_saddr_fallback_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback(ctx);
	check_tunnel_key_v6();
	assert(observed_slot_magic == 0);

	test_finish();
}

/* L1-08/U1 through the pipeline: __encap_and_redirect_with_nodeid ->
 * tail_geneve_to_overlay -> tail_handle_nat_fwd_ipv4 ->
 * tail_handle_snat_fwd_ipv4 -> tail_geneve_encap4/6.
 */
PKTGEN("tc", "geneve_pipeline_v4_no_saddr_fallback")
int geneve_pipeline_v4_no_saddr_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v4_no_saddr_fallback")
int geneve_pipeline_v4_no_saddr_fallback_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, false);
}

CHECK("tc", "geneve_pipeline_v4_no_saddr_fallback")
int geneve_pipeline_v4_no_saddr_fallback_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback(ctx);
	assert(recorded_tunnel_key_flags == BPF_F_ZERO_CSUM_TX);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v6_no_saddr_fallback")
int geneve_pipeline_v6_no_saddr_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v6_no_saddr_fallback")
int geneve_pipeline_v6_no_saddr_fallback_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, true);
}

CHECK("tc", "geneve_pipeline_v6_no_saddr_fallback")
int geneve_pipeline_v6_no_saddr_fallback_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback(ctx);
	check_tunnel_key_v6();

	test_finish();
}
