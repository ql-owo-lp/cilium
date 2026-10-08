// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native Geneve egress on a kernel with BPF_FIB_LOOKUP_SRC support: the
 * outer source address is the preferred source of the route (U2, L1-08).
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

/* The preferred source of the route and the direct routing address differ,
 * to tell which one ends up in the outer header.
 */
#define FIB_SRC_V4		v4_node_one
#define DIRECT_ROUTING_V4	v4_node_three

/* BPF_FIB_LKUP_RET_NO_SRC_ADDR, missing from the bundled UAPI header. */
#define FIB_LKUP_RET_NO_SRC_ADDR	(BPF_FIB_LKUP_RET_FRAG_NEEDED + 1)

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static const union v6addr fib_src_v6 = { .addr = v6_node_one_addr };

static bool mock_fib_no_src;
static __u32 fib_calls;
static __u32 recorded_fib_flags;
static __u32 recorded_fib_src;

/* bpf_fib_lookup() for a route with a preferred source, which is returned
 * with BPF_FIB_LOOKUP_SRC only. For a route without one (mock_fib_no_src),
 * the kernel returns a zero IPv4 source but fails IPv6 lookups with
 * BPF_FIB_LKUP_RET_NO_SRC_ADDR.
 */
static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags)
{
	fib_calls++;
	recorded_fib_flags = flags;
	recorded_fib_src = params->ipv6_src[0] | params->ipv6_src[1] |
			   params->ipv6_src[2] | params->ipv6_src[3];

	if (flags & BPF_FIB_LOOKUP_SRC) {
		if (params->family == AF_INET) {
			params->ipv4_src = mock_fib_no_src ? 0 : FIB_SRC_V4;
		} else if (mock_fib_no_src) {
			return FIB_LKUP_RET_NO_SRC_ADDR;
		} else {
			params->ipv6_src[0] = fib_src_v6.p1;
			params->ipv6_src[1] = fib_src_v6.p2;
			params->ipv6_src[2] = fib_src_v6.p3;
			params->ipv6_src[3] = fib_src_v6.p4;
		}
	}

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

static __always_inline int
mock_skb_set_tunnel_key(struct __sk_buff *skb __maybe_unused,
			const struct bpf_tunnel_key *from,
			__u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	__bpf_memcpy_builtin(&recorded_tunnel_key, from,
			     sizeof(recorded_tunnel_key));
	tunnel_key_set = true;
	return 0;
}

#undef skb_set_tunnel_key
#define skb_set_tunnel_key mock_skb_set_tunnel_key

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(bool, supports_fib_lookup_src, true)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = DIRECT_ROUTING_V4 })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_three_addr })

static int fib_lookup_ret;
static union v6addr fib_lookup_src;

static __always_inline void
reset_test_state(void)
{
	mock_fib_no_src = false;
	fib_calls = 0;
	recorded_fib_flags = 0;
	recorded_fib_src = ~0U;
	redirect_ifindex = 0;
	redirect_tc_index = 0;
	redirect_neigh_calls = 0;
	tunnel_key_set = false;
	__bpf_memzero(&recorded_tunnel_key, sizeof(recorded_tunnel_key));
}

static __always_inline bool
stage_egress_slot(int family)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	const union v6addr daddr = { .addr = v6_node_two_addr };

	if (!meta)
		return false;
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
	return true;
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

/* Native path: encapsulated and handed to redirect_neigh(). Returns the
 * outer IPv4 header, NULL after a failed assertion.
 */
#define check_native_v4(ctx)						\
({									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct iphdr *__ip4 = __data + sizeof(__u32) + ETH_HLEN;	\
									\
	if ((void *)(__ip4 + 1) > __data_end)				\
		test_fatal("outer ip4 out of bounds");			\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(redirect_neigh_calls == 1);				\
	assert(redirect_ifindex == UPLINK_IFINDEX);			\
	assert(!tunnel_key_set);					\
	assert(__ip4->protocol == IPPROTO_UDP);				\
	assert(__ip4->daddr == TUNNEL_DST_V4);				\
	assert(geneve_ipv4_csum(__ip4) == 0);				\
	__ip4;								\
})

#define check_native_v6(ctx)						\
({									\
	const union v6addr __daddr = { .addr = v6_node_two_addr };	\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct ipv6hdr *__ip6 = __data + sizeof(__u32) + ETH_HLEN;	\
									\
	if ((void *)(__ip6 + 1) > __data_end)				\
		test_fatal("outer ip6 out of bounds");			\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(redirect_neigh_calls == 1);				\
	assert(redirect_ifindex == UPLINK_IFINDEX);			\
	assert(!tunnel_key_set);					\
	assert(__ip6->nexthdr == IPPROTO_UDP);				\
	assert(ipv6_addr_equals((union v6addr *)&__ip6->daddr, &__daddr)); \
	__ip6;								\
})

/* U2: with BPF_FIB_LOOKUP_SRC support, geneve_fib_lookup() asks for the
 * preferred source of the route (and still passes none in).
 */
PKTGEN("tc", "geneve_fib_lookup_src_flag_v4")
int geneve_fib_lookup_src_flag_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_fib_lookup_src_flag_v4")
int geneve_fib_lookup_src_flag_v4_setup(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	__be32 daddr = TUNNEL_DST_V4;

	reset_test_state();
	fib_lookup_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET, &daddr,
					   tcp_src_two, 1400);
	fib_lookup_src.p1 = fib_params.l.ipv4_src;
	return 0;
}

CHECK("tc", "geneve_fib_lookup_src_flag_v4")
int geneve_fib_lookup_src_flag_v4_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(fib_lookup_ret == BPF_FIB_LKUP_RET_SUCCESS);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(recorded_fib_src == 0);
	assert(fib_lookup_src.p1 == FIB_SRC_V4);

	test_finish();
}

PKTGEN("tc", "geneve_fib_lookup_src_flag_v6")
int geneve_fib_lookup_src_flag_v6_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_fib_lookup_src_flag_v6")
int geneve_fib_lookup_src_flag_v6_setup(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	union v6addr daddr = { .addr = v6_node_two_addr };

	reset_test_state();
	fib_lookup_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET6, &daddr,
					   tcp_src_two, 1400);
	fib_lookup_src.p1 = fib_params.l.ipv6_src[0];
	fib_lookup_src.p2 = fib_params.l.ipv6_src[1];
	fib_lookup_src.p3 = fib_params.l.ipv6_src[2];
	fib_lookup_src.p4 = fib_params.l.ipv6_src[3];
	return 0;
}

CHECK("tc", "geneve_fib_lookup_src_flag_v6")
int geneve_fib_lookup_src_flag_v6_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(fib_lookup_ret == BPF_FIB_LKUP_RET_SUCCESS);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(recorded_fib_src == 0);
	assert(ipv6_addr_equals(&fib_lookup_src, &fib_src_v6));

	test_finish();
}

/* L1-08: geneve_handle_encap4/6() put the source returned by the FIB
 * lookup in the outer header, in preference to the direct routing address.
 */
PKTGEN("tc", "geneve_encap4_fib_saddr")
int geneve_encap4_fib_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap4_fib_saddr")
int geneve_encap4_fib_saddr_setup(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;

	reset_test_state();
	if (!stage_egress_slot(AF_INET))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	return geneve_handle_encap4(ctx, &ext_err);
}

CHECK("tc", "geneve_encap4_fib_saddr")
int geneve_encap4_fib_saddr_check(const struct __ctx_buff *ctx)
{
	struct iphdr *ip4;

	test_init();

	ip4 = check_native_v4(ctx);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(ip4->saddr == FIB_SRC_V4);

	test_finish();
}

PKTGEN("tc", "geneve_encap6_fib_saddr")
int geneve_encap6_fib_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap6_fib_saddr")
int geneve_encap6_fib_saddr_setup(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;

	reset_test_state();
	if (!stage_egress_slot(AF_INET6))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	return geneve_handle_encap6(ctx, &ext_err);
}

CHECK("tc", "geneve_encap6_fib_saddr")
int geneve_encap6_fib_saddr_check(const struct __ctx_buff *ctx)
{
	struct ipv6hdr *ip6;

	test_init();

	ip6 = check_native_v6(ctx);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &fib_src_v6));

	test_finish();
}

/* L1-08 through the pipeline: __encap_and_redirect_with_nodeid ->
 * tail_geneve_to_overlay -> tail_handle_nat_fwd_ipv4 ->
 * tail_handle_snat_fwd_ipv4 -> tail_geneve_encap4/6.
 */
PKTGEN("tc", "geneve_pipeline_v4_fib_saddr")
int geneve_pipeline_v4_fib_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v4_fib_saddr")
int geneve_pipeline_v4_fib_saddr_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, false);
}

CHECK("tc", "geneve_pipeline_v4_fib_saddr")
int geneve_pipeline_v4_fib_saddr_check(const struct __ctx_buff *ctx)
{
	struct iphdr *ip4;

	test_init();

	ip4 = check_native_v4(ctx);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(recorded_fib_src == 0);
	assert(ip4->saddr == FIB_SRC_V4);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v6_fib_saddr")
int geneve_pipeline_v6_fib_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v6_fib_saddr")
int geneve_pipeline_v6_fib_saddr_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	return enter_pipeline(ctx, true);
}

CHECK("tc", "geneve_pipeline_v6_fib_saddr")
int geneve_pipeline_v6_fib_saddr_check(const struct __ctx_buff *ctx)
{
	struct ipv6hdr *ip6;

	test_init();

	ip6 = check_native_v6(ctx);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(recorded_fib_src == 0);
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &fib_src_v6));

	test_finish();
}

/* L1-08: an IPv4 route without a preferred source yields 0, and the direct
 * routing address is used instead.
 */
PKTGEN("tc", "geneve_encap4_fib_no_saddr")
int geneve_encap4_fib_no_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap4_fib_no_saddr")
int geneve_encap4_fib_no_saddr_setup(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;

	reset_test_state();
	mock_fib_no_src = true;
	if (!stage_egress_slot(AF_INET))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	return geneve_handle_encap4(ctx, &ext_err);
}

CHECK("tc", "geneve_encap4_fib_no_saddr")
int geneve_encap4_fib_no_saddr_check(const struct __ctx_buff *ctx)
{
	struct iphdr *ip4;

	test_init();

	ip4 = check_native_v4(ctx);
	assert(ip4->saddr == DIRECT_ROUTING_V4);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v4_fib_no_saddr")
int geneve_pipeline_v4_fib_no_saddr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v4_fib_no_saddr")
int geneve_pipeline_v4_fib_no_saddr_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	mock_fib_no_src = true;
	return enter_pipeline(ctx, false);
}

CHECK("tc", "geneve_pipeline_v4_fib_no_saddr")
int geneve_pipeline_v4_fib_no_saddr_check(const struct __ctx_buff *ctx)
{
	struct iphdr *ip4;

	test_init();

	ip4 = check_native_v4(ctx);
	assert(recorded_fib_flags == BPF_FIB_LOOKUP_SRC);
	assert(ip4->saddr == DIRECT_ROUTING_V4);

	test_finish();
}

/* U1/L1-08: an IPv6 lookup failing with BPF_FIB_LKUP_RET_NO_SRC_ADDR hands
 * the unmodified packet to the kernel tunnel device, with the tunnel key.
 */
#define check_fallback_v6(ctx)						\
do {									\
	const union v6addr __daddr = { .addr = v6_node_two_addr };	\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct ethhdr *__eth = __data + sizeof(__u32);			\
									\
	if ((void *)(__eth + 1) > __data_end)				\
		test_fatal("inner eth out of bounds");			\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(fib_calls == 1);						\
	assert(redirect_neigh_calls == 0);				\
	assert(redirect_ifindex == ENCAP_IFINDEX);			\
	assert(redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK);	\
	assert(tunnel_key_set);						\
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);		\
	assert(recorded_tunnel_key.remote_ipv6[0] == __daddr.p1);	\
	assert(recorded_tunnel_key.remote_ipv6[1] == __daddr.p2);	\
	assert(recorded_tunnel_key.remote_ipv6[2] == __daddr.p3);	\
	assert(recorded_tunnel_key.remote_ipv6[3] == __daddr.p4);	\
	assert(__eth->h_proto == bpf_htons(ETH_P_IP));			\
	assert((void *)__eth + INNER_LEN_V4 == __data_end);		\
} while (0)

PKTGEN("tc", "geneve_encap6_fib_no_src_addr")
int geneve_encap6_fib_no_src_addr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_encap6_fib_no_src_addr")
int geneve_encap6_fib_no_src_addr_setup(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;

	reset_test_state();
	mock_fib_no_src = true;
	if (!stage_egress_slot(AF_INET6))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	return geneve_handle_encap6(ctx, &ext_err);
}

CHECK("tc", "geneve_encap6_fib_no_src_addr")
int geneve_encap6_fib_no_src_addr_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback_v6(ctx);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v6_fib_no_src_addr")
int geneve_pipeline_v6_fib_no_src_addr_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_pipeline_v6_fib_no_src_addr")
int geneve_pipeline_v6_fib_no_src_addr_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	mock_fib_no_src = true;
	return enter_pipeline(ctx, true);
}

CHECK("tc", "geneve_pipeline_v6_fib_no_src_addr")
int geneve_pipeline_v6_fib_no_src_addr_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_fallback_v6(ctx);

	test_finish();
}
