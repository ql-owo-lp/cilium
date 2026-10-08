// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

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
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_GENEVE	3
#define DSR_ENCAP_MODE		DSR_ENCAP_GENEVE

#define UPLINK_IFINDEX		10
#define SRC_MAC			mac_one
#define DST_MAC			mac_two
#define UPLINK_SMAC		mac_three
#define UPLINK_DMAC		mac_four
#define SRC_IP			v4_pod_one
#define DST_IP			v4_pod_two
#define TUNNEL_SRC_V4		v4_node_one
#define TUNNEL_DST_V4		v4_node_two
#define TEST_SECLABEL		0x1122

/* Kernel-path DSR request: client -> local backend, received on the tunnel
 * device. The payload looks like a Geneve packet with a DSR option.
 */
#define CLIENT_IP		v4_ext_one
#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		__bpf_htons(6081)

#define TEST_SPORT		__bpf_htons(49152)
#define TEST_WIRE_LEN		1400

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 mock_gso_size;

static __always_inline __u32
mock_ctx_gso_size(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_gso_size;
}

#undef ctx_gso_size
#define ctx_gso_size mock_ctx_gso_size

static int mock_encap_room_ret;

/* Makes bpf_skb_adjust_room() fail for the encapsulation, the only call that
 * grows the packet on these paths, without modifying the packet.
 */
static __always_inline int
mock_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	if (len_diff > 0 && mock_encap_room_ret)
		return mock_encap_room_ret;
	return skb_adjust_room(skb, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

static __u32 mock_prandom;

static __always_inline __u32 mock_get_prandom_u32(void)
{
	mock_prandom += 0x9e3779b9;
	return mock_prandom;
}

#undef get_prandom_u32
#define get_prandom_u32 mock_get_prandom_u32

static long mock_fib_ret;
static __u32 fib_calls;
static struct bpf_fib_lookup recorded_fib;
static __u32 recorded_fib_flags;
static __u32 recorded_fib_tc_index;

/* Records the lookup and answers like bpf_fib_lookup(): the egress device on
 * SUCCESS and NO_NEIGH, the MAC addresses on SUCCESS only, and the source
 * address only with BPF_FIB_LOOKUP_SRC, which is never passed here as
 * supports_fib_lookup_src is not set (see bpf_geneve_egress_fib_src.c).
 * The input is copied field by field: a copy of the whole structure would
 * exceed the stack limit of tail_nodeport_nat_egress_ipv6.
 */
static __always_inline long
mock_fib_lookup(const void *ctx, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags)
{
	fib_calls++;
	recorded_fib.family = params->family;
	recorded_fib.l4_protocol = params->l4_protocol;
	recorded_fib.sport = params->sport;
	recorded_fib.dport = params->dport;
	recorded_fib.tot_len = params->tot_len;
	recorded_fib.ipv6_src[0] = params->ipv6_src[0];
	recorded_fib.ipv6_src[1] = params->ipv6_src[1];
	recorded_fib.ipv6_src[2] = params->ipv6_src[2];
	recorded_fib.ipv6_src[3] = params->ipv6_src[3];
	recorded_fib.ipv6_dst[0] = params->ipv6_dst[0];
	recorded_fib.ipv6_dst[1] = params->ipv6_dst[1];
	recorded_fib.ipv6_dst[2] = params->ipv6_dst[2];
	recorded_fib.ipv6_dst[3] = params->ipv6_dst[3];
	recorded_fib_flags = flags;
	recorded_fib_tc_index = ((const struct __sk_buff *)ctx)->tc_index;

	if (mock_fib_ret != BPF_FIB_LKUP_RET_SUCCESS &&
	    mock_fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		return mock_fib_ret;

	params->ifindex = UPLINK_IFINDEX;
	if (mock_fib_ret == BPF_FIB_LKUP_RET_SUCCESS) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)UPLINK_SMAC, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)UPLINK_DMAC, ETH_ALEN);
	}
	return mock_fib_ret;
}

#undef fib_lookup
#define fib_lookup mock_fib_lookup

static __u32 redirect_ifindex;
static __u64 redirect_flags;
static __u16 redirect_tc_index;
static __u32 redirect_mark;
static __u32 redirect_neigh_calls;
static __u32 redirect_slot_magic;

static bool fallback_tunnel_key_set;
static struct bpf_tunnel_key recorded_tunnel_key;
static __u32 recorded_tunnel_key_flags;
static bool fallback_tunnel_opt_set;
static __u32 recorded_tunnel_opt_len;
static __u8 recorded_tunnel_opt[32];

static int mock_tunnel_opt_ret;
static struct geneve_dsr_opt4 mock_tunnel_opt;

static __always_inline int
mock_skb_set_tunnel_key(struct __sk_buff *skb __maybe_unused,
			const struct bpf_tunnel_key *from,
			__u32 size __maybe_unused, __u32 flags)
{
	if (from) {
		__bpf_memcpy_builtin(&recorded_tunnel_key, from,
				     sizeof(recorded_tunnel_key));
		recorded_tunnel_key_flags = flags;
		fallback_tunnel_key_set = true;
	}
	return 0;
}

static __always_inline int
mock_skb_get_tunnel_key(struct __sk_buff *skb __maybe_unused,
			struct bpf_tunnel_key *to,
			__u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	if (!fallback_tunnel_key_set || !to)
		return -ENOENT;
	__bpf_memcpy_builtin(to, &recorded_tunnel_key, sizeof(*to));
	return 0;
}

static __always_inline int
mock_skb_set_tunnel_opt(struct __sk_buff *skb __maybe_unused,
			const void *opt, __u32 opt_len)
{
	if (!opt || opt_len > sizeof(recorded_tunnel_opt))
		return -EINVAL;
	if (opt_len == sizeof(struct geneve_dsr_opt4)) {
		__bpf_memcpy_builtin(recorded_tunnel_opt, opt,
				     sizeof(struct geneve_dsr_opt4));
	} else if (opt_len == sizeof(struct geneve_dsr_opt6)) {
		__bpf_memcpy_builtin(recorded_tunnel_opt, opt,
				     sizeof(struct geneve_dsr_opt6));
	} else {
		return -EINVAL;
	}
	recorded_tunnel_opt_len = opt_len;
	fallback_tunnel_opt_set = true;
	return 0;
}

/* bpf_skb_get_tunnel_opt() for a packet from the kernel tunnel device:
 * returns mock_tunnel_opt_ret, with the option copied out or, on error,
 * @opt zeroed. Only the IPv4 DSR option is supported.
 */
static __always_inline int
mock_skb_get_tunnel_opt(struct __sk_buff *skb __maybe_unused, void *opt,
			__u32 size)
{
	if (size != sizeof(mock_tunnel_opt))
		return -EINVAL;
	if (mock_tunnel_opt_ret < 0)
		__bpf_memzero(opt, sizeof(mock_tunnel_opt));
	else
		__bpf_memcpy_builtin(opt, &mock_tunnel_opt, sizeof(mock_tunnel_opt));
	return mock_tunnel_opt_ret;
}

#undef skb_set_tunnel_key
#define skb_set_tunnel_key mock_skb_set_tunnel_key
#undef skb_get_tunnel_key
#define skb_get_tunnel_key mock_skb_get_tunnel_key
#undef skb_set_tunnel_opt
#define skb_set_tunnel_opt mock_skb_set_tunnel_opt
#undef skb_get_tunnel_opt
#define skb_get_tunnel_opt mock_skb_get_tunnel_opt

/* Defined below, once lib/bpf_overlay.h has provided the slot map. The
 * slots are per-CPU and so can only be observed while the program runs.
 */
static __always_inline __u32 egress_slot_magic(void);

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx, int ifindex, __u64 flags)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_flags = flags;
	redirect_tc_index = (__u16)ctx->tc_index;
	redirect_mark = ctx->mark;
	redirect_slot_magic = egress_slot_magic();
	return CTX_ACT_REDIRECT;
}

static __always_inline int
mock_redirect_neigh(int ifindex, struct bpf_redir_neigh *params __maybe_unused,
		    int plen __maybe_unused, __u32 flags)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_flags = flags;
	redirect_neigh_calls++;
	redirect_slot_magic = egress_slot_magic();
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect
#undef redirect_neigh
#define redirect_neigh mock_redirect_neigh

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
/* Without BPF_FIB_LOOKUP_SRC, the outer source is the direct routing address. */
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = TUNNEL_SRC_V4 })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_one_addr })

static __always_inline __u32 egress_slot_magic(void)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	return meta ? meta->magic : GENEVE_META_MAGIC;
}

static int opt_contract_ret_small;
static int opt_contract_ret_padded;
static __u8 opt_contract_buf[16];
static int opt_contract_ret_empty;

static __be16 first_ip_id;

static int fib_lookup_ret;
static __u16 observed_tc_index;
static __u32 observed_slot_magic;

static int exit_ret_no_magic;
static int exit_ret_bad_family;
static int exit_ret_redirect;
static int exit_ret_drop;

static int kernel_opt_absent_ret;
static struct geneve_dsr_opt4 kernel_opt_absent;
static int kernel_opt_ret;
static struct geneve_dsr_opt4 kernel_opt;

static __always_inline void
reset_test_state(void)
{
	mock_gso_size = 0;
	mock_encap_room_ret = 0;
	mock_fib_ret = BPF_FIB_LKUP_RET_SUCCESS;
	fib_calls = 0;
	__bpf_memzero(&recorded_fib, sizeof(recorded_fib));
	recorded_fib_flags = 0;
	recorded_fib_tc_index = 0;
	redirect_ifindex = 0;
	redirect_flags = 0;
	redirect_tc_index = 0;
	redirect_mark = 0;
	redirect_neigh_calls = 0;
	redirect_slot_magic = ~0U;
	fallback_tunnel_key_set = false;
	__bpf_memzero(&recorded_tunnel_key, sizeof(recorded_tunnel_key));
	recorded_tunnel_key_flags = 0;
	fallback_tunnel_opt_set = false;
	recorded_tunnel_opt_len = 0;
	__bpf_memzero(recorded_tunnel_opt, sizeof(recorded_tunnel_opt));
	mock_tunnel_opt_ret = -ENOENT;
	__bpf_memzero(&mock_tunnel_opt, sizeof(mock_tunnel_opt));
}

/* The egress slot as geneve_encap_and_redirect() stages it. */
static __always_inline struct geneve_metadata *
stage_egress_slot4(__u32 vni)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	if (!meta)
		return NULL;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = vni;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.daddr = TUNNEL_DST_V4;
	return meta;
}

static __always_inline struct geneve_metadata *
stage_egress_slot6(__u32 vni)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	const union v6addr daddr = { .addr = v6_node_two_addr };

	if (!meta)
		return NULL;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = vni;
	meta->family = AF_INET6;
	meta->opt_len = 0;
	meta->ip6.daddr = daddr;
	return meta;
}

/* 1. Full native egress pipeline (IPv4 underlay):
 * __encap_and_redirect_with_nodeid -> tail_geneve_to_overlay ->
 * tail_handle_nat_fwd_ipv4 -> tail_geneve_encap4 -> fib_lookup + geneve_encap4 + redirect
 */
PKTGEN("tc", "geneve_egress_pipeline_v4")
int bpf_geneve_egress_pipeline_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_egress_pipeline_v4")
int bpf_geneve_egress_pipeline_v4_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_egress_pipeline_v4")
int bpf_geneve_egress_pipeline_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u16 expected_tot_len;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Native path: redirect_neigh() to the FIB's device, no fallback. */
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(redirect_flags == 0);
	assert(!fallback_tunnel_key_set);
	/* B4: the markers are cleared and the slot is consumed before the
	 * packet leaves.
	 */
	assert((recorded_fib_tc_index & TC_INDEX_F_BPF_GENEVE_ENCAP) == 0);
	assert((recorded_fib_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) == 0);
	assert(redirect_slot_magic == 0);
	/* B2 */
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);

	/* Verify U2 FIB lookup 5-tuple parameters, without a source address
	 * and without flags as supports_fib_lookup_src is not set.
	 */
	expected_tot_len = (__u16)(INNER_LEN_V4 + sizeof(struct geneve_encaphdr4));
	assert(fib_calls == 1);
	assert(recorded_fib_flags == 0);
	assert(recorded_fib.family == AF_INET);
	assert(recorded_fib.l4_protocol == IPPROTO_UDP);
	assert(recorded_fib.dport == bpf_htons(6081));
	assert(recorded_fib.sport != 0);
	assert(recorded_fib.tot_len == expected_tot_len);
	assert(recorded_fib.ipv4_src == 0);
	assert(recorded_fib.ipv4_dst == TUNNEL_DST_V4);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	/* L1-08: the FIB returned no source, so the direct routing address. */
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);
	/* U1/D31: DF clear in Ethernet mode, a fresh ID per packet. */
	assert(ip4->frag_off == 0);
	assert(ip4->id == bpf_htons((__u16)mock_prandom));
	assert(geneve_ipv4_csum(ip4) == 0);
	assert(udp->source == recorded_fib.sport);
	assert(udp->dest == bpf_htons(6081));
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);

	first_ip_id = ip4->id;

	test_finish();
}

/* D31: the next packet of the flow leaves with another outer IPv4 ID (runs
 * after geneve_egress_pipeline_v4, which records the first one).
 */
PKTGEN("tc", "geneve_egress_pipeline_v4_second_packet")
int bpf_geneve_egress_pipeline_v4_second_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_egress_pipeline_v4_second_packet")
int bpf_geneve_egress_pipeline_v4_second_setup(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_setup(ctx);
}

CHECK("tc", "geneve_egress_pipeline_v4_second_packet")
int bpf_geneve_egress_pipeline_v4_second_check(const struct __ctx_buff *ctx)
{
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");

	assert(ip4->frag_off == 0);
	assert(geneve_ipv4_csum(ip4) == 0);
	assert(ip4->id == bpf_htons((__u16)mock_prandom));
	assert(ip4->id != first_ip_id);

	test_finish();
}

/* 2. Full native egress pipeline (IPv6 underlay + GSO per-segment wire len in FIB) */
PKTGEN("tc", "geneve_egress_pipeline_v6_and_gso_wire_len")
int bpf_geneve_egress_pipeline_v6_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_egress_pipeline_v6_and_gso_wire_len")
int bpf_geneve_egress_pipeline_v6_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.sec_identity = 0x3344,
		.flag_ipv6_tunnel_ep = true,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	mock_gso_size = 64;
	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_egress_pipeline_v6_and_gso_wire_len")
int bpf_geneve_egress_pipeline_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_node_one_addr };
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	const union v6addr zero = {};
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u16 expected_gso_wire_len;

	test_init();
	mock_gso_size = 0;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(!fallback_tunnel_key_set);
	assert(redirect_slot_magic == 0);
	/* B2: MARK_MAGIC_OVERLAY and the source identity over IPv6 too. */
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);

	/* Verify U2 FIB lookup 5-tuple + GSO per-segment wire length */
	expected_gso_wire_len = (__u16)(64 + ETH_HLEN + sizeof(struct iphdr) +
					sizeof(struct tcphdr) +
					sizeof(struct geneve_encaphdr6));
	assert(recorded_fib_flags == 0);
	assert(recorded_fib.family == AF_INET6);
	assert(recorded_fib.l4_protocol == IPPROTO_UDP);
	assert(recorded_fib.dport == bpf_htons(6081));
	assert(recorded_fib.sport != 0);
	assert(recorded_fib.tot_len == expected_gso_wire_len);
	assert(ipv6_addr_equals((const union v6addr *)recorded_fib.ipv6_src, &zero));
	assert(ipv6_addr_equals((const union v6addr *)recorded_fib.ipv6_dst,
				&expected_dst));

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	udp = (void *)(ip6 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated v6 headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	/* L1-08: the direct routing address. */
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert(udp->source == recorded_fib.sport);
	assert(udp->dest == bpf_htons(6081));
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);

	test_finish();
}

/* 3. U1(a): FIB returns BPF_FIB_LKUP_RET_FRAG_NEEDED -> fallback to ENCAP_IFINDEX
 * with tunnel key + DSR option populated and TC_INDEX_F_BPF_GENEVE_FALLBACK set.
 */
PKTGEN("tc", "geneve_fallback_on_frag_needed_v4")
int bpf_geneve_fallback_frag_needed_v4_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_fallback_on_frag_needed_v4")
int bpf_geneve_fallback_frag_needed_v4_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct geneve_dsr_opt4 dsr_opt = {};

	reset_test_state();
	mock_fib_ret = BPF_FIB_LKUP_RET_FRAG_NEEDED;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &dsr_opt);

	return geneve_encap_and_redirect(ctx, &ep, TEST_SECLABEL,
					 NOT_VTEP_DST, &dsr_opt,
					 sizeof(dsr_opt));
}

CHECK("tc", "geneve_fallback_on_frag_needed_v4")
int bpf_geneve_fallback_frag_needed_v4_check(const struct __ctx_buff *ctx)
{
	const struct geneve_dsr_opt4 *opt;
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 1);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert(redirect_flags == 0);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_ENCAP) == 0);
	assert(redirect_slot_magic == 0);
	/* U1: the fallback keeps MARK_MAGIC_OVERLAY and the identity. */
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);

	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key_flags == BPF_F_ZERO_CSUM_TX);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);

	assert(fallback_tunnel_opt_set);
	assert(recorded_tunnel_opt_len == sizeof(struct geneve_dsr_opt4));
	opt = (const struct geneve_dsr_opt4 *)recorded_tunnel_opt;
	assert(opt->hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(opt->hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(opt->addr == v4_svc_one);
	assert(opt->port == tcp_svc_one);

	/* Inner packet must remain unencapsulated for the kernel geneve device */
	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 4. U1(b): FIB returns BPF_FIB_LKUP_RET_UNREACHABLE on IPv6 underlay ->
 * fallback to ENCAP_IFINDEX with IPv6 tunnel key + DSR option.
 */
PKTGEN("tc", "geneve_fallback_on_fib_unreachable_v6")
int bpf_geneve_fallback_unreachable_v6_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_fallback_on_fib_unreachable_v6")
int bpf_geneve_fallback_unreachable_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr svc_addr = { .addr = v6_svc_one_addr };
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.sec_identity = 0x3344,
		.flag_ipv6_tunnel_ep = true,
	};
	struct geneve_dsr_opt6 dsr_opt = {};

	reset_test_state();
	mock_fib_ret = BPF_FIB_LKUP_RET_UNREACHABLE;
	set_geneve_dsr_opt6(tcp_svc_one, &svc_addr, &dsr_opt);

	return geneve_encap_and_redirect(ctx, &ep, TEST_SECLABEL,
					 NOT_VTEP_DST, &dsr_opt,
					 sizeof(dsr_opt));
}

CHECK("tc", "geneve_fallback_on_fib_unreachable_v6")
int bpf_geneve_fallback_unreachable_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	const union v6addr expected_svc = { .addr = v6_svc_one_addr };
	const struct geneve_dsr_opt6 *opt;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	/* U1: the fallback keeps MARK_MAGIC_OVERLAY and the identity. */
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);

	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key_flags == BPF_F_TUNINFO_IPV6);
	assert(recorded_tunnel_key.remote_ipv6[0] == expected_dst.p1);
	assert(recorded_tunnel_key.remote_ipv6[1] == expected_dst.p2);
	assert(recorded_tunnel_key.remote_ipv6[2] == expected_dst.p3);
	assert(recorded_tunnel_key.remote_ipv6[3] == expected_dst.p4);
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);

	assert(fallback_tunnel_opt_set);
	assert(recorded_tunnel_opt_len == sizeof(struct geneve_dsr_opt6));
	opt = (const struct geneve_dsr_opt6 *)recorded_tunnel_opt;
	assert(ipv6_addr_equals((const union v6addr *)&opt->addr, &expected_svc));
	assert(opt->port == tcp_svc_one);

	test_finish();
}

/* 5. U1(c): cil_to_overlay pass-through when TC_INDEX_F_BPF_GENEVE_FALLBACK is set
 * vs normal cil_to_overlay when TC_INDEX_F_BPF_GENEVE_FALLBACK is not set.
 */
PKTGEN("tc", "geneve_cil_to_overlay_fallback_passthrough")
int bpf_geneve_cil_to_overlay_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_cil_to_overlay_fallback_passthrough")
int bpf_geneve_cil_to_overlay_fallback_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	/* Populate a different tunnel_id in mock tunnel key so that if
	 * handle_to_overlay() ran a second time, it would overwrite the mark.
	 */
	recorded_tunnel_key.tunnel_id = 0x5555;
	fallback_tunnel_key_set = true;

	set_identity_mark(ctx, TEST_SECLABEL, MARK_MAGIC_OVERLAY);
	ctx_bpf_geneve_fallback_set(ctx);
	return overlay_send_packet(ctx);
}

CHECK("tc", "geneve_cil_to_overlay_fallback_passthrough")
int bpf_geneve_cil_to_overlay_fallback_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(!ctx_bpf_geneve_fallback_is_set(ctx));
	/* Mark identity was NOT overwritten by recorded_tunnel_key (0x5555). */
	assert(get_identity(ctx) == TEST_SECLABEL);

	test_finish();
}

PKTGEN("tc", "geneve_cil_to_overlay_normal")
int bpf_geneve_cil_to_overlay_normal_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_cil_to_overlay_normal")
int bpf_geneve_cil_to_overlay_normal_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	recorded_tunnel_key.tunnel_id = 0x5555;
	fallback_tunnel_key_set = true;

	set_identity_mark(ctx, TEST_SECLABEL, MARK_MAGIC_OVERLAY);
	ctx_bpf_geneve_fallback_clear(ctx);
	return overlay_send_packet(ctx);
}

CHECK("tc", "geneve_cil_to_overlay_normal")
int bpf_geneve_cil_to_overlay_normal_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	/* Normal cil_to_overlay ran handle_to_overlay() and updated identity from tunnel_key. */
	assert(get_identity(ctx) == 0x5555);

	test_finish();
}

/* 6. T-13: geneve_get_tunnel_opt() contract test */
PKTGEN("tc", "geneve_get_tunnel_opt_contract")
int bpf_geneve_get_tunnel_opt_contract_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_get_tunnel_opt_contract")
int bpf_geneve_get_tunnel_opt_contract_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {};
	struct geneve_metadata *meta;
	__u8 small_buf[4];

	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &dsr_opt);

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta)
		return TEST_ERROR;

	meta->magic = GENEVE_META_MAGIC;
	meta->vni = TEST_SECLABEL;
	meta->family = AF_INET;
	meta->opt_len = sizeof(dsr_opt);
	__bpf_memcpy_builtin(meta->raw_opts, &dsr_opt, sizeof(dsr_opt));
	ctx_bpf_geneve_decap_set(ctx);

	/* (a) size < opt_len -> -ENOMEM */
	opt_contract_ret_small = geneve_get_tunnel_opt(ctx, small_buf,
						       sizeof(small_buf));

	/* (b) size > opt_len -> returns opt_len and zero-pads trailing bytes */
	__bpf_memset_builtin(opt_contract_buf, 0xaa, sizeof(opt_contract_buf));
	opt_contract_ret_padded = geneve_get_tunnel_opt(ctx, opt_contract_buf,
							sizeof(opt_contract_buf));

	/* (c) opt_len == 0 -> -ENOENT */
	meta->opt_len = 0;
	opt_contract_ret_empty = geneve_get_tunnel_opt(ctx, small_buf,
						       sizeof(small_buf));
	ctx_bpf_geneve_decap_clear(ctx);
	meta->magic = 0;
	return 0;
}

CHECK("tc", "geneve_get_tunnel_opt_contract")
int bpf_geneve_get_tunnel_opt_contract_check(const struct __ctx_buff *ctx)
{
	const struct geneve_dsr_opt4 *opt;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);
	assert(opt_contract_ret_small == -ENOMEM);
	assert(opt_contract_ret_padded == sizeof(struct geneve_dsr_opt4));
	opt = (const struct geneve_dsr_opt4 *)opt_contract_buf;
	assert(opt->addr == v4_svc_one);
	assert(opt->port == tcp_svc_one);
	for (unsigned int i = sizeof(struct geneve_dsr_opt4);
	     i < sizeof(opt_contract_buf); i++)
		assert(opt_contract_buf[i] == 0);
	assert(opt_contract_ret_empty == -ENOENT);

	test_finish();
}

/* 7. U2: geneve_fib_lookup() looks up the outer flow (UDP to the tunnel port
 * from the chosen source port, per-segment length) without a source address
 * and, as supports_fib_lookup_src is not set, without flags.
 */
PKTGEN("tc", "geneve_fib_lookup_flow_v4")
int bpf_geneve_fib_lookup_flow_v4_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_fib_lookup_flow_v4")
int bpf_geneve_fib_lookup_flow_v4_setup(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	__be32 daddr = TUNNEL_DST_V4;

	reset_test_state();
	fib_lookup_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET, &daddr,
					   TEST_SPORT, TEST_WIRE_LEN);
	return 0;
}

CHECK("tc", "geneve_fib_lookup_flow_v4")
int bpf_geneve_fib_lookup_flow_v4_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(fib_lookup_ret == BPF_FIB_LKUP_RET_SUCCESS);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == 0);
	assert(recorded_fib.family == AF_INET);
	assert(recorded_fib.l4_protocol == IPPROTO_UDP);
	assert(recorded_fib.sport == TEST_SPORT);
	assert(recorded_fib.dport == bpf_htons(6081));
	assert(recorded_fib.tot_len == TEST_WIRE_LEN);
	assert(recorded_fib.ipv4_src == 0);
	assert(recorded_fib.ipv4_dst == TUNNEL_DST_V4);

	test_finish();
}

PKTGEN("tc", "geneve_fib_lookup_flow_v6")
int bpf_geneve_fib_lookup_flow_v6_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_fib_lookup_flow_v6")
int bpf_geneve_fib_lookup_flow_v6_setup(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {};
	union v6addr daddr = { .addr = v6_node_two_addr };

	reset_test_state();
	fib_lookup_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET6, &daddr,
					   TEST_SPORT, TEST_WIRE_LEN);
	return 0;
}

CHECK("tc", "geneve_fib_lookup_flow_v6")
int bpf_geneve_fib_lookup_flow_v6_check(const struct __ctx_buff *ctx __maybe_unused)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	const union v6addr zero = {};

	test_init();

	assert(fib_lookup_ret == BPF_FIB_LKUP_RET_SUCCESS);
	assert(fib_calls == 1);
	assert(recorded_fib_flags == 0);
	assert(recorded_fib.family == AF_INET6);
	assert(recorded_fib.l4_protocol == IPPROTO_UDP);
	assert(recorded_fib.sport == TEST_SPORT);
	assert(recorded_fib.dport == bpf_htons(6081));
	assert(recorded_fib.tot_len == TEST_WIRE_LEN);
	assert(ipv6_addr_equals((const union v6addr *)recorded_fib.ipv6_src, &zero));
	assert(ipv6_addr_equals((const union v6addr *)recorded_fib.ipv6_dst,
				&expected_dst));

	test_finish();
}

/* 8. L1-08: geneve_handle_encap4/6() take the direct routing address as the
 * outer source when the FIB lookup provides none. B4: they clear the ENCAP
 * marker and consume the slot.
 */
PKTGEN("tc", "geneve_encap4_direct_routing_saddr")
int bpf_geneve_encap4_direct_routing_saddr_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap4_direct_routing_saddr")
int bpf_geneve_encap4_direct_routing_saddr_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	ret = geneve_handle_encap4(ctx, &ext_err);
	observed_tc_index = (__u16)ctx->tc_index;
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap4_direct_routing_saddr")
int bpf_geneve_encap4_direct_routing_saddr_check(const struct __ctx_buff *ctx)
{
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(!fallback_tunnel_key_set);
	assert(recorded_fib_flags == 0);
	assert(recorded_fib.ipv4_src == 0);
	assert((observed_tc_index & TC_INDEX_F_BPF_GENEVE_ENCAP) == 0);
	assert(observed_slot_magic == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);

	test_finish();
}

PKTGEN("tc", "geneve_encap6_direct_routing_saddr")
int bpf_geneve_encap6_direct_routing_saddr_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap6_direct_routing_saddr")
int bpf_geneve_encap6_direct_routing_saddr_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot6(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	ret = geneve_handle_encap6(ctx, &ext_err);
	observed_tc_index = (__u16)ctx->tc_index;
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap6_direct_routing_saddr")
int bpf_geneve_encap6_direct_routing_saddr_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_node_one_addr };
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	const union v6addr zero = {};
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(!fallback_tunnel_key_set);
	assert(recorded_fib_flags == 0);
	assert(ipv6_addr_equals((const union v6addr *)recorded_fib.ipv6_src, &zero));
	assert((observed_tc_index & TC_INDEX_F_BPF_GENEVE_ENCAP) == 0);
	assert(observed_slot_magic == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		test_fatal("outer ip6 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ip6->nexthdr == IPPROTO_UDP);
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));

	test_finish();
}

/* 9. U1: a GSO packet whose segments would exceed 0xffff bytes once
 * encapsulated cannot be looked up with its length; it is handed to the
 * kernel tunnel device unmodified, with the tunnel key and the DSR option.
 */
PKTGEN("tc", "geneve_encap4_gso_wire_len_fallback")
int bpf_geneve_encap4_gso_wire_len_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap4_gso_wire_len_fallback")
int bpf_geneve_encap4_gso_wire_len_fallback_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one,
			    (struct geneve_dsr_opt4 *)meta->raw_opts);
	meta->opt_len = sizeof(struct geneve_dsr_opt4);
	set_identity_mark(ctx, TEST_SECLABEL, MARK_MAGIC_OVERLAY);
	ctx_bpf_geneve_encap_set(ctx);
	mock_gso_size = 0xffff;

	ret = geneve_handle_encap4(ctx, &ext_err);
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap4_gso_wire_len_fallback")
int bpf_geneve_encap4_gso_wire_len_fallback_check(const struct __ctx_buff *ctx)
{
	const struct geneve_dsr_opt4 *opt;
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_ENCAP) == 0);
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);
	assert(observed_slot_magic == 0);

	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key_flags == BPF_F_ZERO_CSUM_TX);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);
	assert(fallback_tunnel_opt_set);
	assert(recorded_tunnel_opt_len == sizeof(struct geneve_dsr_opt4));
	opt = (const struct geneve_dsr_opt4 *)recorded_tunnel_opt;
	assert(opt->addr == v4_svc_one);
	assert(opt->port == tcp_svc_one);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v4_gso_wire_len_fallback")
int bpf_geneve_pipeline_v4_gso_wire_len_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v4_gso_wire_len_fallback")
int bpf_geneve_pipeline_v4_gso_wire_len_fallback_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	mock_gso_size = 0xffff;
	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v4_gso_wire_len_fallback")
int bpf_geneve_pipeline_v4_gso_wire_len_fallback_check(const struct __ctx_buff *ctx)
{
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);
	assert(redirect_slot_magic == 0);
	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);
	assert(!fallback_tunnel_opt_set);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v6_gso_wire_len_fallback")
int bpf_geneve_pipeline_v6_gso_wire_len_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v6_gso_wire_len_fallback")
int bpf_geneve_pipeline_v6_gso_wire_len_fallback_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.sec_identity = 0x3344,
		.flag_ipv6_tunnel_ep = true,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	mock_gso_size = 0xffff;
	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v6_gso_wire_len_fallback")
int bpf_geneve_pipeline_v6_gso_wire_len_fallback_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key_flags == BPF_F_TUNINFO_IPV6);
	assert(recorded_tunnel_key.remote_ipv6[0] == expected_dst.p1);
	assert(recorded_tunnel_key.remote_ipv6[1] == expected_dst.p2);
	assert(recorded_tunnel_key.remote_ipv6[2] == expected_dst.p3);
	assert(recorded_tunnel_key.remote_ipv6[3] == expected_dst.p4);
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("inner eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 10. U1: bpf_skb_adjust_room() failing to make room for the encapsulation
 * leaves the packet unmodified, so it is handed to the kernel tunnel device
 * with the tunnel key and the DSR option.
 */
PKTGEN("tc", "geneve_encap4_adjust_room_fallback")
int bpf_geneve_encap4_adjust_room_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap4_adjust_room_fallback")
int bpf_geneve_encap4_adjust_room_fallback_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one,
			    (struct geneve_dsr_opt4 *)meta->raw_opts);
	meta->opt_len = sizeof(struct geneve_dsr_opt4);
	set_identity_mark(ctx, TEST_SECLABEL, MARK_MAGIC_OVERLAY);
	ctx_bpf_geneve_encap_set(ctx);
	mock_encap_room_ret = -ENOTSUPP;

	ret = geneve_handle_encap4(ctx, &ext_err);
	observed_slot_magic = meta->magic;
	return ret;
}

CHECK("tc", "geneve_encap4_adjust_room_fallback")
int bpf_geneve_encap4_adjust_room_fallback_check(const struct __ctx_buff *ctx)
{
	const struct geneve_dsr_opt4 *opt;
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 1);
	assert(redirect_neigh_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);
	assert(observed_slot_magic == 0);

	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key_flags == BPF_F_ZERO_CSUM_TX);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);
	assert(fallback_tunnel_opt_set);
	assert(recorded_tunnel_opt_len == sizeof(struct geneve_dsr_opt4));
	opt = (const struct geneve_dsr_opt4 *)recorded_tunnel_opt;
	assert(opt->addr == v4_svc_one);
	assert(opt->port == tcp_svc_one);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* U1 through the pipeline, entered like NodePort DSR does with its option:
 * nodeport_add_tunnel_encap_opt -> ... -> tail_geneve_encap4 -> fallback.
 */
PKTGEN("tc", "geneve_pipeline_v4_adjust_room_fallback")
int bpf_geneve_pipeline_v4_adjust_room_fallback_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v4_adjust_room_fallback")
int bpf_geneve_pipeline_v4_adjust_room_fallback_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct geneve_dsr_opt4 dsr_opt = {};
	int ifindex = 0;

	reset_test_state();
	mock_encap_room_ret = -ENOTSUPP;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &dsr_opt);

	return nodeport_add_tunnel_encap_opt(ctx, 0, 0, &ep, TEST_SECLABEL,
					     &dsr_opt, sizeof(dsr_opt),
					     TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN,
					     &ifindex, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v4_adjust_room_fallback")
int bpf_geneve_pipeline_v4_adjust_room_fallback_check(const struct __ctx_buff *ctx)
{
	const struct geneve_dsr_opt4 *opt;
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

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 1);
	assert(redirect_neigh_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert((redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK) != 0);
	assert((redirect_mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);
	assert(redirect_slot_magic == 0);

	assert(fallback_tunnel_key_set);
	assert(recorded_tunnel_key.remote_ipv4 == bpf_ntohl(TUNNEL_DST_V4));
	assert(recorded_tunnel_key.tunnel_id == TEST_SECLABEL);
	assert(fallback_tunnel_opt_set);
	assert(recorded_tunnel_opt_len == sizeof(struct geneve_dsr_opt4));
	opt = (const struct geneve_dsr_opt4 *)recorded_tunnel_opt;
	assert(opt->addr == v4_svc_one);
	assert(opt->port == tcp_svc_one);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 11. U1: BPF_FIB_LKUP_RET_NO_NEIGH keeps the packet on the native path:
 * encapsulated and handed to redirect_neigh(), which resolves the neighbour.
 */
PKTGEN("tc", "geneve_encap4_fib_no_neigh")
int bpf_geneve_encap4_fib_no_neigh_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap4_fib_no_neigh")
int bpf_geneve_encap4_fib_no_neigh_setup(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;

	reset_test_state();
	if (!stage_egress_slot4(TEST_SECLABEL))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	mock_fib_ret = BPF_FIB_LKUP_RET_NO_NEIGH;

	return geneve_handle_encap4(ctx, &ext_err);
}

CHECK("tc", "geneve_encap4_fib_no_neigh")
int bpf_geneve_encap4_fib_no_neigh_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 1);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(!fallback_tunnel_key_set);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated headers out of bounds");
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(udp->dest == bpf_htons(6081));
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);

	test_finish();
}

PKTGEN("tc", "geneve_pipeline_v4_fib_no_neigh")
int bpf_geneve_pipeline_v4_fib_no_neigh_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v4_fib_no_neigh")
int bpf_geneve_pipeline_v4_fib_no_neigh_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	mock_fib_ret = BPF_FIB_LKUP_RET_NO_NEIGH;
	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v4_fib_no_neigh")
int bpf_geneve_pipeline_v4_fib_no_neigh_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(fib_calls == 1);
	assert(redirect_neigh_calls == 1);
	assert(redirect_ifindex == UPLINK_IFINDEX);
	assert(!fallback_tunnel_key_set);
	assert(redirect_slot_magic == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("encapsulated headers out of bounds");
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(udp->dest == bpf_htons(6081));
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);

	test_finish();
}

/* 12. B2: tail_geneve_to_overlay, entered with a staged IPv6 slot, marks the
 * packet MARK_MAGIC_OVERLAY with the identity carried in the VNI.
 */
PKTGEN("tc", "geneve_to_overlay_v6_identity_mark")
int bpf_geneve_to_overlay_v6_identity_mark_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_to_overlay_v6_identity_mark")
int bpf_geneve_to_overlay_v6_identity_mark_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (!stage_egress_slot6(TEST_SECLABEL))
		return TEST_ERROR;

	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "geneve_to_overlay_v6_identity_mark")
int bpf_geneve_to_overlay_v6_identity_mark_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
	assert(get_identity(ctx) == TEST_SECLABEL);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)(eth + 1) > data_end)
		test_fatal("outer eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));

	test_finish();
}

/* 13. L2-07: the egress slot still holds the TLVs (and VNI, family and
 * endpoint) of an earlier packet. A packet staged without options leaves
 * with Geneve opt_len 0 and no TLV bytes.
 */
PKTGEN("tc", "geneve_pipeline_v4_stale_slot_tlvs")
int bpf_geneve_pipeline_v4_stale_slot_tlvs_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_pipeline_v4_stale_slot_tlvs")
int bpf_geneve_pipeline_v4_stale_slot_tlvs_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	struct geneve_metadata *meta;

	reset_test_state();
	meta = stage_egress_slot6(0x5555);
	if (!meta)
		return TEST_ERROR;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one,
			    (struct geneve_dsr_opt4 *)meta->raw_opts);
	meta->opt_len = sizeof(struct geneve_dsr_opt4);

	return __encap_and_redirect_with_nodeid(ctx, &ep, TEST_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_pipeline_v4_stale_slot_tlvs")
int bpf_geneve_pipeline_v4_stale_slot_tlvs_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth, *inner_eth;
	struct iphdr *ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 1);
	assert(recorded_fib.family == AF_INET);
	assert(recorded_fib.ipv4_dst == TUNNEL_DST_V4);
	assert(recorded_fib.tot_len ==
	       INNER_LEN_V4 + sizeof(struct geneve_encaphdr4));

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	inner_eth = (void *)(geneve + 1);
	inner_ip4 = (void *)(inner_eth + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("encapsulated headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(udp->len == bpf_htons(sizeof(*udp) + sizeof(*geneve) + INNER_LEN_V4));
	assert(geneve->opt_len == 0);
	assert(geneve_hdr_vni(geneve) == TEST_SECLABEL);
	assert(inner_eth->h_proto == bpf_htons(ETH_P_IP));
	assert(inner_ip4->saddr == SRC_IP);
	assert(inner_ip4->daddr == DST_IP);
	assert((void *)inner_eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 14. B4: geneve_overlay_egress_exit() drops a packet carrying the ENCAP
 * marker when the egress slot is not usable (consumed, or of no enabled
 * family) instead of passing it on un-encapsulated.
 */
PKTGEN("tc", "geneve_egress_exit_invalid_slot")
int bpf_geneve_egress_exit_invalid_slot_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_egress_exit_invalid_slot")
int bpf_geneve_egress_exit_invalid_slot_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	meta->magic = 0;
	exit_ret_no_magic = geneve_overlay_egress_exit(ctx, CTX_ACT_OK, &ext_err);

	meta->magic = GENEVE_META_MAGIC;
	meta->family = 0;
	exit_ret_bad_family = geneve_overlay_egress_exit(ctx, CTX_ACT_OK, &ext_err);

	meta->magic = 0;
	ctx_bpf_geneve_encap_clear(ctx);
	return CTX_ACT_OK;
}

CHECK("tc", "geneve_egress_exit_invalid_slot")
int bpf_geneve_egress_exit_invalid_slot_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(exit_ret_no_magic == DROP_NO_TUNNEL_KEY);
	assert(exit_ret_bad_family == DROP_NO_TUNNEL_KEY);
	assert(fib_calls == 0);

	test_finish();
}

/* B4: on the kernel path (no ENCAP marker) the verdict passes through even
 * though a valid-looking slot exists, and the slot is left alone.
 */
PKTGEN("tc", "geneve_egress_exit_kernel_path")
int bpf_geneve_egress_exit_kernel_path_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_egress_exit_kernel_path")
int bpf_geneve_egress_exit_kernel_path_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;
	int ret;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_clear(ctx);

	ret = geneve_overlay_egress_exit(ctx, CTX_ACT_OK, &ext_err);
	observed_slot_magic = meta->magic;
	meta->magic = 0;
	return ret;
}

CHECK("tc", "geneve_egress_exit_kernel_path")
int bpf_geneve_egress_exit_kernel_path_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(observed_slot_magic == GENEVE_META_MAGIC);
	assert(fib_calls == 0);
	assert(redirect_ifindex == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + INNER_LEN_V4 != data_end)
		test_fatal("packet was modified");

	test_finish();
}

/* B4: verdicts other than CTX_ACT_OK pass through unchanged, even with the
 * ENCAP marker and a valid slot.
 */
PKTGEN("tc", "geneve_egress_exit_non_ok_verdict")
int bpf_geneve_egress_exit_non_ok_verdict_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_egress_exit_non_ok_verdict")
int bpf_geneve_egress_exit_non_ok_verdict_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;
	__s8 ext_err = 0;

	reset_test_state();
	meta = stage_egress_slot4(TEST_SECLABEL);
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);

	exit_ret_redirect = geneve_overlay_egress_exit(ctx, CTX_ACT_REDIRECT,
						       &ext_err);
	exit_ret_drop = geneve_overlay_egress_exit(ctx, DROP_INVALID, &ext_err);

	meta->magic = 0;
	ctx_bpf_geneve_encap_clear(ctx);
	return CTX_ACT_OK;
}

CHECK("tc", "geneve_egress_exit_non_ok_verdict")
int bpf_geneve_egress_exit_non_ok_verdict_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(exit_ret_redirect == CTX_ACT_REDIRECT);
	assert(exit_ret_drop == DROP_INVALID);
	assert(fib_calls == 0);

	test_finish();
}

/* B4: the exit hook in the real tail_handle_nat_fwd_ipv4 drops a packet with
 * the ENCAP marker but no valid slot (DROP_NO_TUNNEL_KEY).
 */
PKTGEN("tc", "geneve_nat_fwd_exit_invalid_slot")
int bpf_geneve_nat_fwd_exit_invalid_slot_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_nat_fwd_exit_invalid_slot")
int bpf_geneve_nat_fwd_exit_invalid_slot_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;

	reset_test_state();
	meta = geneve_meta_slot(GENEVE_META_EGRESS);
	if (!meta)
		return TEST_ERROR;
	meta->magic = 0;
	ctx_bpf_geneve_encap_set(ctx);
	ctx_store_meta(ctx, CB_SRC_LABEL, TEST_SECLABEL);

	tail_call_static(ctx, cilium_calls, CILIUM_CALL_IPV4_NODEPORT_NAT_FWD);
	return TEST_ERROR;
}

CHECK("tc", "geneve_nat_fwd_exit_invalid_slot")
int bpf_geneve_nat_fwd_exit_invalid_slot_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_TUNNEL_KEY,
		.dir = METRIC_EGRESS,
	};
	void *data, *data_end;
	struct ethhdr *eth;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(fib_calls == 0);
	assert(redirect_ifindex == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + INNER_LEN_V4 != data_end)
		test_fatal("packet was modified");

	test_finish();
}

/* B4: cil_to_overlay (kernel path) ignores a stale ENCAP marker and a
 * valid-looking slot: the packet keeps the kernel's tunnel key and is passed
 * on to the tunnel device, not encapsulated.
 */
PKTGEN("tc", "geneve_cil_to_overlay_stale_encap_flag")
int bpf_geneve_cil_to_overlay_stale_encap_flag_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_egress_pipeline_v4_pktgen(ctx);
}

SETUP("tc", "geneve_cil_to_overlay_stale_encap_flag")
int bpf_geneve_cil_to_overlay_stale_encap_flag_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (!stage_egress_slot4(0x7777))
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	recorded_tunnel_key.tunnel_id = 0x5555;
	fallback_tunnel_key_set = true;

	return overlay_send_packet(ctx);
}

CHECK("tc", "geneve_cil_to_overlay_stale_encap_flag")
int bpf_geneve_cil_to_overlay_stale_encap_flag_check(const struct __ctx_buff *ctx)
{
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

	assert(*status_code == CTX_ACT_OK);
	assert(get_identity(ctx) == 0x5555);
	assert(fib_calls == 0);
	assert(redirect_ifindex == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* A UDP packet to port 6081 whose payload starts with a Geneve header that
 * carries a DSR option for v4_svc_three.
 */
static __always_inline int
build_udp_geneve_payload_packet(struct __ctx_buff *ctx, __be16 sport)
{
	struct geneve_dsr_opt4 *payload_opt;
	struct genevehdr *geneve;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
					  CLIENT_IP, BACKEND_IP,
					  sport, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	geneve = pktgen__push_default_genevehdr_with_options(&builder,
							     sizeof(*payload_opt));
	if (!geneve)
		return TEST_ERROR;
	payload_opt = (void *)(geneve + 1);
	if ((void *)(payload_opt + 1) > ctx_data_end(ctx))
		return TEST_ERROR;
	geneve->opt_len = sizeof(*payload_opt) >> 2;
	set_geneve_dsr_opt4(tcp_svc_three, v4_svc_three, payload_opt);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* The ingress slot as left by an earlier, natively decapsulated packet,
 * with a DSR option for v4_svc_two.
 */
static __always_inline struct geneve_metadata *
stage_stale_ingress_slot(void)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return NULL;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = WORLD_IPV4_ID;
	meta->family = AF_INET;
	set_geneve_dsr_opt4(tcp_svc_two, v4_svc_two,
			    (struct geneve_dsr_opt4 *)meta->raw_opts);
	meta->opt_len = sizeof(struct geneve_dsr_opt4);
	return meta;
}

/* 15. L1-12/L1-13: for a packet from the kernel tunnel device (DECAP marker
 * clear), geneve_get_tunnel_opt() returns exactly what the kernel helper
 * returns: neither the ingress slot's nor the payload's DSR option.
 */
PKTGEN("tc", "geneve_get_tunnel_opt_kernel_path")
int bpf_geneve_get_tunnel_opt_kernel_path_pktgen(struct __ctx_buff *ctx)
{
	return build_udp_geneve_payload_packet(ctx, tcp_src_one);
}

SETUP("tc", "geneve_get_tunnel_opt_kernel_path")
int bpf_geneve_get_tunnel_opt_kernel_path_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta;

	reset_test_state();
	meta = stage_stale_ingress_slot();
	if (!meta)
		return TEST_ERROR;
	ctx_bpf_geneve_decap_clear(ctx);

	__bpf_memset_builtin(&kernel_opt_absent, 0xaa, sizeof(kernel_opt_absent));
	mock_tunnel_opt_ret = -ENOENT;
	kernel_opt_absent_ret = geneve_get_tunnel_opt(ctx, &kernel_opt_absent,
						      sizeof(kernel_opt_absent));

	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &mock_tunnel_opt);
	mock_tunnel_opt_ret = sizeof(mock_tunnel_opt);
	kernel_opt_ret = geneve_get_tunnel_opt(ctx, &kernel_opt,
					       sizeof(kernel_opt));

	meta->magic = 0;
	return 0;
}

CHECK("tc", "geneve_get_tunnel_opt_kernel_path")
int bpf_geneve_get_tunnel_opt_kernel_path_check(const struct __ctx_buff *ctx __maybe_unused)
{
	const __u8 *absent = (const __u8 *)&kernel_opt_absent;

	test_init();

	assert(kernel_opt_absent_ret == -ENOENT);
	for (unsigned int i = 0; i < sizeof(kernel_opt_absent); i++)
		assert(absent[i] == 0);

	assert(kernel_opt_ret == sizeof(struct geneve_dsr_opt4));
	assert(kernel_opt.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(kernel_opt.addr == v4_svc_one);
	assert(kernel_opt.port == tcp_svc_one);

	test_finish();
}

/* L1-12/L1-13 through cil_from_overlay -> nodeport_lb4: a request from the
 * kernel tunnel device without a tunnel option creates no DSR state, even
 * with a stale DECAP marker and ingress slot and a DSR option in its
 * payload. It is delivered locally instead.
 */
PKTGEN("tc", "geneve_kernel_path_dsr_opt_absent")
int bpf_geneve_kernel_path_dsr_opt_absent_pktgen(struct __ctx_buff *ctx)
{
	return build_udp_geneve_payload_packet(ctx, tcp_src_two);
}

SETUP("tc", "geneve_kernel_path_dsr_opt_absent")
int bpf_geneve_kernel_path_dsr_opt_absent_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (!stage_stale_ingress_slot())
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	recorded_tunnel_key.tunnel_id = WORLD_IPV4_ID;
	fallback_tunnel_key_set = true;
	mock_tunnel_opt_ret = -ENOENT;

	return overlay_receive_packet(ctx);
}

CHECK("tc", "geneve_kernel_path_dsr_opt_absent")
int bpf_geneve_kernel_path_dsr_opt_absent_check(const struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = tcp_src_two,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_flags == BPF_F_INGRESS);
	if (map_lookup_elem(get_ct_map4(&tuple), &tuple))
		test_fatal("DSR CT entry created without a tunnel option");

	test_finish();
}

/* L1-12/L1-13: the same request with the DSR option from the kernel helper
 * creates the DSR CT entry for that option's service.
 */
PKTGEN("tc", "geneve_kernel_path_dsr_opt_from_helper")
int bpf_geneve_kernel_path_dsr_opt_from_helper_pktgen(struct __ctx_buff *ctx)
{
	return build_udp_geneve_payload_packet(ctx, tcp_src_three);
}

SETUP("tc", "geneve_kernel_path_dsr_opt_from_helper")
int bpf_geneve_kernel_path_dsr_opt_from_helper_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (!stage_stale_ingress_slot())
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	recorded_tunnel_key.tunnel_id = WORLD_IPV4_ID;
	fallback_tunnel_key_set = true;
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &mock_tunnel_opt);
	mock_tunnel_opt_ret = sizeof(mock_tunnel_opt);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "geneve_kernel_path_dsr_opt_from_helper")
int bpf_geneve_kernel_path_dsr_opt_from_helper_check(const struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = tcp_src_three,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		test_fatal("no DSR CT entry");
	assert(ct_entry->dsr_internal);
	assert(ct_entry->nat_addr.p4 == v4_svc_one);
	assert(ct_entry->nat_port == tcp_svc_one);

	test_finish();
}
