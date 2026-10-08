// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Inter-cluster SNAT on the native Geneve egress path (L1-20): a packet
 * tagged with the cluster ID of a remote cluster's backend is SNATed as on
 * the kernel path (see inter_cluster_snat_clusterip_client_overlay.c), by
 * tail_handle_snat_fwd_ipv4, whose exit hook then encapsulates it natively.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "lib/socket.h"

/* Overlapping PodCIDR is only supported for IPv4 for now */
#define ENABLE_IPV4		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_NODEPORT		1
#define ENABLE_CLUSTER_AWARE_ADDRESSING	1
#define ENABLE_INTER_CLUSTER_SNAT	1

/* A single NAT port, NODEPORT_PORT_MIN_NAT, for a deterministic SNAT. */
#define NODEPORT_PORT_MAX_NAT	32768
#include "nodeport_defaults.h"

#define UPLINK_IFINDEX		10
#define CLIENT_MAC		mac_one
#define CLIENT_ROUTER_MAC	mac_two
#define CLIENT_IP		v4_pod_one
#define BACKEND_IP		v4_pod_two
#define CLIENT_NODE_IP		v4_ext_one
#define BACKEND_NODE_IP		v4_ext_two
#define CLIENT_PORT		__bpf_htons(NODEPORT_PORT_MAX_NAT + 1)
#define BACKEND_PORT		tcp_svc_one
#define CLIENT_SECLABEL		0x1122
#define BACKEND_CLUSTER_ID	2
#define BACKEND_IDENTITY	((BACKEND_CLUSTER_ID << 16) | 0xff01)

#define CLIENT_INTER_CLUSTER_SNAT_PORT	__bpf_htons(NODEPORT_PORT_MIN_NAT)

static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
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
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex,
		  __u64 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
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

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = CLIENT_NODE_IP })
ASSIGN_CONFIG(union v4addr, ipv4_inter_cluster_snat, { .be32 = CLIENT_NODE_IP })
/* Overwrite (local) cluster_id defined in clustermesh.h */
ASSIGN_CONFIG(__u32, cluster_id, 1)

static __always_inline void
reset_test_state(void)
{
	redirect_ifindex = 0;
	redirect_neigh_calls = 0;
}

static __always_inline int
stage_egress_slot(void)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	if (!meta)
		return -1;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = CLIENT_SECLABEL;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.daddr = BACKEND_NODE_IP;
	return 0;
}

static __always_inline int
build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC, (__u8 *)CLIENT_ROUTER_MAC,
					  CLIENT_IP, BACKEND_IP,
					  CLIENT_PORT, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Encapsulated towards the backend's node and redirected to the uplink,
 * with the inner packet SNATed to the inter-cluster SNAT address. The inner
 * packet and its checksums are those of the kernel path test. All subtests
 * send the same connection, the first one creates the SNAT mapping.
 */
#define check_snat_and_encap(ctx)					\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct ethhdr *__eth = __data + sizeof(__u32);			\
	struct iphdr *__outer_ip4 = (void *)(__eth + 1);		\
	struct udphdr *__udp = (void *)(__outer_ip4 + 1);		\
	struct genevehdr *__geneve = (void *)(__udp + 1);		\
	struct ethhdr *__inner_eth = (void *)(__geneve + 1);		\
	struct iphdr *__ip4 = (void *)(__inner_eth + 1);		\
	struct tcphdr *__tcp = (void *)(__ip4 + 1);			\
	struct ipv4_ct_tuple __tuple = {				\
		.daddr = BACKEND_IP,					\
		.saddr = CLIENT_IP,					\
		.dport = BACKEND_PORT,					\
		.sport = CLIENT_PORT,					\
		.nexthdr = IPPROTO_TCP,					\
		.flags = TUPLE_F_OUT,					\
	};								\
	struct ipv4_nat_entry *__entry;					\
									\
	if ((void *)(__tcp + 1) > __data_end)				\
		test_fatal("packet out of bounds");			\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(redirect_neigh_calls == 1);				\
	assert(redirect_ifindex == UPLINK_IFINDEX);			\
	assert(__outer_ip4->saddr == CLIENT_NODE_IP);			\
	assert(__outer_ip4->daddr == BACKEND_NODE_IP);			\
	assert(__udp->dest == bpf_htons(6081));				\
	assert(geneve_hdr_vni(__geneve) == CLIENT_SECLABEL);		\
	assert(__geneve->opt_len == 0);					\
	assert(__ip4->saddr == CONFIG(ipv4_inter_cluster_snat).be32);	\
	assert(__ip4->daddr == BACKEND_IP);				\
	assert(__ip4->check == bpf_htons(0x4111));			\
	assert(__tcp->source == CLIENT_INTER_CLUSTER_SNAT_PORT);	\
	assert(__tcp->dest == BACKEND_PORT);				\
	assert(__tcp->check == bpf_htons(0xd71e));			\
	__entry = map_lookup_elem(&per_cluster_snat_mapping_ipv4_2,	\
				  &__tuple);				\
	if (!__entry)							\
		test_fatal("no egress SNAT mapping");			\
	assert(__entry->to_saddr == CONFIG(ipv4_inter_cluster_snat).be32); \
	assert(__entry->to_sport == CLIENT_INTER_CLUSTER_SNAT_PORT);	\
} while (0)

/* L1-20, full pipeline: __encap_and_redirect_with_nodeid ->
 * tail_geneve_to_overlay -> handle_nat_fwd(cluster_id) ->
 * tail_handle_nat_fwd_ipv4 -> tail_handle_snat_fwd_ipv4 -> tail_geneve_encap4.
 */
PKTGEN("tc", "geneve_inter_cluster_snat_pipeline")
int geneve_inter_cluster_snat_pipeline_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_inter_cluster_snat_pipeline")
int geneve_inter_cluster_snat_pipeline_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = BACKEND_NODE_IP,
		.sec_identity = BACKEND_IDENTITY,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	reset_test_state();
	/* The cluster ID mark that bpf_lxc sets for a remote cluster's backend */
	ctx_set_cluster_id_mark(ctx, BACKEND_CLUSTER_ID);

	return __encap_and_redirect_with_nodeid(ctx, &ep, CLIENT_SECLABEL,
						ep.sec_identity, NOT_VTEP_DST,
						&trace, bpf_htons(ETH_P_IP));
}

CHECK("tc", "geneve_inter_cluster_snat_pipeline")
int geneve_inter_cluster_snat_pipeline_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_snat_and_encap(ctx);

	test_finish();
}

/* L1-20: tail_geneve_to_overlay passes the cluster ID from the mark to the
 * NAT.
 */
PKTGEN("tc", "geneve_inter_cluster_snat_to_overlay")
int geneve_inter_cluster_snat_to_overlay_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_inter_cluster_snat_to_overlay")
int geneve_inter_cluster_snat_to_overlay_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (stage_egress_slot())
		return TEST_ERROR;
	ctx_set_cluster_id_mark(ctx, BACKEND_CLUSTER_ID);

	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "geneve_inter_cluster_snat_to_overlay")
int geneve_inter_cluster_snat_to_overlay_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_snat_and_encap(ctx);

	test_finish();
}

/* L1-20: the exit hook of tail_handle_snat_fwd_ipv4 encapsulates the
 * SNATed packet.
 */
PKTGEN("tc", "geneve_inter_cluster_snat_fwd_exit")
int geneve_inter_cluster_snat_fwd_exit_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_inter_cluster_snat_fwd_exit")
int geneve_inter_cluster_snat_fwd_exit_setup(struct __ctx_buff *ctx)
{
	reset_test_state();
	if (stage_egress_slot())
		return TEST_ERROR;
	ctx_bpf_geneve_encap_set(ctx);
	ctx_store_meta(ctx, CB_SRC_LABEL, CLIENT_SECLABEL);
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, BACKEND_CLUSTER_ID);

	tail_call_static(ctx, cilium_calls, CILIUM_CALL_IPV4_NODEPORT_SNAT_FWD);
	return TEST_ERROR;
}

CHECK("tc", "geneve_inter_cluster_snat_fwd_exit")
int geneve_inter_cluster_snat_fwd_exit_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_snat_and_encap(ctx);

	test_finish();
}
