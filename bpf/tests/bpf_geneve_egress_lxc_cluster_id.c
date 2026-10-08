// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Cluster ID mark on the native Geneve egress path from bpf_lxc (L1-20):
 * the to-overlay pipeline in bpf_overlay takes the cluster ID of a remote
 * cluster's backend from the mark to apply inter-cluster SNAT (see
 * bpf_geneve_egress_inter_cluster_snat.c), so it must be set when bpf_lxc
 * tail calls into it, as it is when bpf_lxc redirects to the tunnel device
 * (see inter_cluster_snat_clusterip_client_lxc.c).
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define CLIENT_MAC		mac_one
#define CLIENT_ROUTER_MAC	mac_two
#define CLIENT_IP		v4_pod_one
#define BACKEND_IP		v4_pod_two
#define CLIENT_PORT		tcp_src_one
#define BACKEND_PORT		tcp_src_two
#define BACKEND_NODE_IP		v4_ext_one
#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one
#define BACKEND_CLUSTER_ID	2
#define BACKEND_IDENTITY	((BACKEND_CLUSTER_ID << 16) | 0xff01)

#define ENCAP_IFINDEX		42
/* Overlapping PodCIDR is only supported for IPv4 for now */
#define ENABLE_IPV4		1
#define TUNNEL_MODE		1
#define ENABLE_NODEPORT		1
#define ENABLE_CLUSTER_AWARE_ADDRESSING	1
#define ENABLE_BPF_GENEVE	1

#include <bpf/config/node.h>

/* Need to undef EVENT_SOURCE here since it is defined in
 * both of common.h and bpf_lxc.c.
 */
#undef EVENT_SOURCE

#include "lib/bpf_lxc.h"

/* Overwrite (local) cluster_id defined in clustermesh.h */
ASSIGN_CONFIG(__u32, cluster_id, 1)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = CLIENT_IP })
ASSIGN_CONFIG(__u32, security_label, 0x10042)
ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"

static __u32 to_overlay_reached;
static __u32 observed_cluster_id;
static __be32 observed_daddr4;

/* Stands in for tail_geneve_to_overlay, where handle_to_overlay() takes the
 * cluster ID from the mark.
 */
__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY)
int test_to_overlay_receiver(struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	to_overlay_reached = 1;
	observed_cluster_id = ctx_get_cluster_id_mark(ctx);
	if (meta)
		observed_daddr4 = meta->ip4.daddr;
	return CTX_ACT_OK;
}

/* L1-20: pod egress to a remote cluster's backend enters the native
 * to-overlay pipeline with the backend's cluster ID in the mark.
 */
PKTGEN("tc", "geneve_lxc_to_overlay_cluster_id")
int geneve_lxc_to_overlay_cluster_id_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC, (__u8 *)CLIENT_ROUTER_MAC,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_lxc_to_overlay_cluster_id")
int geneve_lxc_to_overlay_cluster_id_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 1,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP,
			  BACKEND_CLUSTER_ID);

	ipcache_v4_add_entry(BACKEND_IP, BACKEND_CLUSTER_ID, BACKEND_IDENTITY,
			     BACKEND_NODE_IP, 0);

	policy_add_egress_allow_l3_l4_entry(BACKEND_IDENTITY, IPPROTO_TCP,
					    BACKEND_PORT, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "geneve_lxc_to_overlay_cluster_id")
int geneve_lxc_to_overlay_cluster_id_check(const struct __ctx_buff *ctx)
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
	assert(to_overlay_reached == 1);
	assert(observed_daddr4 == BACKEND_NODE_IP);
	assert(observed_cluster_id == BACKEND_CLUSTER_ID);

	test_finish();
}
