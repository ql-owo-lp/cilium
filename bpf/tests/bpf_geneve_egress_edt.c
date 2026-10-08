// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Bandwidth manager (EDT) on the to-overlay paths with the native Geneve
 * datapath (D20): native packets leave the departure time to cil_to_netdev
 * and keep their aggregate for it; packets on the tunnel device, whether
 * handed over by the native path or on the kernel path, get it set once in
 * cil_to_overlay.
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
#define ENABLE_BANDWIDTH_MANAGER	1

#define UPLINK_IFINDEX		10
#define SRC_IP			v4_pod_one
#define DST_IP			v4_pod_two
#define TUNNEL_DST_V4		v4_node_two
#define TEST_SECLABEL		0x1122

#define AGGREGATE_ID		42
/* One byte per nanosecond: a packet delays the next one by its wire length
 * in nanoseconds.
 */
#define EDT_BPS			NSEC_PER_SEC
#define EDT_PRIO		3

static long mock_fib_ret;
static __u32 fib_calls;
static __u32 fib_queue_mapping;
static __u64 fib_tstamp;

/* Records the EDT state of the packet when the native path looks up the
 * underlay route.
 */
static __always_inline long
mock_fib_lookup(const void *ctx, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	const struct __sk_buff *skb = ctx;

	fib_calls++;
	fib_queue_mapping = skb->queue_mapping;
	fib_tstamp = skb->tstamp;

	if (mock_fib_ret != BPF_FIB_LKUP_RET_SUCCESS)
		return mock_fib_ret;

	params->ifindex = UPLINK_IFINDEX;
	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_three, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_four, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#undef fib_lookup
#define fib_lookup mock_fib_lookup

static __u32 redirect_ifindex;
static __u16 redirect_tc_index;
static __u32 redirect_queue_mapping;
static __u64 redirect_tstamp;
static __u32 redirect_neigh_calls;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx, int ifindex,
		  __u64 flags __maybe_unused)
{
	redirect_ifindex = (__u32)ifindex;
	redirect_tc_index = (__u16)ctx->tc_index;
	redirect_queue_mapping = ctx->queue_mapping;
	redirect_tstamp = ctx->tstamp;
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

static __always_inline int
mock_skb_set_tunnel_key(struct __sk_buff *skb __maybe_unused,
			const struct bpf_tunnel_key *from __maybe_unused,
			__u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	return 0;
}

#undef skb_set_tunnel_key
#define skb_set_tunnel_key mock_skb_set_tunnel_key

#include "lib/bpf_overlay.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_one })

static __u64 t_last_old;
static __u32 setup_wire_len;
static int fallback_ret;
static __u16 fallback_tc_index;
static __u32 fallback_queue_mapping;

static __always_inline void
reset_test_state(void)
{
	mock_fib_ret = BPF_FIB_LKUP_RET_SUCCESS;
	fib_calls = 0;
	fib_queue_mapping = 0;
	fib_tstamp = ~0ULL;
	redirect_ifindex = 0;
	redirect_tc_index = 0;
	redirect_queue_mapping = 0;
	redirect_tstamp = ~0ULL;
	redirect_neigh_calls = 0;
}

/* Puts the packet into an aggregate whose last departure is one second in
 * the future, so that EDT would set the departure time to t_last_old plus
 * the wire length. To be called right before entering the program, as the
 * aggregate (queue_mapping) does not survive between runs.
 */
static __always_inline int
setup_aggregate(struct __ctx_buff *ctx)
{
	struct edt_id key = {
		.id = AGGREGATE_ID,
		.direction = DIRECTION_EGRESS,
	};
	struct edt_info info = {
		.bps = EDT_BPS,
		.t_horizon_drop = 10 * NSEC_PER_SEC,
		.prio = EDT_PRIO,
	};

	reset_test_state();
	t_last_old = ktime_get_ns() + NSEC_PER_SEC;
	info.t_last = t_last_old;
	if (map_update_elem(&cilium_throttle, &key, &info, BPF_ANY))
		return -1;

	setup_wire_len = ctx_wire_len(ctx);
	edt_set_aggregate(ctx, AGGREGATE_ID);
	return 0;
}

static __always_inline struct edt_info *
aggregate_info(void)
{
	struct edt_id key = {
		.id = AGGREGATE_ID,
		.direction = DIRECTION_EGRESS,
	};

	return map_lookup_elem(&cilium_throttle, &key);
}

/* Enter the native egress pipeline like bpf_lxc does for a pod-to-pod
 * packet to a remote node.
 */
static __always_inline int
enter_pipeline(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = 0x3344,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

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

/* Native egress: no departure time, the aggregate left in queue_mapping
 * when the packet reaches the underlay device, t_last untouched.
 */
#define check_native_no_edt(ctx)					\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
	struct edt_info *__info = aggregate_info();			\
									\
	if (__data + sizeof(__u32) > __data_end)			\
		test_fatal("status code out of bounds");		\
	if (!__info)							\
		test_fatal("no aggregate");				\
	assert(*(__u32 *)__data == CTX_ACT_REDIRECT);			\
	assert(redirect_neigh_calls == 1);				\
	assert(redirect_ifindex == UPLINK_IFINDEX);			\
	assert(fib_calls == 1);						\
	assert(fib_queue_mapping == AGGREGATE_ID);			\
	assert(fib_tstamp == 0);					\
	assert((ctx)->tstamp == 0);					\
	assert((ctx)->priority == 0);					\
	assert(__info->t_last == t_last_old);				\
} while (0)

/* EDT ran once: the departure time is one delay after t_last_old. */
#define check_edt_once(ctx)						\
do {									\
	struct edt_info *__info = aggregate_info();			\
									\
	if (!__info)							\
		test_fatal("no aggregate");				\
	assert((ctx)->tstamp == t_last_old + setup_wire_len);		\
	assert(__info->t_last == (ctx)->tstamp);			\
	assert((ctx)->priority == EDT_PRIO - 1);			\
} while (0)

/* D20: the full native pipeline does not schedule the packet. */
PKTGEN("tc", "geneve_edt_native_pipeline")
int geneve_edt_native_pipeline_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_native_pipeline")
int geneve_edt_native_pipeline_setup(struct __ctx_buff *ctx)
{
	if (setup_aggregate(ctx))
		return TEST_ERROR;
	return enter_pipeline(ctx);
}

CHECK("tc", "geneve_edt_native_pipeline")
int geneve_edt_native_pipeline_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_native_no_edt(ctx);

	test_finish();
}

/* D20: tail_geneve_to_overlay on its own, entered with a staged egress
 * slot.
 */
PKTGEN("tc", "geneve_edt_to_overlay_native")
int geneve_edt_to_overlay_native_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_to_overlay_native")
int geneve_edt_to_overlay_native_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = TEST_SECLABEL;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.daddr = TUNNEL_DST_V4;

	if (setup_aggregate(ctx))
		return TEST_ERROR;
	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY);
	return TEST_ERROR;
}

CHECK("tc", "geneve_edt_to_overlay_native")
int geneve_edt_to_overlay_native_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_native_no_edt(ctx);

	test_finish();
}

/* D20: a native packet handed to the tunnel device (here: it does not fit
 * the route MTU) still carries its aggregate and no departure time, for
 * cil_to_overlay to schedule it.
 */
PKTGEN("tc", "geneve_edt_pipeline_fallback")
int geneve_edt_pipeline_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_pipeline_fallback")
int geneve_edt_pipeline_fallback_setup(struct __ctx_buff *ctx)
{
	if (setup_aggregate(ctx))
		return TEST_ERROR;
	mock_fib_ret = BPF_FIB_LKUP_RET_FRAG_NEEDED;
	return enter_pipeline(ctx);
}

CHECK("tc", "geneve_edt_pipeline_fallback")
int geneve_edt_pipeline_fallback_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct edt_info *info;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	info = aggregate_info();
	if (!info)
		test_fatal("no aggregate");

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_neigh_calls == 0);
	assert(redirect_ifindex == ENCAP_IFINDEX);
	assert(redirect_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK);
	assert(redirect_queue_mapping == AGGREGATE_ID);
	assert(redirect_tstamp == 0);
	assert(info->t_last == t_last_old);

	test_finish();
}

/* D20: geneve_fallback_to_overlay() schedules the packet, consuming the
 * aggregate, and clears the marker.
 */
PKTGEN("tc", "geneve_edt_fallback_to_overlay")
int geneve_edt_fallback_to_overlay_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_fallback_to_overlay")
int geneve_edt_fallback_to_overlay_setup(struct __ctx_buff *ctx)
{
	if (setup_aggregate(ctx))
		return TEST_ERROR;
	ctx_bpf_geneve_fallback_set(ctx);

	fallback_ret = geneve_fallback_to_overlay(ctx);
	fallback_tc_index = (__u16)ctx->tc_index;
	fallback_queue_mapping = ctx->queue_mapping;
	return 0;
}

CHECK("tc", "geneve_edt_fallback_to_overlay")
int geneve_edt_fallback_to_overlay_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(fallback_ret == CTX_ACT_OK);
	assert(!(fallback_tc_index & TC_INDEX_F_BPF_GENEVE_FALLBACK));
	assert(fallback_queue_mapping == 0);
	check_edt_once(ctx);

	test_finish();
}

/* D20: the same through the cil_to_overlay entry point. */
PKTGEN("tc", "geneve_edt_cil_to_overlay_fallback")
int geneve_edt_cil_to_overlay_fallback_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_cil_to_overlay_fallback")
int geneve_edt_cil_to_overlay_fallback_setup(struct __ctx_buff *ctx)
{
	if (setup_aggregate(ctx))
		return TEST_ERROR;
	ctx_bpf_geneve_fallback_set(ctx);
	return overlay_send_packet(ctx);
}

CHECK("tc", "geneve_edt_cil_to_overlay_fallback")
int geneve_edt_cil_to_overlay_fallback_check(const struct __ctx_buff *ctx)
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
	check_edt_once(ctx);

	test_finish();
}

/* D20: on the kernel path cil_to_overlay schedules the packet as before. */
PKTGEN("tc", "geneve_edt_cil_to_overlay_kernel_path")
int geneve_edt_cil_to_overlay_kernel_path_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "geneve_edt_cil_to_overlay_kernel_path")
int geneve_edt_cil_to_overlay_kernel_path_setup(struct __ctx_buff *ctx)
{
	if (setup_aggregate(ctx))
		return TEST_ERROR;
	return overlay_send_packet(ctx);
}

CHECK("tc", "geneve_edt_cil_to_overlay_kernel_path")
int geneve_edt_cil_to_overlay_kernel_path_check(const struct __ctx_buff *ctx)
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
	assert(fib_calls == 0);
	check_edt_once(ctx);

	test_finish();
}
