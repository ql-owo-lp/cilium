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

#define HOST_IFINDEX		7

#define REMOTE_POD_IP		v4_pod_one
#define LOCAL_HOST_IP		v4_node_two

#define POD_IDENTITY		0x1122

/* Tunnel ID that the kernel tunnel device reports to cil_from_overlay. */
static __u32 kernel_tunnel_id;

static __always_inline int
mock_skb_get_tunnel_key(struct __sk_buff *skb __maybe_unused,
			struct bpf_tunnel_key *to, __u32 size __maybe_unused,
			__u32 flags __maybe_unused)
{
	to->tunnel_id = kernel_tunnel_id;
	return 0;
}

#define skb_get_tunnel_key mock_skb_get_tunnel_key

/* Host delivery ends in ctx_redirect() to cilium_host. */
static struct {
	__u32 count;
	__u32 ifindex;
	__u32 tc_index;
} host_redirect;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx, int ifindex,
		  __u32 flags __maybe_unused)
{
	host_redirect.count++;
	host_redirect.ifindex = (__u32)ifindex;
	host_redirect.tc_index = ctx->tc_index;
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect

/* Record the ifindex of the TRACE_FROM_OVERLAY notification. */
static __u32 trace_count;
static __u32 trace_ifindex;

#define TRACE_EXTENSION
#define trace_extension_hook(ctx, msg)				\
	do {							\
		if ((msg).subtype == TRACE_FROM_OVERLAY) {	\
			trace_count++;				\
			trace_ifindex = (msg).ifindex;		\
		}						\
	} while (0)

#include "lib/bpf_overlay.h"
#include "lib/metrics.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(__u32, cilium_host_ifindex, HOST_IFINDEX)
ASSIGN_CONFIG(bool, enable_trace_notify, true)

static __u32 setup_ingress_ifindex;

/* The inner packet, as bpf_host leaves it after native decapsulation or the
 * kernel tunnel device delivers it: a remote pod talking to this host.
 */
static __always_inline int build_inner_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  REMOTE_POD_IP, LOCAL_HOST_IP,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Stage the ingress slot like geneve_decap4() (valid) or a dropped packet
 * (invalid) leaves it.
 */
static __always_inline int stage_slot(__u32 magic, __u32 vni)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return -1;
	meta->magic = magic;
	meta->vni = vni;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.saddr = v4_node_one;
	meta->ip4.daddr = v4_node_two;
	return 0;
}

static __always_inline void reset_observations(void)
{
	kernel_tunnel_id = 0;
	__bpf_memzero(&host_redirect, sizeof(host_redirect));
	trace_count = 0;
	trace_ifindex = 0;
}

static __always_inline int enter_native(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY);
	return TEST_ERROR;
}

static __always_inline __u32 status_code(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return TEST_ERROR;
	return *(__u32 *)data;
}

/* B4: a native packet whose slot was invalidated is dropped. */
PKTGEN(PROG_TYPE, "geneve_from_overlay_native_invalid_slot_drops")
int geneve_from_overlay_native_invalid_slot_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_native_invalid_slot_drops")
int geneve_from_overlay_native_invalid_slot_drops_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	metrics_del_entry((__u8)-DROP_NO_TUNNEL_KEY, METRIC_INGRESS);
	if (stage_slot(0, POD_IDENTITY))
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	return enter_native(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_native_invalid_slot_drops")
int geneve_from_overlay_native_invalid_slot_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_TUNNEL_KEY,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(host_redirect.count == 0);

	test_finish();
}

/* B4: a valid slot is not used for a packet that bpf_host did not mark as
 * natively decapsulated.
 */
PKTGEN(PROG_TYPE, "geneve_from_overlay_native_without_decap_flag_drops")
int geneve_from_overlay_native_without_decap_flag_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_native_without_decap_flag_drops")
int geneve_from_overlay_native_without_decap_flag_drops_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	metrics_del_entry((__u8)-DROP_NO_TUNNEL_KEY, METRIC_INGRESS);
	if (stage_slot(GENEVE_META_MAGIC, POD_IDENTITY))
		return TEST_ERROR;
	ctx_bpf_geneve_decap_clear(ctx);
	return enter_native(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_native_without_decap_flag_drops")
int geneve_from_overlay_native_without_decap_flag_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_NO_TUNNEL_KEY,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(host_redirect.count == 0);

	test_finish();
}

/* B4: cil_from_overlay takes the source identity from the kernel tunnel key,
 * not from a valid slot and DECAP flag left behind by another packet: the
 * kernel reports HOST_ID, which is dropped although the slot holds a pod.
 */
PKTGEN(PROG_TYPE, "geneve_from_overlay_kernel_ignores_stale_slot")
int geneve_from_overlay_kernel_ignores_stale_slot_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_kernel_ignores_stale_slot")
int geneve_from_overlay_kernel_ignores_stale_slot_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	metrics_del_entry((__u8)-DROP_INVALID_IDENTITY, METRIC_INGRESS);
	if (stage_slot(GENEVE_META_MAGIC, POD_IDENTITY))
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	kernel_tunnel_id = HOST_ID;
	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_kernel_ignores_stale_slot")
int geneve_from_overlay_kernel_ignores_stale_slot_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_INVALID_IDENTITY,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(host_redirect.count == 0);

	test_finish();
}

/* B4: the reverse: the slot left behind holds HOST_ID, the kernel tunnel key
 * a pod. The packet is delivered with the kernel's identity, and the stale
 * DECAP flag is cleared so that nothing later in the pipeline reads the slot.
 */
PKTGEN(PROG_TYPE, "geneve_from_overlay_kernel_identity_from_tunnel_key")
int geneve_from_overlay_kernel_identity_from_tunnel_key_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_kernel_identity_from_tunnel_key")
int geneve_from_overlay_kernel_identity_from_tunnel_key_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	if (stage_slot(GENEVE_META_MAGIC, HOST_ID))
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	kernel_tunnel_id = POD_IDENTITY;
	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_kernel_identity_from_tunnel_key")
int geneve_from_overlay_kernel_identity_from_tunnel_key_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(status_code(ctx) == CTX_ACT_REDIRECT);
	assert(host_redirect.count == 1);
	assert(host_redirect.ifindex == HOST_IFINDEX);
	assert(!(host_redirect.tc_index & TC_INDEX_F_BPF_GENEVE_DECAP));
	assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_IDENTITY);
	assert(get_identity(ctx) == POD_IDENTITY);

	test_finish();
}

/* D30b: TRACE_FROM_OVERLAY of a natively decapsulated packet reports the
 * tunnel device, like the kernel path reports the device the packet was
 * received on.
 */
PKTGEN(PROG_TYPE, "geneve_from_overlay_native_trace_ifindex")
int geneve_from_overlay_native_trace_ifindex_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_native_trace_ifindex")
int geneve_from_overlay_native_trace_ifindex_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	if (stage_slot(GENEVE_META_MAGIC, POD_IDENTITY))
		return TEST_ERROR;
	ctx_bpf_geneve_decap_set(ctx);
	return enter_native(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_native_trace_ifindex")
int geneve_from_overlay_native_trace_ifindex_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(status_code(ctx) == CTX_ACT_REDIRECT);
	assert(get_identity(ctx) == POD_IDENTITY);
	assert(trace_count == 1);
	assert(trace_ifindex == ENCAP_IFINDEX);

	test_finish();
}

/* D30b: the kernel path keeps reporting the receiving device. */
PKTGEN(PROG_TYPE, "geneve_from_overlay_kernel_trace_ifindex")
int geneve_from_overlay_kernel_trace_ifindex_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_from_overlay_kernel_trace_ifindex")
int geneve_from_overlay_kernel_trace_ifindex_setup(struct __ctx_buff *ctx)
{
	reset_observations();
	kernel_tunnel_id = POD_IDENTITY;
	setup_ingress_ifindex = ctx->ingress_ifindex;
	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_from_overlay_kernel_trace_ifindex")
int geneve_from_overlay_kernel_trace_ifindex_check(const struct __ctx_buff *ctx)
{
	test_init();

	assert(setup_ingress_ifindex != ENCAP_IFINDEX);
	assert(status_code(ctx) == CTX_ACT_REDIRECT);
	assert(trace_count == 1);
	assert(trace_ifindex == setup_ingress_ifindex);

	test_finish();
}
