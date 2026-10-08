// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* D20: handle_to_overlay() leaves EDT for natively encapsulated packets to
 * cil_to_netdev on the underlay device, where the aggregate that bpf_lxc
 * stored in queue_mapping is still present. A departure time set at the
 * overlay would be lost on the redirect to the underlay device, and
 * edt_sched_departure() consumes the aggregate, so cil_to_netdev would no
 * longer find it either.
 *
 * In production ctx_wire_len() on the underlay device is the length of the
 * encapsulated packet (qdisc_pkt_len_init() on that device).
 * BPF_PROG_TEST_RUN does not recompute it after bpf_skb_adjust_room(), so
 * the expected delay is derived from the wire_len that cil_to_netdev sees.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define TUNNEL_MODE			1
#define ENCAP_IFINDEX			42
#define ENABLE_BPF_GENEVE		1
#define ENABLE_BANDWIDTH_MANAGER	1

#define SRC_NODE_V4		v4_node_one
#define DST_NODE_V4		v4_node_two
#define SRC_POD_V4		v4_pod_one
#define DST_POD_V4		v4_pod_one_on_node_two
#define SRC_POD_SEC_IDENTITY	0x1234
#define GENEVE_SPORT		bpf_htons(50000)

#define EDT_AGGREGATE		7
#define EDT_BPS			125000	/* 1 Mbit/s */
#define EDT_PRIO		3

#include "lib/bpf_host.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)

/* Throttle state before the packet, and the wire length it is charged. */
static __u64 t_last_before;
static __u32 wire_len;

/* Inner pod-to-pod packet, as handed to the native Geneve egress. */
static __always_inline int build_inner_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)mac_one, (__u8 *)mac_two,
					  SRC_POD_V4, DST_POD_V4,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline struct edt_info *throttle_entry(void)
{
	struct edt_id id = {
		.id = EDT_AGGREGATE,
		.direction = DIRECTION_EGRESS,
	};

	return map_lookup_elem(&cilium_throttle, &id);
}

/* Reset the aggregate's throttle entry to a link that has just gone idle,
 * encapsulate as tail_geneve_encap4() does (VNI = source identity, no
 * TLVs), mark the packet as handle_to_overlay() does if @overlay_mark and
 * send it to cil_to_netdev with @aggregate in queue_mapping, without a
 * departure time.
 */
static __always_inline int
send_geneve_packet(struct __ctx_buff *ctx, bool overlay_mark, __u32 aggregate)
{
	struct edt_id id = {
		.id = EDT_AGGREGATE,
		.direction = DIRECTION_EGRESS,
	};
	struct edt_info info = {
		.bps = EDT_BPS,
		.t_horizon_drop = NSEC_PER_SEC,
		.prio = EDT_PRIO,
	};
	int ret;

	info.t_last = ktime_get_ns();
	t_last_before = info.t_last;
	map_update_elem(&cilium_throttle, &id, &info, BPF_ANY);

	ret = geneve_encap4(ctx, SRC_NODE_V4, DST_NODE_V4, SRC_POD_SEC_IDENTITY,
			    GENEVE_SPORT, NULL, 0);
	if (ret < 0)
		return ret;

	if (overlay_mark)
		set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);
	else
		ctx->mark = 0;

	wire_len = ctx_wire_len(ctx);
	ctx->tstamp = 0;
	ctx->priority = 0;
	edt_set_aggregate(ctx, aggregate);

	return netdev_send_packet(ctx);
}

/* @scheduled: cil_to_netdev set the departure time from the throttle
 * entry, one packet's delay after the previous departure. Otherwise it left
 * the packet and the throttle entry alone.
 */
static __always_inline int
check_departure(const struct __ctx_buff *ctx, bool scheduled)
{
	void *data, *data_end;
	__u32 *status_code;
	struct edt_info *info;
	__u64 delay;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	info = throttle_entry();
	if (!info)
		test_fatal("throttle entry missing");

	if (scheduled) {
		/* A zero delay would let the packet depart right away. */
		if (!wire_len)
			test_fatal("no wire length to charge");
		delay = (__u64)wire_len * NSEC_PER_SEC / EDT_BPS;

		assert(ctx->tstamp == t_last_before + delay);
		assert(info->t_last == ctx->tstamp);
		assert(ctx->priority == EDT_PRIO - 1);
	} else {
		assert(ctx->tstamp == 0);
		assert(info->t_last == t_last_before);
		assert(ctx->priority == 0);
	}

	test_finish();
}

/* D20: the marked native packet is scheduled once from its aggregate. */
PKTGEN("tc", "geneve_edt_overlay_mark_scheduled")
int geneve_edt_overlay_mark_scheduled_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_edt_overlay_mark_scheduled")
int geneve_edt_overlay_mark_scheduled_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, EDT_AGGREGATE);
}

CHECK("tc", "geneve_edt_overlay_mark_scheduled")
int geneve_edt_overlay_mark_scheduled_check(const struct __ctx_buff *ctx)
{
	return check_departure(ctx, true);
}

/* D20: without the aggregate (as when an earlier edt_sched_departure()
 * consumed it) the packet leaves unthrottled.
 */
PKTGEN("tc", "geneve_edt_overlay_mark_no_aggregate_unthrottled")
int geneve_edt_overlay_mark_no_aggregate_unthrottled_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_edt_overlay_mark_no_aggregate_unthrottled")
int geneve_edt_overlay_mark_no_aggregate_unthrottled_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, 0);
}

CHECK("tc", "geneve_edt_overlay_mark_no_aggregate_unthrottled")
int geneve_edt_overlay_mark_no_aggregate_unthrottled_check(const struct __ctx_buff *ctx)
{
	return check_departure(ctx, false);
}

/* D20 contrast: EDT keys on the aggregate alone, the unmarked packet is
 * scheduled the same way.
 */
PKTGEN("tc", "geneve_edt_no_mark_scheduled")
int geneve_edt_no_mark_scheduled_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_edt_no_mark_scheduled")
int geneve_edt_no_mark_scheduled_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false, EDT_AGGREGATE);
}

CHECK("tc", "geneve_edt_no_mark_scheduled")
int geneve_edt_no_mark_scheduled_check(const struct __ctx_buff *ctx)
{
	return check_departure(ctx, true);
}
