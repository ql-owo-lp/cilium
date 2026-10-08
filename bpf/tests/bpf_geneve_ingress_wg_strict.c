// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define ENABLE_WIREGUARD	1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1

#define REMOTE_POD_IP		v4_pod_one
#define LOCAL_POD_IP		v4_pod_two
#define LOCAL_POD_IFINDEX	5
#define LOCAL_POD_LXC_ID	0
#define POD_IDENTITY		0x1122

static __always_inline int
mock_skb_get_tunnel_key(struct __sk_buff *skb __maybe_unused,
			struct bpf_tunnel_key *to, __u32 size __maybe_unused,
			__u32 flags __maybe_unused)
{
	to->tunnel_id = POD_IDENTITY;
	return 0;
}

#define skb_get_tunnel_key mock_skb_get_tunnel_key

/* Local delivery ends in the endpoint's policy program, which accepts. */
__section_entry
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[LOCAL_POD_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline void
mock_tail_call_dynamic(struct __ctx_buff *ctx, const void *map __maybe_unused,
		       __u32 slot)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "lib/bpf_overlay.h"
#include "lib/endpoint.h"
#include "lib/metrics.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(bool, enable_identity_mark, true)
ASSIGN_CONFIG(bool, encryption_strict_ingress, true)

/* The inner packet of a remote pod talking to a local one. */
static __always_inline int build_inner_v4(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  REMOTE_POD_IP, LOCAL_POD_IP,
					  tcp_src_one, tcp_dst_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Enter tail_geneve_from_overlay as tail_geneve_decap4() does. */
static __always_inline int enter_native(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = POD_IDENTITY;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.saddr = v4_node_one;
	meta->ip4.daddr = v4_node_two;
	ctx_bpf_geneve_decap_set(ctx);

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

/* B3, L1-03: WireGuard strict ingress: a natively decapsulated packet that
 * did not arrive through WireGuard is dropped.
 */
PKTGEN(PROG_TYPE, "geneve_wg_strict_native_unencrypted_drops")
int geneve_wg_strict_native_unencrypted_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_wg_strict_native_unencrypted_drops")
int geneve_wg_strict_native_unencrypted_drops_setup(struct __ctx_buff *ctx)
{
	metrics_del_entry((__u8)-DROP_UNENCRYPTED_TRAFFIC, METRIC_INGRESS);
	ctx->mark = 0;
	return enter_native(ctx);
}

CHECK(PROG_TYPE, "geneve_wg_strict_native_unencrypted_drops")
int geneve_wg_strict_native_unencrypted_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNENCRYPTED_TRAFFIC,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);

	test_finish();
}

/* B3, L1-03: the kernel path drops the same packet. */
PKTGEN(PROG_TYPE, "geneve_wg_strict_kernel_unencrypted_drops")
int geneve_wg_strict_kernel_unencrypted_drops_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_wg_strict_kernel_unencrypted_drops")
int geneve_wg_strict_kernel_unencrypted_drops_setup(struct __ctx_buff *ctx)
{
	metrics_del_entry((__u8)-DROP_UNENCRYPTED_TRAFFIC, METRIC_INGRESS);
	ctx->mark = 0;
	return overlay_receive_packet(ctx);
}

CHECK(PROG_TYPE, "geneve_wg_strict_kernel_unencrypted_drops")
int geneve_wg_strict_kernel_unencrypted_drops_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNENCRYPTED_TRAFFIC,
		.dir = METRIC_INGRESS,
	};

	test_init();

	assert(status_code(ctx) == CTX_ACT_DROP);
	assert_metrics_count(key, 1);

	test_finish();
}

/* B3, L1-03: a natively decapsulated packet that was decrypted is
 * delivered, and the decrypt mark is cleared on the way.
 */
PKTGEN(PROG_TYPE, "geneve_wg_strict_native_decrypted_delivered")
int geneve_wg_strict_native_decrypted_delivered_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4(ctx);
}

SETUP(PROG_TYPE, "geneve_wg_strict_native_decrypted_delivered")
int geneve_wg_strict_native_decrypted_delivered_setup(struct __ctx_buff *ctx)
{
	metrics_del_entry((__u8)-DROP_UNENCRYPTED_TRAFFIC, METRIC_INGRESS);
	endpoint_v4_add_entry(LOCAL_POD_IP, LOCAL_POD_IFINDEX, LOCAL_POD_LXC_ID,
			      0, 0, 0, NULL, NULL);
	ctx->mark = MARK_MAGIC_DECRYPT;
	return enter_native(ctx);
}

CHECK(PROG_TYPE, "geneve_wg_strict_native_decrypted_delivered")
int geneve_wg_strict_native_decrypted_delivered_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = (__u8)-DROP_UNENCRYPTED_TRAFFIC,
		.dir = METRIC_INGRESS,
	};

	test_init();

	endpoint_v4_del_entry(LOCAL_POD_IP);

	assert(status_code(ctx) == CTX_ACT_OK);
	assert(!ctx_is_decrypt(ctx));
	assert_metrics_count(key, 0);

	test_finish();
}
