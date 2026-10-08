// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* VNI staged by the native Geneve egress path with VTEP integration
 * enabled: as in ctx_set_encap_info4(), the VTEP VNI for an IPv4 tunnel
 * endpoint when one is given, the source identity otherwise, and always the
 * source identity for an IPv6 tunnel endpoint as in ctx_set_encap_info6().
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_ROUTING		1

#include "lib/bpf_lxc.h"

#define TEST_SECLABEL		0x1122
#define VTEP_DST_IP		v4_ext_one
#define VTEP_CIDR		IPV4(110, 0, 11, 0)
#define VTEP_ENDPOINT		v4_ext_two

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(__u32, security_label, TEST_SECLABEL)
ASSIGN_CONFIG(bool, enable_vtep, true)
ASSIGN_CONFIG(__u32, vtep_mask, IPV4(255, 255, 255, 0))

#include "lib/policy.h"

static __u32 to_overlay_reached;
static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static __be32 observed_daddr4;
static union v6addr observed_daddr6;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY)
int test_to_overlay_receiver(struct __ctx_buff *ctx __maybe_unused)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	to_overlay_reached = 1;
	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_daddr4 = meta->ip4.daddr;
		observed_daddr6 = meta->ip6.daddr;
	}
	return CTX_ACT_OK;
}

static __always_inline void
reset_obs(void)
{
	to_overlay_reached = 0;
	observed_magic = 0;
	observed_vni = 0;
	observed_family = 0;
	observed_opt_len = 0;
	observed_daddr4 = 0;
	__bpf_memzero(&observed_daddr6, sizeof(observed_daddr6));
}

static __always_inline int
build_packet(struct __ctx_buff *ctx, __be32 daddr)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, daddr,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Stage directly, as __encap_with_nodeid() does, and return the verdict of
 * the receiver.
 */
static __always_inline int
stage_v4(struct __ctx_buff *ctx, __u32 vni)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = VTEP_ENDPOINT,
		.flag_has_tunnel_ep = true,
	};

	reset_obs();
	return geneve_encap_and_redirect(ctx, &ep, TEST_SECLABEL, vni, NULL, 0);
}

#define check_staged_v4(ctx, vni)					\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
									\
	if (__data + sizeof(__u32) > __data_end)			\
		test_fatal("status code out of bounds");		\
	assert(*(__u32 *)__data == CTX_ACT_OK);				\
	assert(to_overlay_reached == 1);				\
	assert(observed_magic == GENEVE_META_MAGIC);			\
	assert(observed_vni == (vni));					\
	assert(observed_family == AF_INET);				\
	assert(observed_daddr4 == VTEP_ENDPOINT);			\
	assert(observed_opt_len == 0);					\
} while (0)

/* bpf_lxc sends a packet to a VTEP with the VTEP VNI (WORLD_IPV4_ID). */
PKTGEN("tc", "geneve_lxc_vtep_to_overlay")
int geneve_lxc_vtep_to_overlay_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, VTEP_DST_IP);
}

SETUP("tc", "geneve_lxc_vtep_to_overlay")
int geneve_lxc_vtep_to_overlay_setup(struct __ctx_buff *ctx)
{
	struct vtep_key key = { .vtep_ip = VTEP_CIDR };
	struct vtep_value value = {
		.vtep_mac.addr = mac_five_addr,
		.tunnel_endpoint = VTEP_ENDPOINT,
	};

	reset_obs();
	if (map_update_elem(&cilium_vtep_map, &key, &value, BPF_ANY))
		return TEST_ERROR;
	policy_add_egress_allow_all_entry();

	return pod_send_packet(ctx);
}

CHECK("tc", "geneve_lxc_vtep_to_overlay")
int geneve_lxc_vtep_to_overlay_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4(ctx, get_tunnel_id(WORLD_IPV4_ID));

	test_finish();
}

/* A VTEP VNI given for an IPv4 tunnel endpoint is staged. */
PKTGEN("tc", "geneve_lxc_vtep_vni_v4")
int geneve_lxc_vtep_vni_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, VTEP_DST_IP);
}

SETUP("tc", "geneve_lxc_vtep_vni_v4")
int geneve_lxc_vtep_vni_v4_setup(struct __ctx_buff *ctx)
{
	return stage_v4(ctx, WORLD_IPV4_ID);
}

CHECK("tc", "geneve_lxc_vtep_vni_v4")
int geneve_lxc_vtep_vni_v4_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4(ctx, get_tunnel_id(WORLD_IPV4_ID));

	test_finish();
}

/* Without one (NOT_VTEP_DST), the source identity is staged. */
PKTGEN("tc", "geneve_lxc_vtep_not_vtep_dst")
int geneve_lxc_vtep_not_vtep_dst_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, v4_pod_two);
}

SETUP("tc", "geneve_lxc_vtep_not_vtep_dst")
int geneve_lxc_vtep_not_vtep_dst_setup(struct __ctx_buff *ctx)
{
	return stage_v4(ctx, NOT_VTEP_DST);
}

CHECK("tc", "geneve_lxc_vtep_not_vtep_dst")
int geneve_lxc_vtep_not_vtep_dst_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4(ctx, TEST_SECLABEL);

	test_finish();
}

/* An IPv6 tunnel endpoint never takes the VTEP VNI. */
PKTGEN("tc", "geneve_lxc_vtep_vni_v6")
int geneve_lxc_vtep_vni_v6_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, VTEP_DST_IP);
}

SETUP("tc", "geneve_lxc_vtep_vni_v6")
int geneve_lxc_vtep_vni_v6_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.flag_has_tunnel_ep = true,
		.flag_ipv6_tunnel_ep = true,
	};

	reset_obs();
	return geneve_encap_and_redirect(ctx, &ep, TEST_SECLABEL, WORLD_IPV4_ID,
					 NULL, 0);
}

CHECK("tc", "geneve_lxc_vtep_vni_v6")
int geneve_lxc_vtep_vni_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
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
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_SECLABEL);
	assert(observed_family == AF_INET6);
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));
	assert(observed_opt_len == 0);

	test_finish();
}
