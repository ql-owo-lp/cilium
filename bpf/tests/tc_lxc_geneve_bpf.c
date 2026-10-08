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
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_GENEVE	3
#define DSR_ENCAP_MODE		DSR_ENCAP_GENEVE
#define ENABLE_ROUTING		1

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(union macaddr, interface_mac, { .addr = mac_one_addr })
ASSIGN_CONFIG(__u32, security_label, 0x1122)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "nodeport_defaults.h"

#define REMOTE_POD_ID	0x3344
#define TUNNEL_DST_V4	v4_node_two

static __u32 to_overlay_reached;
static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static __be32 observed_daddr4;
static union v6addr observed_daddr6;
static struct geneve_dsr_opt4 observed_dsr4;
static struct geneve_dsr_opt6 observed_dsr6;

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
		if (meta->opt_len == sizeof(observed_dsr4))
			__bpf_memcpy_builtin(&observed_dsr4, meta->raw_opts,
					     sizeof(observed_dsr4));
		if (meta->opt_len == sizeof(observed_dsr6))
			__bpf_memcpy_builtin(&observed_dsr6, meta->raw_opts,
					     sizeof(observed_dsr6));
	}
	return CTX_ACT_OK;
}

static __always_inline void
reset_lxc_obs(void)
{
	to_overlay_reached = 0;
	observed_magic = 0;
	observed_vni = 0;
	observed_family = 0;
	observed_opt_len = 0;
	observed_daddr4 = 0;
	__bpf_memzero(&observed_daddr6, sizeof(observed_daddr6));
	__bpf_memzero(&observed_dsr4, sizeof(observed_dsr4));
	__bpf_memzero(&observed_dsr6, sizeof(observed_dsr6));
}

/* 1. Pod egress (IPv4 inner -> IPv4 tunnel endpoint) stages cilium_geneve_meta[GENEVE_META_EGRESS]
 * and tail-calls cilium_calls_bpf_overlay[GENEVE_CALL_TO_OVERLAY].
 */
PKTGEN("tc", "01_lxc_to_overlay_geneve_bpf_v4")
int tc_lxc_to_overlay_geneve_bpf_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "01_lxc_to_overlay_geneve_bpf_v4")
int tc_lxc_to_overlay_geneve_bpf_v4_setup(struct __ctx_buff *ctx)
{
	reset_lxc_obs();
	policy_add_egress_allow_all_entry();
	ipcache_v4_add_entry(v4_pod_two, 0, REMOTE_POD_ID, TUNNEL_DST_V4, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "01_lxc_to_overlay_geneve_bpf_v4")
int tc_lxc_to_overlay_geneve_bpf_v4_check(const struct __ctx_buff *ctx)
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
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == CONFIG(security_label));
	assert(observed_family == AF_INET);
	assert(observed_daddr4 == TUNNEL_DST_V4);
	assert(observed_opt_len == 0);

	test_finish();
}

/* 2. Pod egress (IPv6 inner -> IPv6 tunnel endpoint) stages cilium_geneve_meta[GENEVE_META_EGRESS]
 * and tail-calls cilium_calls_bpf_overlay[GENEVE_CALL_TO_OVERLAY].
 */
PKTGEN("tc", "02_lxc_to_overlay_geneve_bpf_v6")
int tc_lxc_to_overlay_geneve_bpf_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "02_lxc_to_overlay_geneve_bpf_v6")
int tc_lxc_to_overlay_geneve_bpf_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr dst_pod = { .addr = v6_pod_two_addr };
	const union v6addr tunnel_ep = { .addr = v6_node_two_addr };

	reset_lxc_obs();
	policy_add_egress_allow_all_entry();
	ipcache_v6_add_entry_with_mask_size_ipv6_underlay(&dst_pod, 0,
							  REMOTE_POD_ID,
							  &tunnel_ep, 0, 128);

	return pod_send_packet(ctx);
}

CHECK("tc", "02_lxc_to_overlay_geneve_bpf_v6")
int tc_lxc_to_overlay_geneve_bpf_v6_check(const struct __ctx_buff *ctx)
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
	assert(observed_vni == CONFIG(security_label));
	assert(observed_family == AF_INET6);
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));
	assert(observed_opt_len == 0);

	test_finish();
}

/* 3. nodeport_add_tunnel_encap_opt (IPv4 DSR option) in bpf_lxc stages DSR TLV
 * in cilium_geneve_meta[GENEVE_META_EGRESS] and tail-calls GENEVE_CALL_TO_OVERLAY.
 */
PKTGEN("tc", "03_lxc_dsr_geneve_bpf_v4")
int tc_lxc_dsr_geneve_bpf_v4_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v4_pktgen(ctx);
}

SETUP("tc", "03_lxc_dsr_geneve_bpf_v4")
int tc_lxc_dsr_geneve_bpf_v4_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = REMOTE_POD_ID,
	};
	struct geneve_dsr_opt4 dsr_opt = {};
	int ifindex = 0;

	reset_lxc_obs();
	set_geneve_dsr_opt4(tcp_svc_one, v4_svc_one, &dsr_opt);

	return nodeport_add_tunnel_encap_opt(ctx, v4_pod_one, tcp_src_one, &ep,
					     CONFIG(security_label), &dsr_opt,
					     sizeof(dsr_opt),
					     TRACE_REASON_UNKNOWN,
					     TRACE_PAYLOAD_LEN, &ifindex,
					     bpf_htons(ETH_P_IP));
}

CHECK("tc", "03_lxc_dsr_geneve_bpf_v4")
int tc_lxc_dsr_geneve_bpf_v4_check(const struct __ctx_buff *ctx)
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
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == CONFIG(security_label));
	assert(observed_family == AF_INET);
	assert(observed_daddr4 == TUNNEL_DST_V4);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt4));
	assert(observed_dsr4.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(observed_dsr4.hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(observed_dsr4.addr == v4_svc_one);
	assert(observed_dsr4.port == tcp_svc_one);

	test_finish();
}

/* 4. nodeport_add_tunnel_encap_opt (IPv6 DSR option) in bpf_lxc stages DSR TLV
 * in cilium_geneve_meta[GENEVE_META_EGRESS] and tail-calls GENEVE_CALL_TO_OVERLAY.
 */
PKTGEN("tc", "04_lxc_dsr_geneve_bpf_v6")
int tc_lxc_dsr_geneve_bpf_v6_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v6_pktgen(ctx);
}

SETUP("tc", "04_lxc_dsr_geneve_bpf_v6")
int tc_lxc_dsr_geneve_bpf_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr svc_ip = { .addr = v6_svc_one_addr };
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.sec_identity = REMOTE_POD_ID,
		.flag_ipv6_tunnel_ep = true,
	};
	struct geneve_dsr_opt6 dsr_opt = {};
	int ifindex = 0;

	reset_lxc_obs();
	set_geneve_dsr_opt6(tcp_svc_one, &svc_ip, &dsr_opt);

	return nodeport_add_tunnel_encap_opt(ctx, 0, tcp_src_one, &ep,
					     CONFIG(security_label), &dsr_opt,
					     sizeof(dsr_opt),
					     TRACE_REASON_UNKNOWN,
					     TRACE_PAYLOAD_LEN, &ifindex,
					     bpf_htons(ETH_P_IPV6));
}

CHECK("tc", "04_lxc_dsr_geneve_bpf_v6")
int tc_lxc_dsr_geneve_bpf_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	const union v6addr expected_svc = { .addr = v6_svc_one_addr };
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
	assert(observed_vni == CONFIG(security_label));
	assert(observed_family == AF_INET6);
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt6));
	assert(observed_dsr6.hdr.opt_class == bpf_htons(DSR_GENEVE_OPT_CLASS));
	assert(observed_dsr6.hdr.type == DSR_GENEVE_OPT_TYPE);
	assert(ipv6_addr_equals((const union v6addr *)&observed_dsr6.addr, &expected_svc));
	assert(observed_dsr6.port == tcp_svc_one);

	test_finish();
}

/* A packet to TUNNEL_DST_V4 staged with the source identity as VNI and
 * without options.
 */
#define check_staged_v4_no_opts(ctx)					\
do {									\
	void *__data = (void *)(long)ctx_data(ctx);			\
	void *__data_end = (void *)(long)(ctx)->data_end;		\
									\
	if (__data + sizeof(__u32) > __data_end)			\
		test_fatal("status code out of bounds");		\
	assert(*(__u32 *)__data == CTX_ACT_OK);				\
	assert(to_overlay_reached == 1);				\
	assert(observed_magic == GENEVE_META_MAGIC);			\
	assert(observed_vni == CONFIG(security_label));			\
	assert(observed_family == AF_INET);				\
	assert(observed_daddr4 == TUNNEL_DST_V4);			\
	assert(observed_opt_len == 0);					\
} while (0)

/* 5. Same VNI selection as ctx_set_encap_info4(): without VTEP integration
 * a VTEP VNI is ignored (see bpf_geneve_egress_lxc_vtep.c for VTEPs).
 */
PKTGEN("tc", "05_lxc_geneve_bpf_vtep_vni_ignored")
int tc_lxc_geneve_bpf_vtep_vni_ignored_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v4_pktgen(ctx);
}

SETUP("tc", "05_lxc_geneve_bpf_vtep_vni_ignored")
int tc_lxc_geneve_bpf_vtep_vni_ignored_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = REMOTE_POD_ID,
	};

	reset_lxc_obs();
	return geneve_encap_and_redirect(ctx, &ep, CONFIG(security_label),
					 WORLD_IPV4_ID, NULL, 0);
}

CHECK("tc", "05_lxc_geneve_bpf_vtep_vni_ignored")
int tc_lxc_geneve_bpf_vtep_vni_ignored_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4_no_opts(ctx);

	test_finish();
}

/* L2-07: leave the egress slot valid, with a DSR TLV and an IPv6 tunnel
 * endpoint, as an earlier packet would.
 */
static __always_inline int
fill_stale_egress_slot(void)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	const union v6addr stale_dst = { .addr = v6_node_three_addr };
	struct geneve_dsr_opt6 stale_opt = {};

	if (!meta)
		return -1;
	set_geneve_dsr_opt6(tcp_svc_two, &stale_dst, &stale_opt);
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = REMOTE_POD_ID;
	meta->family = AF_INET6;
	meta->opt_len = sizeof(stale_opt);
	meta->ip6.daddr = stale_dst;
	__bpf_memcpy_builtin(meta->raw_opts, &stale_opt, sizeof(stale_opt));
	return 0;
}

/* 6. Staging a packet without options over a stale slot (L2-07). */
PKTGEN("tc", "06_lxc_geneve_bpf_stale_slot")
int tc_lxc_geneve_bpf_stale_slot_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v4_pktgen(ctx);
}

SETUP("tc", "06_lxc_geneve_bpf_stale_slot")
int tc_lxc_geneve_bpf_stale_slot_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = REMOTE_POD_ID,
	};

	reset_lxc_obs();
	if (fill_stale_egress_slot())
		return TEST_ERROR;

	return geneve_encap_and_redirect(ctx, &ep, CONFIG(security_label),
					 NOT_VTEP_DST, NULL, 0);
}

CHECK("tc", "06_lxc_geneve_bpf_stale_slot")
int tc_lxc_geneve_bpf_stale_slot_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4_no_opts(ctx);

	test_finish();
}

/* 7. The same for pod egress (L2-07). */
PKTGEN("tc", "07_lxc_to_overlay_geneve_bpf_stale_slot")
int tc_lxc_to_overlay_geneve_bpf_stale_slot_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v4_pktgen(ctx);
}

SETUP("tc", "07_lxc_to_overlay_geneve_bpf_stale_slot")
int tc_lxc_to_overlay_geneve_bpf_stale_slot_setup(struct __ctx_buff *ctx)
{
	reset_lxc_obs();
	policy_add_egress_allow_all_entry();
	ipcache_v4_add_entry(v4_pod_two, 0, REMOTE_POD_ID, TUNNEL_DST_V4, 0);
	if (fill_stale_egress_slot())
		return TEST_ERROR;

	return pod_send_packet(ctx);
}

CHECK("tc", "07_lxc_to_overlay_geneve_bpf_stale_slot")
int tc_lxc_to_overlay_geneve_bpf_stale_slot_check(const struct __ctx_buff *ctx)
{
	test_init();

	check_staged_v4_no_opts(ctx);

	test_finish();
}

/* 8. D17(2): in a remote_endpoint_info on the stack, like bpf_lxc's
 * fake_info, an IPv6 tunnel endpoint can be 4 but not 8 byte aligned, and
 * the verifier rejects misaligned stack loads. It is filled from the packet
 * so that it stays on the stack.
 */
PKTGEN("tc", "08_lxc_geneve_bpf_v6_stack_endpoint")
int tc_lxc_geneve_bpf_v6_stack_endpoint_pktgen(struct __ctx_buff *ctx)
{
	return tc_lxc_to_overlay_geneve_bpf_v6_pktgen(ctx);
}

SETUP("tc", "08_lxc_geneve_bpf_v6_stack_endpoint")
int tc_lxc_geneve_bpf_v6_stack_endpoint_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep __aligned(8) = {
		.sec_identity = REMOTE_POD_ID,
		.flag_has_tunnel_ep = true,
		.flag_ipv6_tunnel_ep = true,
	};

	reset_lxc_obs();
	if (ctx_load_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			   &ep.tunnel_endpoint.ip6, sizeof(ep.tunnel_endpoint.ip6)) < 0)
		return TEST_ERROR;

	return geneve_encap_and_redirect(ctx, &ep, CONFIG(security_label),
					 NOT_VTEP_DST, NULL, 0);
}

CHECK("tc", "08_lxc_geneve_bpf_v6_stack_endpoint")
int tc_lxc_geneve_bpf_v6_stack_endpoint_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_pod_two_addr };
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
	assert(observed_vni == CONFIG(security_label));
	assert(observed_family == AF_INET6);
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));
	assert(observed_opt_len == 0);

	test_finish();
}
