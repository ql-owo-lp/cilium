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
#define FRONTEND_IP		v4_svc_one
#define FRONTEND_IPV6		{ .addr = v6_svc_one_addr }
#define FRONTEND_PORT		tcp_svc_one

/* DSR option that the kernel tunnel device reports to cil_from_overlay. */
#define KERNEL_FRONTEND_IP	v4_svc_two

/* Service with a hostNetwork backend, and the backend that bpf_host's IPIP
 * termination would force (CB_FORCED_BACKEND_V4).
 */
#define LB_SVC_IP		v4_svc_three
#define LB_SVC_PORT		tcp_svc_two
#define HOST_BACKEND_IP		v4_node_two
#define FORCED_BACKEND_IP	v4_pod_two

#define CLIENT_IP		v4_ext_one
#define CLIENT_IPV6		{ .addr = v6_ext_node_one_addr }
#define CLIENT_PORT		tcp_src_one
#define CLIENT_PORT_2		tcp_src_two
#define CLIENT_PORT_3		tcp_src_three
#define CLIENT_SEC_IDENTITY	CIDR_IDENTITY_RANGE_START

#define BACKEND_IP		v4_pod_one
#define BACKEND_IPV6		{ .addr = v6_pod_one_addr }
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_SEC_IDENTITY	0x1122

#define TUNNEL_SRC_V4		v4_node_one
#define TUNNEL_DST_V4		v4_node_two

static __u32 redirect_ifindex;

/* Answers like bpf_fib_lookup() for a route with a preferred source, which
 * is only returned with BPF_FIB_LOOKUP_SRC.
 */
static __always_inline long
mock_fib_lookup(const void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags)
{
	const union v6addr v6_src = { .addr = v6_node_one_addr };

	params->ifindex = UPLINK_IFINDEX;
	if (flags & BPF_FIB_LOOKUP_SRC) {
		if (params->family == AF_INET)
			params->ipv4_src = TUNNEL_SRC_V4;
		else
			__bpf_memcpy_builtin(params->ipv6_src, &v6_src, sizeof(v6_src));
	}

	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_three, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_four, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#undef fib_lookup
#define fib_lookup mock_fib_lookup

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
	return CTX_ACT_REDIRECT;
}

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect
#undef redirect_neigh
#define redirect_neigh mock_redirect_neigh

static __always_inline int
mock_skb_get_tunnel_key(struct __sk_buff *skb, struct bpf_tunnel_key *to,
			__u32 size, __u32 flags);
static __always_inline int
mock_skb_get_tunnel_opt(struct __sk_buff *skb, void *opt, __u32 size);

#define skb_get_tunnel_key mock_skb_get_tunnel_key
#define skb_get_tunnel_opt mock_skb_get_tunnel_opt

#include "lib/bpf_overlay.h"
#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(bool, enable_ipip_termination, true)
/* U2, L1-08: the native DSR replies take their outer source from the route
 * (mock_fib_lookup()). There is no direct routing address, so without
 * BPF_FIB_LOOKUP_SRC they would fall back to the tunnel device.
 */
ASSIGN_CONFIG(bool, supports_fib_lookup_src, true)

static __always_inline int
mock_skb_get_tunnel_key(struct __sk_buff *skb __maybe_unused,
			struct bpf_tunnel_key *to, __u32 size __maybe_unused,
			__u32 flags __maybe_unused)
{
	to->tunnel_id = WORLD_IPV4_ID;
	return 0;
}

static __always_inline int
mock_skb_get_tunnel_opt(struct __sk_buff *skb __maybe_unused, void *opt,
			__u32 size)
{
	if (size != sizeof(struct geneve_dsr_opt4))
		return -ENOENT;
	set_geneve_dsr_opt4(FRONTEND_PORT, KERNEL_FRONTEND_IP, opt);
	return sizeof(struct geneve_dsr_opt4);
}

static __always_inline int
enter_native_from_overlay(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY);
	return TEST_ERROR;
}

static __always_inline int
pktgen_dsr_request_v4(struct __ctx_buff *ctx, __be16 client_port)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, BACKEND_IP,
					  client_port, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Stage the ingress slot and DECAP flag as tail_geneve_decap4() leaves them
 * for a DSR request to FRONTEND_IP.
 */
static __always_inline int
stage_dsr_slot_v4(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {};
	struct geneve_metadata *meta;

	set_geneve_dsr_opt4(FRONTEND_PORT, FRONTEND_IP, &dsr_opt);

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = WORLD_IPV4_ID;
	meta->family = AF_INET;
	meta->ip4.saddr = TUNNEL_SRC_V4;
	meta->ip4.daddr = TUNNEL_DST_V4;
	meta->opt_len = sizeof(dsr_opt);
	__bpf_memcpy_builtin(meta->raw_opts, &dsr_opt, sizeof(dsr_opt));

	ctx_bpf_geneve_decap_set(ctx);
	return 0;
}

/* The DSR request from CLIENT_IP:@client_port was accepted and created the
 * DSR CT entry for the reply with @frontend_ip as the service address.
 */
static __always_inline int
check_dsr_ingress_v4(const struct __ctx_buff *ctx, __be16 client_port,
		     __be32 frontend_ip)
{
	struct ipv4_ct_tuple expected_tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = client_port,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags   = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);

	ct_entry = map_lookup_elem(&cilium_ct4_global, &expected_tuple);
	if (!ct_entry)
		test_fatal("No DSR entry in cilium_ct4_global");

	assert(ct_entry->nat_addr.p4 == frontend_ip);
	assert(ct_entry->nat_port == FRONTEND_PORT);

	test_finish();
}

/* 1. Native Geneve DSR ingress (IPv4):
 * tail_geneve_from_overlay -> tail_handle_ipv4 -> nodeport_lb4 ->
 * geneve_get_tunnel_opt -> creates DSR CT entry in cilium_ct4_global.
 */
PKTGEN("tc", "01_geneve_overlay_native_dsr_ingress_v4")
int bpf_geneve_overlay_dsr_ingress_v4_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_dsr_request_v4(ctx, CLIENT_PORT);
}

SETUP("tc", "01_geneve_overlay_native_dsr_ingress_v4")
int bpf_geneve_overlay_dsr_ingress_v4_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_SEC_IDENTITY, 0, 0);

	if (stage_dsr_slot_v4(ctx))
		return TEST_ERROR;
	return enter_native_from_overlay(ctx);
}

CHECK("tc", "01_geneve_overlay_native_dsr_ingress_v4")
int bpf_geneve_overlay_dsr_ingress_v4_check(const struct __ctx_buff *ctx)
{
	return check_dsr_ingress_v4(ctx, CLIENT_PORT, FRONTEND_IP);
}

/* 2. Native Geneve DSR reply egress (IPv4):
 * __encap_and_redirect_with_nodeid -> tail_geneve_to_overlay ->
 * real tail_handle_nat_fwd_ipv4 (Rev-DNAT using cilium_ct4_global entry) ->
 * tail_geneve_encap4 -> redirects encapsulated Rev-DNATed packet to UPLINK_IFINDEX.
 */
PKTGEN("tc", "02_geneve_overlay_native_dsr_reply_egress_v4")
int bpf_geneve_overlay_dsr_reply_v4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_two, (__u8 *)mac_one,
					  BACKEND_IP, CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "02_geneve_overlay_native_dsr_reply_egress_v4")
int bpf_geneve_overlay_dsr_reply_v4_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip4.be32 = TUNNEL_DST_V4,
		.sec_identity = CLIENT_SEC_IDENTITY,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	redirect_ifindex = 0;
	return __encap_and_redirect_with_nodeid(ctx, &ep, BACKEND_SEC_IDENTITY,
						CLIENT_SEC_IDENTITY,
						NOT_VTEP_DST, &trace,
						bpf_htons(ETH_P_IP));
}

CHECK("tc", "02_geneve_overlay_native_dsr_reply_egress_v4")
int bpf_geneve_overlay_dsr_reply_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth, *inner_eth;
	struct iphdr *ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct tcphdr *inner_tcp;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_ifindex == UPLINK_IFINDEX);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	inner_eth = (void *)(geneve + 1);
	inner_ip4 = (void *)(inner_eth + 1);
	inner_tcp = (void *)(inner_ip4 + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("encapsulated reply headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == TUNNEL_SRC_V4);
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(geneve_hdr_vni(geneve) == BACKEND_SEC_IDENTITY);

	/* Verify Reverse-DNAT rewrote inner source IP:port to FRONTEND_IP:FRONTEND_PORT */
	assert(inner_ip4->saddr == FRONTEND_IP);
	assert(inner_ip4->daddr == CLIENT_IP);
	assert(inner_tcp->source == FRONTEND_PORT);
	assert(inner_tcp->dest == CLIENT_PORT);

	test_finish();
}

static __always_inline int
pktgen_dsr_request_v6(struct __ctx_buff *ctx, __be16 client_port)
{
	union v6addr client_ip = CLIENT_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)&client_ip, (__u8 *)&backend_ip,
					  client_port, BACKEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
setup_native_dsr_ingress_v6(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	struct geneve_dsr_opt6 dsr_opt = {};
	struct geneve_metadata *meta;

	endpoint_v6_add_entry(&backend_ip, 0, 0, 0, 0, NULL, NULL);
	ipcache_v6_add_entry(&client_ip, 0, CLIENT_SEC_IDENTITY, 0, 0);

	set_geneve_dsr_opt6(FRONTEND_PORT, &frontend_ip, &dsr_opt);

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = WORLD_IPV6_ID;
	meta->family = AF_INET6;
	meta->opt_len = sizeof(dsr_opt);
	__bpf_memcpy_builtin(meta->raw_opts, &dsr_opt, sizeof(dsr_opt));

	ctx_bpf_geneve_decap_set(ctx);
	return enter_native_from_overlay(ctx);
}

static __always_inline int
check_dsr_ingress_v6(const struct __ctx_buff *ctx, __be16 client_port)
{
	union v6addr frontend_ip = FRONTEND_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	union v6addr client_ip = CLIENT_IPV6;
	struct ipv6_ct_tuple expected_tuple = {
		.saddr   = backend_ip,
		.daddr   = client_ip,
		.sport   = client_port,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
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

	ct_entry = map_lookup_elem(&cilium_ct6_global, &expected_tuple);
	if (!ct_entry)
		test_fatal("No DSR entry in cilium_ct6_global");

	assert(ipv6_addr_equals(&ct_entry->nat_addr, &frontend_ip));
	assert(ct_entry->nat_port == FRONTEND_PORT);

	test_finish();
}

/* 3. Native Geneve DSR ingress (IPv6):
 * tail_geneve_from_overlay -> tail_handle_ipv6 -> nodeport_lb6 ->
 * geneve_get_tunnel_opt -> creates DSR CT entry in cilium_ct6_global.
 */
PKTGEN("tc", "03_geneve_overlay_native_dsr_ingress_v6")
int bpf_geneve_overlay_dsr_ingress_v6_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_dsr_request_v6(ctx, CLIENT_PORT);
}

SETUP("tc", "03_geneve_overlay_native_dsr_ingress_v6")
int bpf_geneve_overlay_dsr_ingress_v6_setup(struct __ctx_buff *ctx)
{
	return setup_native_dsr_ingress_v6(ctx);
}

CHECK("tc", "03_geneve_overlay_native_dsr_ingress_v6")
int bpf_geneve_overlay_dsr_ingress_v6_check(const struct __ctx_buff *ctx)
{
	return check_dsr_ingress_v6(ctx, CLIENT_PORT);
}

/* 4. Native Geneve DSR reply egress (IPv6, T-11):
 * __encap_and_redirect_with_nodeid -> tail_geneve_to_overlay ->
 * real tail_handle_nat_fwd_ipv6 (Rev-DNAT using cilium_ct6_global entry) ->
 * tail_geneve_encap6 -> redirects encapsulated Rev-DNATed packet to UPLINK_IFINDEX.
 */
PKTGEN("tc", "04_geneve_overlay_native_dsr_reply_egress_v6")
int bpf_geneve_overlay_dsr_reply_v6_pktgen(struct __ctx_buff *ctx)
{
	union v6addr client_ip = CLIENT_IPV6;
	union v6addr backend_ip = BACKEND_IPV6;
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_two, (__u8 *)mac_one,
					  (__u8 *)&backend_ip, (__u8 *)&client_ip,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "04_geneve_overlay_native_dsr_reply_egress_v6")
int bpf_geneve_overlay_dsr_reply_v6_setup(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info ep = {
		.tunnel_endpoint.ip6 = { .addr = v6_node_two_addr },
		.sec_identity = CLIENT_SEC_IDENTITY,
		.flag_ipv6_tunnel_ep = true,
	};
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};

	redirect_ifindex = 0;
	return __encap_and_redirect_with_nodeid(ctx, &ep, BACKEND_SEC_IDENTITY,
						CLIENT_SEC_IDENTITY,
						NOT_VTEP_DST, &trace,
						bpf_htons(ETH_P_IPV6));
}

CHECK("tc", "04_geneve_overlay_native_dsr_reply_egress_v6")
int bpf_geneve_overlay_dsr_reply_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_outer_src = { .addr = v6_node_one_addr };
	const union v6addr expected_outer_dst = { .addr = v6_node_two_addr };
	const union v6addr frontend_ip = FRONTEND_IPV6;
	const union v6addr client_ip = CLIENT_IPV6;
	void *data, *data_end;
	struct ethhdr *eth, *inner_eth;
	struct ipv6hdr *ip6, *inner_ip6;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct tcphdr *inner_tcp;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);
	assert(redirect_ifindex == UPLINK_IFINDEX);

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	udp = (void *)(ip6 + 1);
	geneve = (void *)(udp + 1);
	inner_eth = (void *)(geneve + 1);
	inner_ip6 = (void *)(inner_eth + 1);
	inner_tcp = (void *)(inner_ip6 + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("encapsulated v6 reply headers out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_outer_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_outer_dst));
	assert(geneve_hdr_vni(geneve) == BACKEND_SEC_IDENTITY);

	/* Verify Reverse-DNAT rewrote inner IPv6 source IP:port to FRONTEND_IPV6:FRONTEND_PORT */
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->saddr, &frontend_ip));
	assert(ipv6_addr_equals((union v6addr *)&inner_ip6->daddr, &client_ip));
	assert(inner_tcp->source == FRONTEND_PORT);
	assert(inner_tcp->dest == CLIENT_PORT);

	test_finish();
}

/* 5. Native overlay ingress security checks:
 * VNI == HOST_ID is rejected with CTX_ACT_DROP (DROP_INVALID_IDENTITY).
 */
PKTGEN("tc", "05_geneve_overlay_native_ingress_host_id_drop")
int bpf_geneve_overlay_host_id_drop_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_overlay_dsr_ingress_v4_pktgen(ctx);
}

SETUP("tc", "05_geneve_overlay_native_ingress_host_id_drop")
int bpf_geneve_overlay_host_id_drop_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = HOST_ID;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.saddr = TUNNEL_SRC_V4;
	meta->ip4.daddr = TUNNEL_DST_V4;

	ctx_bpf_geneve_decap_set(ctx);
	return enter_native_from_overlay(ctx);
}

CHECK("tc", "05_geneve_overlay_native_ingress_host_id_drop")
int bpf_geneve_overlay_host_id_drop_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

/* 6. B3, L1-03: cil_from_netdev sets the skip-nodeport flag when XDP found
 * no service for the outer packet (XFER_PKT_NO_SVC). The native entry clears
 * it like cil_from_overlay, so the inner DSR request still gets its CT
 * entry. Sibling of 1, with its own flow.
 */
PKTGEN("tc", "06_geneve_overlay_native_dsr_ingress_v4_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v4_skip_nodeport_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_dsr_request_v4(ctx, CLIENT_PORT_2);
}

SETUP("tc", "06_geneve_overlay_native_dsr_ingress_v4_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v4_skip_nodeport_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);

	if (stage_dsr_slot_v4(ctx))
		return TEST_ERROR;
	ctx_skip_nodeport_set(ctx);
	return enter_native_from_overlay(ctx);
}

CHECK("tc", "06_geneve_overlay_native_dsr_ingress_v4_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v4_skip_nodeport_check(const struct __ctx_buff *ctx)
{
	return check_dsr_ingress_v4(ctx, CLIENT_PORT_2, FRONTEND_IP);
}

/* 7. B3, L1-03: as 6, for IPv6 (sibling of 3). */
PKTGEN("tc", "07_geneve_overlay_native_dsr_ingress_v6_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v6_skip_nodeport_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_dsr_request_v6(ctx, CLIENT_PORT_2);
}

SETUP("tc", "07_geneve_overlay_native_dsr_ingress_v6_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v6_skip_nodeport_setup(struct __ctx_buff *ctx)
{
	ctx_skip_nodeport_set(ctx);
	return setup_native_dsr_ingress_v6(ctx);
}

CHECK("tc", "07_geneve_overlay_native_dsr_ingress_v6_skip_nodeport")
int bpf_geneve_overlay_dsr_ingress_v6_skip_nodeport_check(const struct __ctx_buff *ctx)
{
	return check_dsr_ingress_v6(ctx, CLIENT_PORT_2);
}

/* 8. B3, L1-03: the native entry starts from clean skb->cb[], like
 * cil_from_overlay. bpf_host's IPIP termination runs before the Geneve
 * intercept and leaves CB_FORCED_BACKEND_V4 set for a Geneve packet received
 * in IPIP; consumed by nodeport_svc_lb4(), it would bypass the backend
 * selection of the inner service request.
 */
PKTGEN("tc", "08_geneve_overlay_native_ingress_stale_cb_cleared")
int bpf_geneve_overlay_native_ingress_stale_cb_cleared_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  CLIENT_IP, LB_SVC_IP,
					  CLIENT_PORT, LB_SVC_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "08_geneve_overlay_native_ingress_stale_cb_cleared")
int bpf_geneve_overlay_native_ingress_stale_cb_cleared_setup(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	lb_v4_add_service(LB_SVC_IP, LB_SVC_PORT, IPPROTO_TCP, 1, 1);
	lb_v4_add_backend(LB_SVC_IP, LB_SVC_PORT, 1, 124, HOST_BACKEND_IP,
			  BACKEND_PORT, IPPROTO_TCP, 0);
	endpoint_v4_add_entry(HOST_BACKEND_IP, 0, 0, ENDPOINT_F_HOST, 0, 0,
			      NULL, NULL);

	if (!meta)
		return TEST_ERROR;
	meta->magic = GENEVE_META_MAGIC;
	meta->vni = WORLD_IPV4_ID;
	meta->family = AF_INET;
	meta->opt_len = 0;
	meta->ip4.saddr = TUNNEL_SRC_V4;
	meta->ip4.daddr = TUNNEL_DST_V4;
	ctx_bpf_geneve_decap_set(ctx);

	ctx_store_meta(ctx, CB_FORCED_BACKEND_V4, FORCED_BACKEND_IP);
	redirect_ifindex = 0;
	return enter_native_from_overlay(ctx);
}

CHECK("tc", "08_geneve_overlay_native_ingress_stale_cb_cleared")
int bpf_geneve_overlay_native_ingress_stale_cb_cleared_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct tcphdr *l4;
	__u32 *status_code;

	test_init();

	endpoint_v4_del_entry(HOST_BACKEND_IP);

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	ip4 = data + sizeof(*status_code) + sizeof(struct ethhdr);
	l4 = (void *)(ip4 + 1);
	if ((void *)(l4 + 1) > data_end)
		test_fatal("headers out of bounds");

	/* DNATed to the selected backend and delivered to the host */
	assert(*status_code == CTX_ACT_REDIRECT);
	assert(ip4->daddr == HOST_BACKEND_IP);
	assert(l4->dest == BACKEND_PORT);

	test_finish();
}

/* 9. B4, L1-04, L2-09: cil_from_overlay takes the DSR option from the kernel
 * tunnel device, not from a valid slot and DECAP flag left behind by an
 * earlier natively decapsulated packet.
 */
PKTGEN("tc", "09_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot")
int bpf_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_dsr_request_v4(ctx, CLIENT_PORT_3);
}

SETUP("tc", "09_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot")
int bpf_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot_setup(struct __ctx_buff *ctx)
{
	endpoint_v4_add_entry(BACKEND_IP, 0, 0, 0, 0, 0, NULL, NULL);

	if (stage_dsr_slot_v4(ctx))
		return TEST_ERROR;
	return overlay_receive_packet(ctx);
}

CHECK("tc", "09_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot")
int bpf_geneve_overlay_kernel_dsr_ingress_ignores_stale_slot_check(const struct __ctx_buff *ctx)
{
	return check_dsr_ingress_v4(ctx, CLIENT_PORT_3, KERNEL_FRONTEND_IP);
}
