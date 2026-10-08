// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* B2: cil_to_netdev must handle natively encapsulated Geneve packets the way
 * it handles packets coming out of the kernel tunnel device. The packets
 * arrive as tail_geneve_encap4/6() emit them, an outer node-to-node packet
 * from the node address, carrying the MARK_MAGIC_OVERLAY | identity mark
 * that handle_to_overlay() sets. With BPF masquerading the mark is what
 * keeps the outer flow out of handle_nat_fwd(): host traffic from the
 * masquerade address with a source port in the NAT range would otherwise
 * be tracked in CT and the SNAT map (and port-SNATed on a collision).
 *
 * The outer source port is fixed at 50000, in the NAT range 32768-65535
 * (nodeport_defaults.h). geneve_src_port() picks it from all of 1-65535,
 * so about half of all flows fall into that range.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_NODEPORT		1
#define ENABLE_MASQUERADE_IPV4	1
#define ENABLE_MASQUERADE_IPV6	1

#define SRC_NODE_V4		v4_node_one
#define DST_NODE_V4		v4_node_two
#define SRC_POD_V4		v4_pod_one
#define DST_POD_V4		v4_pod_one_on_node_two
#define SRC_POD_SEC_IDENTITY	0x1234
#define GENEVE_SPORT		bpf_htons(50000)
#define GENEVE_DPORT		bpf_htons(6081)

#include "nodeport_defaults.h"

#include "lib/bpf_host.h"
#include "lib/endpoint.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, nat_ipv4_masquerade, { .be32 = SRC_NODE_V4 })
ASSIGN_CONFIG(union v6addr, nat_ipv6_masquerade, { .addr = v6_node_one_addr })

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

/* The CT entry BPF masquerading creates for the outer flow (laid out as in
 * host_bpf_masq.h) and the SNAT entry for it.
 */
static __always_inline void
outer_tuples_v4(struct ipv4_ct_tuple *ct_tuple, struct ipv4_ct_tuple *snat_tuple)
{
	ct_tuple->daddr = SRC_NODE_V4;
	ct_tuple->saddr = DST_NODE_V4;
	ct_tuple->dport = GENEVE_DPORT;
	ct_tuple->sport = GENEVE_SPORT;
	ct_tuple->nexthdr = IPPROTO_UDP;
	ct_tuple->flags = TUPLE_F_OUT;

	snat_tuple->daddr = DST_NODE_V4;
	snat_tuple->saddr = SRC_NODE_V4;
	snat_tuple->dport = GENEVE_DPORT;
	snat_tuple->sport = GENEVE_SPORT;
	snat_tuple->nexthdr = IPPROTO_UDP;
	snat_tuple->flags = NAT_DIR_EGRESS;
}

static __always_inline void
outer_tuples_v6(struct ipv6_ct_tuple *ct_tuple, struct ipv6_ct_tuple *snat_tuple)
{
	ipv6_addr_copy(&ct_tuple->daddr, (union v6addr *)v6_node_one);
	ipv6_addr_copy(&ct_tuple->saddr, (union v6addr *)v6_node_two);
	ct_tuple->dport = GENEVE_DPORT;
	ct_tuple->sport = GENEVE_SPORT;
	ct_tuple->nexthdr = IPPROTO_UDP;
	ct_tuple->flags = TUPLE_F_OUT;

	ipv6_addr_copy(&snat_tuple->daddr, (union v6addr *)v6_node_two);
	ipv6_addr_copy(&snat_tuple->saddr, (union v6addr *)v6_node_one);
	snat_tuple->dport = GENEVE_DPORT;
	snat_tuple->sport = GENEVE_SPORT;
	snat_tuple->nexthdr = IPPROTO_UDP;
	snat_tuple->flags = NAT_DIR_EGRESS;
}

/* Install the host endpoint for the node addresses, drop the state an
 * earlier subtest may have left for the outer flow, encapsulate as
 * tail_geneve_encap4/6() do (VNI = source identity, no TLVs), mark the
 * packet as handle_to_overlay() does if @overlay_mark and send it to
 * cil_to_netdev.
 */
static __always_inline int
send_geneve_packet(struct __ctx_buff *ctx, bool ipv6_underlay, bool overlay_mark)
{
	int ret;

	if (ipv6_underlay) {
		struct ipv6_ct_tuple ct_tuple __align_stack_8 = {};
		struct ipv6_ct_tuple snat_tuple __align_stack_8 = {};

		endpoint_v6_add_entry((union v6addr *)v6_node_one, 0, 0,
				      ENDPOINT_F_HOST, HOST_ID,
				      (__u8 *)mac_one, (__u8 *)mac_one);
		outer_tuples_v6(&ct_tuple, &snat_tuple);
		map_delete_elem(get_ct_map6(&ct_tuple), &ct_tuple);
		map_delete_elem(&cilium_snat_v6_external, &snat_tuple);

		ret = geneve_encap6(ctx, (union v6addr *)v6_node_one,
				    (union v6addr *)v6_node_two,
				    SRC_POD_SEC_IDENTITY, GENEVE_SPORT, NULL, 0);
	} else {
		struct ipv4_ct_tuple ct_tuple = {}, snat_tuple = {};

		endpoint_v4_add_entry(SRC_NODE_V4, 0, 0, ENDPOINT_F_HOST, HOST_ID,
				      0, (__u8 *)mac_one, (__u8 *)mac_one);
		outer_tuples_v4(&ct_tuple, &snat_tuple);
		map_delete_elem(get_ct_map4(&ct_tuple), &ct_tuple);
		map_delete_elem(&cilium_snat_v4_external, &snat_tuple);

		ret = geneve_encap4(ctx, SRC_NODE_V4, DST_NODE_V4,
				    SRC_POD_SEC_IDENTITY, GENEVE_SPORT, NULL, 0);
	}
	if (ret < 0)
		return ret;

	if (overlay_mark)
		set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);
	else
		ctx->mark = 0;

	return netdev_send_packet(ctx);
}

/* Returns the outer UDP header of the packet in @ctx (behind the status
 * code), or NULL if it is out of bounds.
 */
static __always_inline struct udphdr *
outer_udp(const struct __ctx_buff *ctx, bool ipv6_underlay)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *l4;

	l4 = data + sizeof(__u32) + ETH_HLEN +
	     (ipv6_underlay ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
	if ((void *)(l4 + 1) > data_end)
		return NULL;
	return l4;
}

static __always_inline int
check_geneve_packet(const struct __ctx_buff *ctx, bool ipv6_underlay, bool overlay_mark)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	void *ct_entry, *snat_entry;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == CTX_ACT_OK);

	l4 = outer_udp(ctx, ipv6_underlay);
	if (!l4)
		test_fatal("outer headers out of bounds");
	/* Not port-SNATed in either case. */
	assert(l4->source == GENEVE_SPORT);
	assert(l4->dest == GENEVE_DPORT);

	if (ipv6_underlay) {
		struct ipv6_ct_tuple ct_tuple __align_stack_8 = {};
		struct ipv6_ct_tuple snat_tuple __align_stack_8 = {};

		outer_tuples_v6(&ct_tuple, &snat_tuple);
		ct_entry = map_lookup_elem(get_ct_map6(&ct_tuple), &ct_tuple);
		snat_entry = snat_v6_lookup(&snat_tuple);
	} else {
		struct ipv4_ct_tuple ct_tuple = {}, snat_tuple = {};

		outer_tuples_v4(&ct_tuple, &snat_tuple);
		ct_entry = map_lookup_elem(get_ct_map4(&ct_tuple), &ct_tuple);
		snat_entry = snat_v4_lookup(&snat_tuple);
	}

	if (overlay_mark) {
		/* handle_nat_fwd() skipped: no state, mark untouched. */
		assert(!ct_entry);
		assert(!snat_entry);
		assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
		assert(get_identity(ctx) == SRC_POD_SEC_IDENTITY);
	} else {
		/* Tracked as a masqueraded host connection. */
		assert(ct_entry);
		assert(snat_entry);
		assert(ctx_snat_done(ctx));
	}

	test_finish();
}

/* B2: the marked outer IPv4 packet bypasses BPF masquerading. */
PKTGEN("tc", "geneve_snat_v4_overlay_mark_skipped")
int geneve_snat_v4_overlay_mark_skipped_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_snat_v4_overlay_mark_skipped")
int geneve_snat_v4_overlay_mark_skipped_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false, true);
}

CHECK("tc", "geneve_snat_v4_overlay_mark_skipped")
int geneve_snat_v4_overlay_mark_skipped_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, false, true);
}

/* B2 contrast: without the mark the outer IPv4 flow gets CT and SNAT
 * entries.
 */
PKTGEN("tc", "geneve_snat_v4_no_mark_tracked")
int geneve_snat_v4_no_mark_tracked_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_snat_v4_no_mark_tracked")
int geneve_snat_v4_no_mark_tracked_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false, false);
}

CHECK("tc", "geneve_snat_v4_no_mark_tracked")
int geneve_snat_v4_no_mark_tracked_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, false, false);
}

/* B2: the marked outer IPv6 packet bypasses BPF masquerading. */
PKTGEN("tc", "geneve_snat_v6_overlay_mark_skipped")
int geneve_snat_v6_overlay_mark_skipped_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_snat_v6_overlay_mark_skipped")
int geneve_snat_v6_overlay_mark_skipped_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, true);
}

CHECK("tc", "geneve_snat_v6_overlay_mark_skipped")
int geneve_snat_v6_overlay_mark_skipped_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, true, true);
}

/* B2 contrast: without the mark the outer IPv6 flow gets CT and SNAT
 * entries.
 */
PKTGEN("tc", "geneve_snat_v6_no_mark_tracked")
int geneve_snat_v6_no_mark_tracked_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_snat_v6_no_mark_tracked")
int geneve_snat_v6_no_mark_tracked_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, false);
}

CHECK("tc", "geneve_snat_v6_no_mark_tracked")
int geneve_snat_v6_no_mark_tracked_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, true, false);
}
