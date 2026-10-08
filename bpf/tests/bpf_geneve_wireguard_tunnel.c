// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* B2: cil_to_netdev must handle natively encapsulated Geneve packets the way
 * it handles packets coming out of the kernel tunnel device. The packets
 * arrive as tail_geneve_encap4/6() emit them, an outer node-to-node packet
 * carrying the MARK_MAGIC_OVERLAY | identity mark that handle_to_overlay()
 * sets. With WireGuard in tunnel mode that mark is what makes
 * wg_maybe_redirect_to_encrypt() send them to cilium_wg0 (overlay_encrypt).
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1
#define ENABLE_WIREGUARD	1

#define WG_IFINDEX		51
#define WG_KEY			1

#define SRC_NODE_V4		v4_node_one
#define DST_NODE_V4		v4_node_two
#define SRC_NODE_V6		((const union v6addr *)v6_node_one)
#define DST_NODE_V6		((const union v6addr *)v6_node_two)
#define SRC_POD_V4		v4_pod_one
#define DST_POD_V4		v4_pod_one_on_node_two
#define SRC_POD_SEC_IDENTITY	0x1234
#define GENEVE_SPORT		bpf_htons(50000)

static struct {
	int ifindex;
	__u32 flags;
	__u32 calls;
} redirect_rec;

static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex,
		  __u32 flags)
{
	redirect_rec.ifindex = ifindex;
	redirect_rec.flags = flags;
	redirect_rec.calls++;
	return CTX_ACT_REDIRECT;
}

#define ctx_redirect mock_ctx_redirect

#include "lib/bpf_host.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(__u32, wg_ifindex, WG_IFINDEX)

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

/* The ipcache knows both nodes, and the peer has a WireGuard key, so only
 * the source identity decides whether the outer packet gets encrypted.
 */
static __always_inline void setup_ipcache(void)
{
	ipcache_v4_add_entry(SRC_NODE_V4, 0, HOST_ID, 0, 0);
	ipcache_v4_add_entry(DST_NODE_V4, 0, REMOTE_NODE_ID, 0, WG_KEY);
	ipcache_v6_add_entry(SRC_NODE_V6, 0, HOST_ID, 0, 0);
	ipcache_v6_add_entry(DST_NODE_V6, 0, REMOTE_NODE_ID, 0, WG_KEY);
}

/* Encapsulate as tail_geneve_encap4/6() do (VNI = source identity, no TLVs),
 * mark the packet as handle_to_overlay() does if @overlay_mark and send it
 * to cil_to_netdev.
 */
static __always_inline int
send_geneve_packet(struct __ctx_buff *ctx, bool ipv6_underlay, bool overlay_mark)
{
	int ret;

	setup_ipcache();
	__bpf_memzero(&redirect_rec, sizeof(redirect_rec));

	if (ipv6_underlay)
		ret = geneve_encap6(ctx, SRC_NODE_V6, DST_NODE_V6,
				    SRC_POD_SEC_IDENTITY, GENEVE_SPORT, NULL, 0);
	else
		ret = geneve_encap4(ctx, SRC_NODE_V4, DST_NODE_V4,
				    SRC_POD_SEC_IDENTITY, GENEVE_SPORT, NULL, 0);
	if (ret < 0)
		return ret;

	if (overlay_mark)
		set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);
	else
		ctx->mark = 0;

	return netdev_send_packet(ctx);
}

/* @encrypted: the packet was redirected to cilium_wg0, otherwise it left
 * cil_to_netdev in cleartext. Either way it is still the unmodified outer
 * Geneve packet.
 */
static __always_inline int
check_geneve_packet(const struct __ctx_buff *ctx, bool ipv6_underlay, bool encrypted)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct udphdr *l4;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	if (encrypted) {
		assert(*status_code == CTX_ACT_REDIRECT);
		assert(redirect_rec.calls == 1);
		assert(redirect_rec.ifindex == WG_IFINDEX);
		assert(redirect_rec.flags == 0);
		/* overlay_encrypt keeps the mark and the identity in it. */
		assert((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_OVERLAY);
		assert(get_identity(ctx) == SRC_POD_SEC_IDENTITY);
	} else {
		assert(*status_code == CTX_ACT_OK);
		assert(redirect_rec.calls == 0);
		assert(ctx->mark == 0);
	}

	l2 = data + sizeof(*status_code);
	if (ipv6_underlay) {
		struct ipv6hdr *l3 = (void *)(l2 + 1);

		l4 = (void *)(l3 + 1);
		if ((void *)(l4 + 1) > data_end)
			test_fatal("outer headers out of bounds");

		assert(l2->h_proto == bpf_htons(ETH_P_IPV6));
		assert(ipv6_addr_equals((union v6addr *)&l3->saddr, SRC_NODE_V6));
		assert(ipv6_addr_equals((union v6addr *)&l3->daddr, DST_NODE_V6));
		assert(l3->nexthdr == IPPROTO_UDP);
	} else {
		struct iphdr *l3 = (void *)(l2 + 1);

		l4 = (void *)(l3 + 1);
		if ((void *)(l4 + 1) > data_end)
			test_fatal("outer headers out of bounds");

		assert(l2->h_proto == bpf_htons(ETH_P_IP));
		assert(l3->saddr == SRC_NODE_V4);
		assert(l3->daddr == DST_NODE_V4);
		assert(l3->protocol == IPPROTO_UDP);
	}
	assert(l4->source == GENEVE_SPORT);
	assert(l4->dest == bpf_htons(6081));

	test_finish();
}

/* B2: the overlay mark sends the outer IPv4 packet to cilium_wg0. */
PKTGEN("tc", "geneve_wg_v4_overlay_mark_encrypted")
int geneve_wg_v4_overlay_mark_encrypted_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_v4_overlay_mark_encrypted")
int geneve_wg_v4_overlay_mark_encrypted_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false, true);
}

CHECK("tc", "geneve_wg_v4_overlay_mark_encrypted")
int geneve_wg_v4_overlay_mark_encrypted_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, false, true);
}

/* B2 contrast: without the mark, the source identity is looked up by the
 * outer source address, the node's own (HOST_ID), which is not encrypted.
 * The packet leaves in cleartext.
 */
PKTGEN("tc", "geneve_wg_v4_no_mark_cleartext")
int geneve_wg_v4_no_mark_cleartext_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_v4_no_mark_cleartext")
int geneve_wg_v4_no_mark_cleartext_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false, false);
}

CHECK("tc", "geneve_wg_v4_no_mark_cleartext")
int geneve_wg_v4_no_mark_cleartext_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, false, false);
}

/* B2: the overlay mark sends the outer IPv6 packet to cilium_wg0. */
PKTGEN("tc", "geneve_wg_v6_overlay_mark_encrypted")
int geneve_wg_v6_overlay_mark_encrypted_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_v6_overlay_mark_encrypted")
int geneve_wg_v6_overlay_mark_encrypted_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, true);
}

CHECK("tc", "geneve_wg_v6_overlay_mark_encrypted")
int geneve_wg_v6_overlay_mark_encrypted_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, true, true);
}

/* B2 contrast: the unmarked outer IPv6 packet leaves in cleartext. */
PKTGEN("tc", "geneve_wg_v6_no_mark_cleartext")
int geneve_wg_v6_no_mark_cleartext_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_v6_no_mark_cleartext")
int geneve_wg_v6_no_mark_cleartext_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true, false);
}

CHECK("tc", "geneve_wg_v6_no_mark_cleartext")
int geneve_wg_v6_no_mark_cleartext_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, true, false);
}
