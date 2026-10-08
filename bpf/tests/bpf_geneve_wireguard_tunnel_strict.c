// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* B2 with WireGuard strict mode, configured for the pod CIDR as in
 * encrypt_host_wireguard_tunnel_strict.c. Strict mode does not back up a
 * missing overlay mark on a natively encapsulated Geneve packet: the outer
 * packet is node-to-node, outside the strict CIDR (and TUNNEL_MODE exempts
 * remote nodes in strict_allow() anyway), so without the mark it leaves in
 * cleartext rather than being dropped.
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
ASSIGN_CONFIG(struct strict_encryption_cfg, strict_egress_encryption, {
	.enabled = true,
	.ipv4_net = { .be32 = IPV4(192, 168, 0, 0) },
	.ipv4_net_size = 16,
});

/* Inner pod-to-pod packet, inside the strict CIDR. */
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

/* Encapsulate as tail_geneve_encap4() does, mark the packet as
 * handle_to_overlay() does if @overlay_mark and send it to cil_to_netdev.
 */
static __always_inline int
send_geneve_packet(struct __ctx_buff *ctx, bool overlay_mark)
{
	int ret;

	ipcache_v4_add_entry(SRC_NODE_V4, 0, HOST_ID, 0, 0);
	ipcache_v4_add_entry(DST_NODE_V4, 0, REMOTE_NODE_ID, 0, WG_KEY);
	__bpf_memzero(&redirect_rec, sizeof(redirect_rec));

	ret = geneve_encap4(ctx, SRC_NODE_V4, DST_NODE_V4, SRC_POD_SEC_IDENTITY,
			    GENEVE_SPORT, NULL, 0);
	if (ret < 0)
		return ret;

	if (overlay_mark)
		set_identity_mark(ctx, SRC_POD_SEC_IDENTITY, MARK_MAGIC_OVERLAY);
	else
		ctx->mark = 0;

	return netdev_send_packet(ctx);
}

static __always_inline int
check_geneve_packet(const struct __ctx_buff *ctx, bool encrypted)
{
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
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
	} else {
		/* Neither encrypted nor DROP_UNENCRYPTED_TRAFFIC. */
		assert(*status_code == CTX_ACT_OK);
		assert(redirect_rec.calls == 0);
	}

	l2 = data + sizeof(*status_code);
	l3 = (void *)(l2 + 1);
	l4 = (void *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		test_fatal("outer headers out of bounds");

	assert(l2->h_proto == bpf_htons(ETH_P_IP));
	assert(l3->saddr == SRC_NODE_V4);
	assert(l3->daddr == DST_NODE_V4);
	assert(l3->protocol == IPPROTO_UDP);
	assert(l4->dest == bpf_htons(6081));

	test_finish();
}

/* B2: with strict mode, the overlay mark still sends the packet to
 * cilium_wg0 before the strict check.
 */
PKTGEN("tc", "geneve_wg_strict_v4_overlay_mark_encrypted")
int geneve_wg_strict_v4_overlay_mark_encrypted_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_strict_v4_overlay_mark_encrypted")
int geneve_wg_strict_v4_overlay_mark_encrypted_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true);
}

CHECK("tc", "geneve_wg_strict_v4_overlay_mark_encrypted")
int geneve_wg_strict_v4_overlay_mark_encrypted_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, true);
}

/* B2 contrast: strict mode lets the unmarked outer packet pass in
 * cleartext, so the mark is the only thing that keeps it encrypted.
 */
PKTGEN("tc", "geneve_wg_strict_v4_no_mark_cleartext")
int geneve_wg_strict_v4_no_mark_cleartext_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_wg_strict_v4_no_mark_cleartext")
int geneve_wg_strict_v4_no_mark_cleartext_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false);
}

CHECK("tc", "geneve_wg_strict_v4_no_mark_cleartext")
int geneve_wg_strict_v4_no_mark_cleartext_check(const struct __ctx_buff *ctx)
{
	return check_geneve_packet(ctx, false);
}
