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

static __u32 mock_gso_size;

static __always_inline __u32
mock_ctx_gso_size(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_gso_size;
}

#undef ctx_gso_size
#define ctx_gso_size mock_ctx_gso_size

/* Flags of the decapsulating skb_adjust_room() call, and skb->protocol
 * before it.
 */
static __u64 decap_adjust_flags;
static __be16 decap_adjust_protocol;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	if (len_diff < 0) {
		decap_adjust_flags = flags;
		decap_adjust_protocol = (__be16)skb->protocol;
	}
	return skb_adjust_room(skb, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

static int BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, __be16 vlan_proto,
		    __u16 vlan_tci);

#include "lib/bpf_host.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })
ASSIGN_CONFIG(union v6addr, ipv6_direct_routing, { .addr = v6_node_two_addr })
ASSIGN_CONFIG(union macaddr, interface_mac, { .addr = mac_two_addr })

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC_V4	v4_node_one
#define TUNNEL_DST_V4	v4_node_two
#define TEST_VNI	0x456789
#define TEST_SPORT	51515

/* Another local address, known as such only to the ipcache. */
#define LOCAL_ADDR_V4	v4_node_three
#define LOCAL_ADDR_V6	{ .addr = v6_node_three_addr }

#define DECAP_L3_FLAGS	(BPF_F_ADJ_ROOM_DECAP_L3_IPV4 | \
			 BPF_F_ADJ_ROOM_DECAP_L3_IPV6)

#define INNER_LEN_V4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))
#define INNER_LEN_V6	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 overlay_tail_reached;
static bool observed_decap_flag;
static __u32 observed_queue_mapping;
static __u32 observed_vlan_present;
static __be16 observed_protocol;
static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static __be32 observed_saddr4;
static __be32 observed_daddr4;
static union v6addr observed_saddr6;
static union v6addr observed_daddr6;

static __u32 pre_decap_vlan_present;

static bool bypass_wrong_dport;
static bool bypass_nonlocal_dst;
static bool bypass_ipv4_frag;
static bool bypass_ipv4_opts;
static bool bypass_oam_control;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY)
int test_from_overlay_receiver(struct __ctx_buff *ctx)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	overlay_tail_reached = 1;
	observed_decap_flag = ctx_bpf_geneve_decap_is_set(ctx);
	observed_queue_mapping = ctx->queue_mapping;
	observed_vlan_present = ctx->vlan_present;
	observed_protocol = (__be16)ctx->protocol;

	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_saddr4 = meta->ip4.saddr;
		observed_daddr4 = meta->ip4.daddr;
		observed_saddr6 = meta->ip6.saddr;
		observed_daddr6 = meta->ip6.daddr;
	}
	return CTX_ACT_OK;
}

static __always_inline void
reset_ingress_obs(void)
{
	mock_gso_size = 0;
	overlay_tail_reached = 0;
	observed_decap_flag = false;
	observed_queue_mapping = 0xffff;
	observed_vlan_present = 0xffff;
	observed_protocol = 0;
	observed_magic = 0;
	observed_vni = 0;
	observed_family = 0;
	observed_opt_len = 0;
	observed_saddr4 = 0;
	observed_daddr4 = 0;
	__bpf_memzero(&observed_saddr6, sizeof(observed_saddr6));
	__bpf_memzero(&observed_daddr6, sizeof(observed_daddr6));
	decap_adjust_flags = 0;
	decap_adjust_protocol = 0;
}

static __always_inline int
build_inner_v4_tcp(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
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

static __always_inline int
build_inner_v6_tcp(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)SRC_MAC, (__u8 *)DST_MAC,
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

/* 1. Native IPv4 Geneve ingress decap from cil_from_netdev (incl. queue_mapping reset) */
PKTGEN("tc", "geneve_netdev_decap_v4")
int bpf_geneve_netdev_decap_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v4")
int bpf_geneve_netdev_decap_v4_setup(struct __ctx_buff *ctx)
{
	struct geneve_dsr_opt4 dsr_opt = {
		.hdr = {
			.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS),
			.type = DSR_GENEVE_OPT_TYPE,
			.length = DSR_IPV4_GENEVE_OPT_LEN,
		},
		.addr = v4_svc_one,
		.port = tcp_svc_one,
	};
	int ret;

	reset_ingress_obs();

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&dsr_opt,
			    sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	ctx->queue_mapping = 7;
	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v4")
int bpf_geneve_netdev_decap_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_decap_flag);
	assert(observed_queue_mapping == 0);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);
	assert(observed_family == AF_INET);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt4));
	assert(observed_saddr4 == TUNNEL_SRC_V4);
	assert(observed_daddr4 == TUNNEL_DST_V4);

	/* B7: same family, skb->protocol is already right. U3c: Ethernet
	 * mode never asks the kernel to reset the UDP tunnel GSO state.
	 */
	assert(decap_adjust_protocol == bpf_htons(ETH_P_IP));
	assert(!(decap_adjust_flags & DECAP_L3_FLAGS));
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP));
	assert(observed_protocol == bpf_htons(ETH_P_IP));

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 2. Native IPv4 Geneve ingress decap of L3-wire-format packet (protocol_type == ETH_P_IP) */
PKTGEN("tc", "geneve_netdev_decap_v4_l3_wire")
int bpf_geneve_netdev_decap_v4_l3_wire_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eth;
	struct iphdr *outer_ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	ethhdr__set_macs(eth, (__u8 *)SRC_MAC, (__u8 *)DST_MAC);
	eth->h_proto = bpf_htons(ETH_P_IP);

	outer_ip4 = pktgen__push_default_iphdr(&builder);
	if (!outer_ip4)
		return TEST_ERROR;
	outer_ip4->saddr = TUNNEL_SRC_V4;
	outer_ip4->daddr = TUNNEL_DST_V4;

	udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(TEST_SPORT);
	udp->dest = bpf_htons(6081);

	geneve = pktgen__push_default_genevehdr(&builder);
	if (!geneve)
		return TEST_ERROR;
	geneve->protocol_type = bpf_htons(ETH_P_IP);
	geneve->vni[0] = (__u8)(TEST_VNI >> 16);
	geneve->vni[1] = (__u8)(TEST_VNI >> 8);
	geneve->vni[2] = (__u8)TEST_VNI;

	inner_ip4 = pktgen__push_default_iphdr(&builder);
	if (!inner_ip4)
		return TEST_ERROR;
	inner_ip4->saddr = SRC_IP;
	inner_ip4->daddr = DST_IP;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_netdev_decap_v4_l3_wire")
int bpf_geneve_netdev_decap_v4_l3_wire_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *outer_ip4 = data + ETH_HLEN;

	if ((void *)(outer_ip4 + 1) > data_end)
		return TEST_ERROR;
	outer_ip4->check = 0;
	outer_ip4->check = geneve_ipv4_csum(outer_ip4);

	reset_ingress_obs();
	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v4_l3_wire")
int bpf_geneve_netdev_decap_v4_l3_wire_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_decap_flag);
	assert(observed_vni == TEST_VNI);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 3. Native IPv6 Geneve ingress decap from cil_from_netdev (dual-stack inner IPv4) */
PKTGEN("tc", "geneve_netdev_decap_v6")
int bpf_geneve_netdev_decap_v6_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v6")
int bpf_geneve_netdev_decap_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	const union v6addr svc_addr = { .addr = v6_svc_one_addr };
	struct geneve_dsr_opt6 dsr_opt = {};
	int ret;

	reset_ingress_obs();
	set_geneve_dsr_opt6(tcp_svc_one, &svc_addr, &dsr_opt);

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&dsr_opt,
			    sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v6")
int bpf_geneve_netdev_decap_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_node_one_addr };
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_decap_flag);
	assert(observed_protocol == bpf_htons(ETH_P_IP));
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);
	assert(observed_family == AF_INET6);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt6));
	assert(ipv6_addr_equals(&observed_saddr6, &expected_src));
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));

	/* B7: the kernel switches skb->protocol to the inner family. U3c: no
	 * UDP tunnel GSO reset in Ethernet mode.
	 */
	assert(decap_adjust_protocol == bpf_htons(ETH_P_IPV6));
	assert(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV4);
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV6));
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP));

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("inner headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 4. D29: Priority-tagged (vlan_present=1, VID 0) frame has its VLAN tag popped on native decap */
PKTGEN("tc", "geneve_netdev_decap_vlan0_pop")
int bpf_geneve_netdev_decap_vlan0_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_vlan0_pop")
int bpf_geneve_netdev_decap_vlan0_setup(struct __ctx_buff *ctx)
{
	int ret;

	reset_ingress_obs();
	pre_decap_vlan_present = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	/* Push priority-tagged 802.1Q header with VID 0 (PCP = 1 -> TCI 0x2000) */
	if (skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q), 0x2000) < 0)
		return TEST_ERROR;
	pre_decap_vlan_present = ctx->vlan_present;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_vlan0_pop")
int bpf_geneve_netdev_decap_vlan0_check(const struct __ctx_buff *ctx)
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
	assert(pre_decap_vlan_present == 1);
	assert(overlay_tail_reached == 1);
	assert(observed_vlan_present == 0);
	assert(!ctx->vlan_present);

	test_finish();
}

/* 5. D30c: PACKET_OTHERHOST frame is NOT intercepted by native decap */
PKTGEN("tc", "geneve_netdev_bypass_otherhost")
int bpf_geneve_netdev_bypass_otherhost_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_bypass_otherhost")
int bpf_geneve_netdev_bypass_otherhost_setup(struct __ctx_buff *ctx)
{
	int ret;

	reset_ingress_obs();

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	ctx_change_type(ctx, PACKET_OTHERHOST);
	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_otherhost")
int bpf_geneve_netdev_bypass_otherhost_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();
	assert(overlay_tail_reached == 0);
	test_finish();
}

/* 6. D28: Inner ARP (ETH_P_ARP) is skipped by native decap and left to the kernel path */
PKTGEN("tc", "geneve_netdev_bypass_inner_arp")
int bpf_geneve_netdev_bypass_inner_arp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eth, *inner_eth;
	struct iphdr *outer_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	struct arphdreth *arp;

	pktgen__init(&builder, ctx);

	eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	ethhdr__set_macs(eth, (__u8 *)SRC_MAC, (__u8 *)DST_MAC);
	eth->h_proto = bpf_htons(ETH_P_IP);

	outer_ip4 = pktgen__push_default_iphdr(&builder);
	if (!outer_ip4)
		return TEST_ERROR;
	outer_ip4->saddr = TUNNEL_SRC_V4;
	outer_ip4->daddr = TUNNEL_DST_V4;

	udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(TEST_SPORT);
	udp->dest = bpf_htons(6081);

	geneve = pktgen__push_default_genevehdr(&builder);
	if (!geneve)
		return TEST_ERROR;
	geneve->protocol_type = bpf_htons(ETH_P_TEB);
	geneve->vni[0] = (__u8)(TEST_VNI >> 16);
	geneve->vni[1] = (__u8)(TEST_VNI >> 8);
	geneve->vni[2] = (__u8)TEST_VNI;

	inner_eth = pktgen__push_ethhdr(&builder);
	if (!inner_eth)
		return TEST_ERROR;
	ethhdr__set_macs(inner_eth, (__u8 *)SRC_MAC, (__u8 *)DST_MAC);

	arp = pktgen__push_default_arphdr_ethernet(&builder);
	if (!arp)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_netdev_bypass_inner_arp")
int bpf_geneve_netdev_bypass_inner_arp_setup(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *outer_ip4 = data + ETH_HLEN;

	if ((void *)(outer_ip4 + 1) > data_end)
		return TEST_ERROR;
	outer_ip4->check = 0;
	outer_ip4->check = geneve_ipv4_csum(outer_ip4);

	reset_ingress_obs();
	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_inner_arp")
int bpf_geneve_netdev_bypass_inner_arp_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(overlay_tail_reached == 0);

	/* Outer Geneve headers remain intact for kernel geneve device */
	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->daddr == TUNNEL_DST_V4);

	test_finish();
}

/* 7. U3e: GSO-marked skb (gso_size != 0) is skipped by cil_from_netdev in eth mode */
PKTGEN("tc", "geneve_netdev_bypass_gso_eth_mode")
int bpf_geneve_netdev_bypass_gso_eth_mode_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_bypass_gso_eth_mode")
int bpf_geneve_netdev_bypass_gso_eth_mode_setup(struct __ctx_buff *ctx)
{
	int ret;

	reset_ingress_obs();

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	mock_gso_size = 100;
	ret = netdev_receive_packet(ctx);
	mock_gso_size = 0;
	return ret;
}

CHECK("tc", "geneve_netdev_bypass_gso_eth_mode")
int bpf_geneve_netdev_bypass_gso_eth_mode_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(overlay_tail_reached == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		test_fatal("outer ip4 out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->daddr == TUNNEL_DST_V4);

	test_finish();
}

/* 8. Non-matching packets (wrong dport, non-local dst, fragment, IP options,
 * OAM control frame, and from_host entrypoint) are NOT intercepted.
 */
PKTGEN("tc", "geneve_netdev_bypass_non_matching")
int bpf_geneve_netdev_bypass_non_matching_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_bypass_non_matching")
int bpf_geneve_netdev_bypass_non_matching_setup(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	int ret;

	reset_ingress_obs();
	bypass_wrong_dport = true;
	bypass_nonlocal_dst = true;
	bypass_ipv4_frag = true;
	bypass_ipv4_opts = true;
	bypass_oam_control = true;

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	ip4 = data + ETH_HLEN;
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;

	/* (a) Wrong UDP destination port */
	udp->dest = bpf_htons(6082);
	bypass_wrong_dport = geneve_is_native_ingress4(ctx, ip4);
	udp->dest = bpf_htons(6081);

	/* (b) Non-local destination IP */
	ip4->daddr = v4_ext_one;
	bypass_nonlocal_dst = geneve_is_native_ingress4(ctx, ip4);
	ip4->daddr = TUNNEL_DST_V4;

	/* (c) IPv4 fragment (MF bit 0x2000) */
	ip4->frag_off = bpf_htons(0x2000);
	bypass_ipv4_frag = geneve_is_native_ingress4(ctx, ip4);
	ip4->frag_off = 0;

	/* (d) IPv4 options (ihl > 5) */
	ip4->ihl = 6;
	bypass_ipv4_opts = geneve_is_native_ingress4(ctx, ip4);
	ip4->ihl = 5;

	/* (e) Geneve OAM control frame */
	geneve->control = 1;
	bypass_oam_control = geneve_is_native_ingress4(ctx, ip4);
	geneve->control = 0;

	/* (f) cil_from_host (from_host == true) does not intercept Geneve */
	return host_send_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_non_matching")
int bpf_geneve_netdev_bypass_non_matching_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	assert(!bypass_wrong_dport);
	assert(!bypass_nonlocal_dst);
	assert(!bypass_ipv4_frag);
	assert(!bypass_ipv4_opts);
	assert(!bypass_oam_control);
	assert(overlay_tail_reached == 0);

	test_finish();
}

/* 9. B7: IPv6 in IPv4. The kernel switches skb->protocol to the inner
 * family, which the stack and redirect_neigh() dispatch on.
 */
PKTGEN("tc", "geneve_netdev_decap_v6_in_v4")
int bpf_geneve_netdev_decap_v6_in_v4_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v6_in_v4")
int bpf_geneve_netdev_decap_v6_in_v4_setup(struct __ctx_buff *ctx)
{
	int ret;

	reset_ingress_obs();

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v6_in_v4")
int bpf_geneve_netdev_decap_v6_in_v4_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_pod_one_addr };
	const union v6addr expected_dst = { .addr = v6_pod_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_family == AF_INET);

	assert(decap_adjust_protocol == bpf_htons(ETH_P_IP));
	assert(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV6);
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L3_IPV4));
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP));
	assert(observed_protocol == bpf_htons(ETH_P_IPV6));

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		test_fatal("inner headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert((void *)eth + INNER_LEN_V6 == data_end);

	test_finish();
}

/* 10. B7: IPv6 in IPv6, same family: skb->protocol is already right. */
PKTGEN("tc", "geneve_netdev_decap_v6_in_v6")
int bpf_geneve_netdev_decap_v6_in_v6_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v6_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v6_in_v6")
int bpf_geneve_netdev_decap_v6_in_v6_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_node_two_addr };
	int ret;

	reset_ingress_obs();

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v6_in_v6")
int bpf_geneve_netdev_decap_v6_in_v6_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_src = { .addr = v6_pod_one_addr };
	const union v6addr expected_dst = { .addr = v6_pod_two_addr };
	void *data, *data_end;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_family == AF_INET6);

	assert(decap_adjust_protocol == bpf_htons(ETH_P_IPV6));
	assert(!(decap_adjust_flags & DECAP_L3_FLAGS));
	assert(!(decap_adjust_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP));
	assert(observed_protocol == bpf_htons(ETH_P_IPV6));

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		test_fatal("inner headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ipv6_addr_equals((union v6addr *)&ip6->saddr, &expected_src));
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert((void *)eth + INNER_LEN_V6 == data_end);

	test_finish();
}

/* 11. L3-04: an outer IPv4 destination that is a local address other than
 * the direct routing one (a HOST_ID entry in the ipcache) is decapsulated
 * natively too.
 */
PKTGEN("tc", "geneve_netdev_decap_v4_ipcache_host_addr")
int bpf_geneve_netdev_decap_v4_ipcache_host_addr_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v4_ipcache_host_addr")
int bpf_geneve_netdev_decap_v4_ipcache_host_addr_setup(struct __ctx_buff *ctx)
{
	int ret;

	reset_ingress_obs();
	ipcache_v4_add_entry(LOCAL_ADDR_V4, 0, HOST_ID, 0, 0);

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, LOCAL_ADDR_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v4_ipcache_host_addr")
int bpf_geneve_netdev_decap_v4_ipcache_host_addr_check(const struct __ctx_buff *ctx)
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
	assert(overlay_tail_reached == 1);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_daddr4 == LOCAL_ADDR_V4);

	test_finish();
}

/* 12. L3-04: as 11, for an outer IPv6 destination. */
PKTGEN("tc", "geneve_netdev_decap_v6_ipcache_host_addr")
int bpf_geneve_netdev_decap_v6_ipcache_host_addr_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_decap_v6_ipcache_host_addr")
int bpf_geneve_netdev_decap_v6_ipcache_host_addr_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = LOCAL_ADDR_V6;
	int ret;

	reset_ingress_obs();
	ipcache_v6_add_entry(&daddr, 0, HOST_ID, 0, 0);

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_decap_v6_ipcache_host_addr")
int bpf_geneve_netdev_decap_v6_ipcache_host_addr_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = LOCAL_ADDR_V6;
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 1);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_family == AF_INET6);
	assert(ipv6_addr_equals(&observed_daddr6, &expected_dst));

	test_finish();
}

/* 13. L1-11, D12: a Geneve version other than 0 is left to the kernel
 * device, through cil_from_netdev, unchanged.
 */
PKTGEN("tc", "geneve_netdev_bypass_bad_version")
int bpf_geneve_netdev_bypass_bad_version_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_bypass_bad_version")
int bpf_geneve_netdev_bypass_bad_version_setup(struct __ctx_buff *ctx)
{
	struct genevehdr *geneve;
	void *data, *data_end;
	int ret;

	reset_ingress_obs();

	ret = geneve_encap4(ctx, TUNNEL_SRC_V4, TUNNEL_DST_V4, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	geneve = data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr);
	if ((void *)(geneve + 1) > data_end)
		return TEST_ERROR;
	geneve->ver = 1;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_bad_version")
int bpf_geneve_netdev_bypass_bad_version_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct genevehdr *geneve;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip4 = (void *)(eth + 1);
	udp = (void *)(ip4 + 1);
	geneve = (void *)(udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("outer headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));
	assert(ip4->daddr == TUNNEL_DST_V4);
	assert(udp->dest == bpf_htons(6081));
	assert(geneve->ver == 1);
	assert((void *)(geneve + 1) + INNER_LEN_V4 == data_end);

	test_finish();
}

/* 14. L1-11, D12: an outer IPv6 header followed by an extension header,
 * which Cilium never emits, is left to the kernel device unchanged.
 */
PKTGEN("tc", "geneve_netdev_bypass_v6_ext_hdr")
int bpf_geneve_netdev_bypass_v6_ext_hdr_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *eth, *inner_eth;
	struct ipv6hdr *outer_ip6;
	struct ipv6_opt_hdr *opt;
	struct udphdr *udp;
	struct genevehdr *geneve;
	void *data;

	pktgen__init(&builder, ctx);

	eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	ethhdr__set_macs(eth, (__u8 *)SRC_MAC, (__u8 *)DST_MAC);

	outer_ip6 = pktgen__push_default_ipv6hdr(&builder);
	if (!outer_ip6)
		return TEST_ERROR;
	ipv6hdr__set_addrs(outer_ip6, (__u8 *)v6_node_one, (__u8 *)v6_node_two);

	opt = pktgen__append_ipv6_extension_header(&builder, NEXTHDR_DEST, 8);
	if (!opt)
		return TEST_ERROR;

	udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(TEST_SPORT);
	udp->dest = bpf_htons(6081);

	geneve = pktgen__push_default_genevehdr(&builder);
	if (!geneve)
		return TEST_ERROR;
	geneve->vni[0] = (__u8)(TEST_VNI >> 16);
	geneve->vni[1] = (__u8)(TEST_VNI >> 8);
	geneve->vni[2] = (__u8)TEST_VNI;

	/* Of the inner frame, only the Ethernet header matters here. */
	inner_eth = pktgen__push_ethhdr(&builder);
	if (!inner_eth)
		return TEST_ERROR;
	ethhdr__set_macs(inner_eth, (__u8 *)SRC_MAC, (__u8 *)DST_MAC);
	inner_eth->h_proto = bpf_htons(ETH_P_IP);

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "geneve_netdev_bypass_v6_ext_hdr")
int bpf_geneve_netdev_bypass_v6_ext_hdr_setup(struct __ctx_buff *ctx)
{
	reset_ingress_obs();
	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_v6_ext_hdr")
int bpf_geneve_netdev_bypass_v6_ext_hdr_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_node_two_addr };
	void *data, *data_end;
	struct ipv6_opt_hdr *opt;
	struct ipv6hdr *ip6;
	struct ethhdr *eth;
	struct udphdr *udp;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	opt = (void *)(ip6 + 1);
	udp = (void *)opt + 8;
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ip6->nexthdr == NEXTHDR_DEST);
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert(opt->nexthdr == IPPROTO_UDP);
	assert(udp->dest == bpf_htons(6081));
	assert((void *)(udp + 1) + sizeof(struct genevehdr) + sizeof(struct ethhdr) +
	       sizeof(default_data) == data_end);

	test_finish();
}

/* 15. L3-04: an outer IPv6 destination that is not local is left to the
 * kernel unchanged.
 */
PKTGEN("tc", "geneve_netdev_bypass_v6_nonlocal_dst")
int bpf_geneve_netdev_bypass_v6_nonlocal_dst_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_v4_tcp(ctx);
}

SETUP("tc", "geneve_netdev_bypass_v6_nonlocal_dst")
int bpf_geneve_netdev_bypass_v6_nonlocal_dst_setup(struct __ctx_buff *ctx)
{
	const union v6addr saddr = { .addr = v6_node_one_addr };
	const union v6addr daddr = { .addr = v6_ext_node_one_addr };
	int ret;

	reset_ingress_obs();

	ret = geneve_encap6(ctx, &saddr, &daddr, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	return netdev_receive_packet(ctx);
}

CHECK("tc", "geneve_netdev_bypass_v6_nonlocal_dst")
int bpf_geneve_netdev_bypass_v6_nonlocal_dst_check(const struct __ctx_buff *ctx)
{
	const union v6addr expected_dst = { .addr = v6_ext_node_one_addr };
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct ethhdr *eth;
	struct udphdr *udp;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == CTX_ACT_OK);
	assert(overlay_tail_reached == 0);

	eth = (void *)status_code + sizeof(*status_code);
	ip6 = (void *)(eth + 1);
	udp = (void *)(ip6 + 1);
	if ((void *)(udp + 1) > data_end)
		test_fatal("outer headers out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IPV6));
	assert(ip6->nexthdr == IPPROTO_UDP);
	assert(ipv6_addr_equals((union v6addr *)&ip6->daddr, &expected_dst));
	assert(udp->dest == bpf_htons(6081));
	assert((void *)(udp + 1) + sizeof(struct genevehdr) + INNER_LEN_V4 == data_end);

	test_finish();
}
