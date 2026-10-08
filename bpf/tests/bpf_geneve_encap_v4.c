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
#define GENEVE_INNER_PROTOCOL	2 /* GENEVE_INNER_PROTO_IP */

static __u32 mock_gso_size;

static __always_inline __u32
mock_ctx_gso_size(const struct __sk_buff *ctx __maybe_unused)
{
	return mock_gso_size;
}

#undef ctx_gso_size
#define ctx_gso_size mock_ctx_gso_size

static __u64 recorded_decap_flags;
static bool mask_decap_l4_udp = true;

static __always_inline int
mock_skb_adjust_room(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
		     __u64 flags)
{
	if (len_diff < 0) {
		recorded_decap_flags = flags;
		if (mask_decap_l4_udp)
			flags &= ~BPF_F_ADJ_ROOM_DECAP_L4_UDP;
	}
	return skb_adjust_room(skb, len_diff, mode, flags);
}

#undef ctx_adjust_hroom
#define ctx_adjust_hroom mock_skb_adjust_room

#include "lib/bpf_host.h"
#include "lib/ipcache.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, ipv4_direct_routing, { .be32 = v4_node_two })
ASSIGN_CONFIG(union macaddr, interface_mac, { .addr = mac_two_addr })

#define SRC_MAC		mac_one
#define DST_MAC		mac_two
#define SRC_IP		v4_pod_one
#define DST_IP		v4_pod_two
#define TUNNEL_SRC	v4_node_one
#define TUNNEL_DST	v4_node_two
#define TEST_VNI	0x123456
#define TEST_SPORT	42424

#define INNER_LEN	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 observed_magic;
static __u32 observed_vni;
static __u8 observed_family;
static __u8 observed_opt_len;
static __be32 observed_saddr;
static __be32 observed_daddr;
static __u32 ip_mode_overlay_reached;

__declare_tail_in(cilium_calls_bpf_overlay, GENEVE_CALL_FROM_OVERLAY)
int test_ip_mode_from_overlay(struct __ctx_buff *ctx __maybe_unused)
{
	const struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);

	ip_mode_overlay_reached = 1;
	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_saddr = meta->ip4.saddr;
		observed_daddr = meta->ip4.daddr;
	}
	return CTX_ACT_OK;
}

PKTGEN("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_pktgen(struct __ctx_buff *ctx)
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

SETUP("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_setup(struct __ctx_buff *ctx)
{
	mock_gso_size = 0;
	return geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
			     bpf_htons(TEST_SPORT), NULL, 0);
}

CHECK("tc", "geneve_encap_v4")
int bpf_geneve_encap_v4_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4, *inner_ip4;
	struct udphdr *udp;
	struct genevehdr *geneve;
	__u32 *status_code;
	__u16 expected_udp_len;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert(*status_code == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("outer eth out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("outer ip4 out of bounds");

	expected_udp_len = (__u16)(INNER_LEN - ETH_HLEN +
				   sizeof(struct geneve_encaphdr4) -
				   sizeof(struct iphdr));

	assert(ip4->version == 4);
	assert(ip4->ihl == 5);
	assert(ip4->ttl == IPDEFTTL);
	assert(ip4->protocol == IPPROTO_UDP);
	assert(ip4->saddr == TUNNEL_SRC);
	assert(ip4->daddr == TUNNEL_DST);
	/* ip mode sets DF=1 on outer IPv4 headers. */
	assert(ip4->frag_off == bpf_htons(IP_DF));
	assert(ip4->tot_len == bpf_htons((__u16)(expected_udp_len + sizeof(*ip4))));
	assert(geneve_ipv4_csum(ip4) == 0);

	udp = (void *)ip4 + sizeof(*ip4);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("outer udp out of bounds");

	assert(udp->source == bpf_htons(TEST_SPORT));
	assert(udp->dest == bpf_htons(6081));
	assert(udp->len == bpf_htons(expected_udp_len));
	assert(udp->check == 0);

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve hdr out of bounds");

	assert(geneve->ver == GENEVE_VERSION);
	assert(geneve->opt_len == 0);
	assert(geneve->control == 0);
	assert(geneve->critical == 0);
	assert(geneve->protocol_type == bpf_htons(ETH_P_IP));
	assert(geneve_hdr_vni(geneve) == TEST_VNI);

	/* Inner IPv4 header immediately follows Geneve header in ip mode. */
	inner_ip4 = (void *)(geneve + 1);
	if ((void *)(inner_ip4 + 1) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(inner_ip4->saddr == SRC_IP);
	assert(inner_ip4->daddr == DST_IP);

	assert((__u64)((void *)data_end - (void *)eth) ==
	       INNER_LEN + sizeof(struct geneve_encaphdr4));

	test_finish();
}

PKTGEN("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v4_pktgen(ctx);
}

SETUP("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_setup(struct __ctx_buff *ctx)
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
	const struct geneve_metadata *meta;
	int ret;

	mock_gso_size = 0;
	mask_decap_l4_udp = true;
	recorded_decap_flags = 0;
	observed_magic = 0;
	observed_vni = 0;
	observed_family = 0;
	observed_opt_len = 0;
	observed_saddr = 0;
	observed_daddr = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
			    bpf_htons(TEST_SPORT), (const __u8 *)&dsr_opt,
			    sizeof(dsr_opt));
	if (ret < 0)
		return ret;

	ret = geneve_decap4(ctx);
	if (ret < 0)
		return ret;

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (meta) {
		observed_magic = meta->magic;
		observed_vni = meta->vni;
		observed_family = meta->family;
		observed_opt_len = meta->opt_len;
		observed_saddr = meta->ip4.saddr;
		observed_daddr = meta->ip4.daddr;
	}
	return 0;
}

CHECK("tc", "geneve_encap_decap_v4_ip_mode")
int bpf_geneve_encap_decap_v4_ip_mode_check(const struct __ctx_buff *ctx)
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

	assert(*status_code == 0);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) != 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");

	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");

	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);
	assert((void *)eth + INNER_LEN == data_end);

	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);
	assert(observed_family == AF_INET);
	assert(observed_opt_len == sizeof(struct geneve_dsr_opt4));
	assert(observed_saddr == TUNNEL_SRC);
	assert(observed_daddr == TUNNEL_DST);

	test_finish();
}

/* Verify that in ip mode, cil_from_netdev does NOT skip GSO-marked skbs
 * (gso_size != 0) at the native ingress intercept and requests
 * BPF_F_ADJ_ROOM_DECAP_L4_UDP on decapsulation.
 */
PKTGEN("tc", "geneve_netdev_gso_not_skipped_ip_mode")
int bpf_geneve_netdev_gso_ip_mode_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v4_pktgen(ctx);
}

SETUP("tc", "geneve_netdev_gso_not_skipped_ip_mode")
int bpf_geneve_netdev_gso_ip_mode_setup(struct __ctx_buff *ctx)
{
	int ret;

	mock_gso_size = 0;
	mask_decap_l4_udp = true;
	recorded_decap_flags = 0;
	ip_mode_overlay_reached = 0;
	observed_magic = 0;
	observed_vni = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	mock_gso_size = 100;
	ret = netdev_receive_packet(ctx);
	mock_gso_size = 0;
	return ret;
}

CHECK("tc", "geneve_netdev_gso_not_skipped_ip_mode")
int bpf_geneve_netdev_gso_ip_mode_check(const struct __ctx_buff *ctx)
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
	assert(ip_mode_overlay_reached == 1);
	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) != 0);
	assert(observed_magic == GENEVE_META_MAGIC);
	assert(observed_vni == TEST_VNI);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);

	test_finish();
}

/* Exercise the unmasked skb_adjust_room() call with BPF_F_ADJ_ROOM_DECAP_L4_UDP
 * in ip mode; skip if the running kernel does not yet support the bpf-next flag.
 */
PKTGEN("tc", "geneve_decap_v4_ip_mode_l4_udp_kernel_probe")
int bpf_geneve_decap_v4_l4_udp_probe_pktgen(struct __ctx_buff *ctx)
{
	return bpf_geneve_encap_v4_pktgen(ctx);
}

SETUP("tc", "geneve_decap_v4_ip_mode_l4_udp_kernel_probe")
int bpf_geneve_decap_v4_l4_udp_probe_setup(struct __ctx_buff *ctx)
{
	int ret;

	mock_gso_size = 0;
	recorded_decap_flags = 0;

	ret = geneve_encap4(ctx, TUNNEL_SRC, TUNNEL_DST, TEST_VNI,
			    bpf_htons(TEST_SPORT), NULL, 0);
	if (ret < 0)
		return ret;

	mask_decap_l4_udp = false;
	ret = geneve_decap4(ctx);
	mask_decap_l4_udp = true;
	return ret;
}

CHECK("tc", "geneve_decap_v4_ip_mode_l4_udp_kernel_probe")
int bpf_geneve_decap_v4_l4_udp_probe_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip4;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(*status_code) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	assert((recorded_decap_flags & BPF_F_ADJ_ROOM_DECAP_L4_UDP) != 0);
	if (*status_code == DROP_INVALID) {
		test_skip_now();
	}

	assert(*status_code == 0);

	eth = (void *)status_code + sizeof(*status_code);
	if ((void *)eth + sizeof(*eth) > data_end)
		test_fatal("eth out of bounds");
	assert(eth->h_proto == bpf_htons(ETH_P_IP));

	ip4 = (void *)eth + sizeof(*eth);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		test_fatal("inner ip4 out of bounds");
	assert(ip4->saddr == SRC_IP);
	assert(ip4->daddr == DST_IP);

	test_finish();
}
