/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Native (BPF-built) Geneve datapath: wire format, TLV handling and the
 * header builders.
 *
 * Only included from geneve_encap.h, i.e. by tc programs built with
 * ENABLE_BPF_GENEVE; the program glue (tail calls, drop notifications, FIB
 * lookups) lives there. The XDP datapath does not use this header and keeps
 * sending packets through ctx_set_encap_info4/6().
 *
 * Wire format: RFC 8926. The datapath emits the frames that the kernel
 * geneve device sends in collect_md mode: protocol type TEB, VNI = Cilium
 * tunnel ID, the DSR TLV when needed, TTL / hop limit 64, the ECN field per
 * RFC 6040, a fresh IPv4 ID per packet and IPv6 flow label 0. Deviations
 * are documented where the fields are set (outer UDP checksum over IPv6,
 * IPv4 ID selection, source port of packets without a flow hash). With
 * GENEVE_INNER_PROTOCOL set to GENEVE_INNER_PROTO_IP, the inner Ethernet
 * header is omitted and outer IPv4 headers have DF set.
 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <bpf/config/node.h>

#include "common.h"
#include "csum.h"
#include "jhash.h"
#include "tunnel.h"

#define GENEVE_VERSION		0

/* RFC 8926 section 3.4: opt_len is a 6 bit count of 4 byte words, every TLV
 * occupies at least one word.
 */
#define GENEVE_OPT_MAX_LEN	252
#define GENEVE_OPT_MAX_COUNT	(GENEVE_OPT_MAX_LEN / 4)

/* ECN field of the IPv4 TOS / IPv6 traffic class (RFC 3168). */
#define GENEVE_ECN_MASK		0x03
#define GENEVE_ECN_NOT_ECT	0x00
#define GENEVE_ECN_ECT_1	0x01
#define GENEVE_ECN_ECT_0	0x02
#define GENEVE_ECN_CE		0x03

/* Inner protocol mode. GENEVE_INNER_PROTO_ETH is what the kernel geneve
 * device produces and accepts (Transparent Ethernet Bridging). With
 * GENEVE_INNER_PROTO_IP the inner Ethernet header is omitted and the Geneve
 * protocol type carries the inner ethertype; only nodes running the native
 * datapath can receive such frames, and only on kernels with
 * BPF_F_ADJ_ROOM_DECAP_L4_UDP (see geneve_strip()).
 *
 * GENEVE_INNER_PROTO_IP requires the path MTU between nodes to be at least
 * the device MTU (more precisely, the route MTU that the FIB lookup
 * reports): packets that fit the route but not the path are black-holed.
 * The hop that cannot forward them drops them (outer IPv4 has DF set, see
 * geneve_encap4(); IPv6 routers never fragment) and reports it with an ICMP
 * error, which the sender's kernel discards: both __udp4_lib_err_encap()
 * and __udp6_lib_err_encap() (v6.18 net/ipv4/udp.c L905-906,
 * net/ipv6/udp.c L686-688) only accept errors that the geneve socket
 * claims, and it claims none for non-TEB frames (drivers/net/geneve.c
 * L431-432). So no PMTU exception is recorded, whereas for Ethernet frames
 * one would make the FIB lookup report the smaller MTU and send the packets
 * through the tunnel device (see geneve_handle_encap4()).
 */
#define GENEVE_INNER_PROTO_ETH	1
#define GENEVE_INNER_PROTO_IP	2

#ifndef GENEVE_INNER_PROTOCOL
# define GENEVE_INNER_PROTOCOL	GENEVE_INNER_PROTO_ETH
#endif
#if GENEVE_INNER_PROTOCOL != GENEVE_INNER_PROTO_ETH && \
    GENEVE_INNER_PROTOCOL != GENEVE_INNER_PROTO_IP
# error "GENEVE_INNER_PROTOCOL must be GENEVE_INNER_PROTO_ETH or GENEVE_INNER_PROTO_IP"
#endif

static __always_inline bool geneve_inner_is_eth(void)
{
	return GENEVE_INNER_PROTOCOL == GENEVE_INNER_PROTO_ETH;
}

/* Outer headers of a Geneve packet without the Ethernet header and TLVs. */
struct geneve_encaphdr4 {
	struct iphdr ip;
	struct udphdr udp;
	struct genevehdr geneve;
} __packed;

struct geneve_encaphdr6 {
	struct ipv6hdr ip6;
	struct udphdr udp;
	struct genevehdr geneve;
} __packed;

static __always_inline __u32 geneve_hdr_vni(const struct genevehdr *geneve)
{
	return ((__u32)geneve->vni[0] << 16) |
	       ((__u32)geneve->vni[1] << 8) |
	       (__u32)geneve->vni[2];
}

/* The O and C bits are left clear. That matches the kernel path, where the
 * geneve device builds the header from bpf_skb_set_tunnel_opt() metadata,
 * which never sets them, even for the critical DSR option. Receivers find
 * critical options by their type (see geneve_validate_opts()).
 */
static __always_inline void
geneve_hdr_init(struct genevehdr *geneve, __be16 protocol_type, __u32 vni,
		__u8 opt_words)
{
	memset(geneve, 0, sizeof(*geneve));
	geneve->ver = GENEVE_VERSION;
	geneve->opt_len = opt_words;
	geneve->protocol_type = protocol_type;
	geneve->vni[0] = (__u8)(vni >> 16);
	geneve->vni[1] = (__u8)(vni >> 8);
	geneve->vni[2] = (__u8)vni;
}

/* Per-CPU metadata slots used to hand the tunnel key and TLVs from one
 * program to the next within a single packet's processing:
 *
 *  - GENEVE_META_INGRESS is written by the decapsulating program (bpf_host)
 *    and read by tail_geneve_from_overlay (bpf_overlay).
 *  - GENEVE_META_EGRESS is written by geneve_encap_and_redirect() (bpf_lxc,
 *    bpf_host, bpf_overlay) and consumed by tail_geneve_encap4/6
 *    (bpf_overlay).
 *
 * Programs in the chain run back to back on the same CPU with preemption
 * disabled, so a slot is never shared with another packet. The validity of a
 * slot is additionally bound to the packet through TC_INDEX_F_BPF_GENEVE_*.
 */
#define GENEVE_META_MAGIC	0x474e564d /* "GNVM" */

enum geneve_meta_slot {
	GENEVE_META_INGRESS = 0,
	GENEVE_META_EGRESS = 1,
	GENEVE_META_SLOTS,
};

struct geneve_metadata {
	__u32 magic;
	/* Cilium tunnel ID (VNI), host byte order. */
	__u32 vni;
	/* AF_INET or AF_INET6: address family of the outer header. */
	__u8 family;
	/* Valid bytes in raw_opts, always a multiple of 4. */
	__u8 opt_len;
	__u16 pad;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		} ip4;
		struct {
			union v6addr saddr;
			union v6addr daddr;
		} ip6;
	};
	/* GENEVE_OPT_MAX_LEN rounded up to 256 so that the verifier can prove
	 * a 4 byte TLV header read at any offset <= GENEVE_OPT_MAX_LEN to be
	 * in bounds.
	 */
	__u8 raw_opts[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct geneve_metadata);
	__uint(max_entries, GENEVE_META_SLOTS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_geneve_meta __section_maps_btf;

static __always_inline struct geneve_metadata *
geneve_meta_slot(enum geneve_meta_slot slot)
{
	__u32 key = slot;

	return map_lookup_elem(&cilium_geneve_meta, &key);
}

/* Validate a sequence of RFC 8926 TLVs. Structural errors (TLV running past
 * the end of the option area, trailing bytes) and critical options that this
 * node does not understand are rejected; RFC 8926 section 3.5 requires the
 * packet to be dropped in the latter case. The only critical option Cilium
 * understands is its own DSR option.
 *
 * The loop is bounded by GENEVE_OPT_MAX_COUNT and keeps @offset provably
 * below 256 so that it can walk a struct geneve_metadata raw_opts buffer.
 */
static __always_inline bool
geneve_validate_opts(const __u8 *opts, __u32 total_len)
{
	__u32 offset = 0;
	int i;

	if (total_len > GENEVE_OPT_MAX_LEN)
		return false;

	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		const struct geneve_opt_hdr *hdr;
		__u32 len;

		if (offset >= total_len)
			break;
		if (offset > GENEVE_OPT_MAX_LEN - sizeof(*hdr))
			return false;

		hdr = (const struct geneve_opt_hdr *)(opts + offset);
		len = sizeof(*hdr) + ((__u32)hdr->length << 2);
		if (offset + len > total_len)
			return false;

		if ((hdr->type & GENEVE_OPT_TYPE_CRIT) &&
		    (hdr->opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS) ||
		     hdr->type != DSR_GENEVE_OPT_TYPE))
			return false;

		offset += len;
	}

	return offset == total_len;
}

/* Find the first TLV matching @opt_class/@opt_type in a validated option
 * area. @min_len is the minimum total TLV length the caller needs.
 */
static __always_inline const void *
geneve_find_opt(const __u8 *opts, __u32 total_len, __be16 opt_class,
		__u8 opt_type, __u32 min_len)
{
	__u32 offset = 0;
	int i;

	if (min_len < sizeof(struct geneve_opt_hdr))
		min_len = sizeof(struct geneve_opt_hdr);
	if (total_len > GENEVE_OPT_MAX_LEN || min_len > GENEVE_OPT_MAX_LEN)
		return NULL;

	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		const struct geneve_opt_hdr *hdr;
		__u32 len;

		if (offset >= total_len ||
		    offset > GENEVE_OPT_MAX_LEN - min_len)
			break;

		hdr = (const struct geneve_opt_hdr *)(opts + offset);
		len = sizeof(*hdr) + ((__u32)hdr->length << 2);
		if (offset + len > total_len)
			break;

		if (hdr->opt_class == opt_class && hdr->type == opt_type &&
		    len >= min_len)
			return hdr;

		offset += len;
	}

	return NULL;
}

/* Copy @len bytes (a multiple of 4, <= GENEVE_OPT_MAX_LEN) of TLVs between
 * the packet and a buffer. Decomposing @len into power-of-two chunks keeps
 * every ctx_load/store_bytes() size a compile time constant.
 */
#define GENEVE_OPT_CHUNK(op, ctx, off, buf, len, pos, n)			\
	do {								\
		if ((len) & (n)) {					\
			if (op(ctx, (off) + (pos), (buf) + (pos), (n)) < 0)	\
				return -1;				\
			(pos) += (n);					\
		}							\
	} while (0)

static __always_inline int
geneve_load_opts(const struct __ctx_buff *ctx, __u32 off, __u8 *dst, __u32 len)
{
	__u32 pos = 0;

	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 128);
	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 64);
	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 32);
	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 16);
	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 8);
	GENEVE_OPT_CHUNK(ctx_load_bytes, ctx, off, dst, len, pos, 4);
	return 0;
}

#define __geneve_store_bytes(ctx, off, buf, n) ctx_store_bytes(ctx, off, buf, n, 0)

static __always_inline int
geneve_store_opts(struct __ctx_buff *ctx, __u32 off, const __u8 *src, __u32 len)
{
	__u32 pos = 0;

	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 128);
	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 64);
	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 32);
	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 16);
	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 8);
	GENEVE_OPT_CHUNK(__geneve_store_bytes, ctx, off, src, len, pos, 4);
	return 0;
}

#undef __geneve_store_bytes
#undef GENEVE_OPT_CHUNK

/* Checksum of an option-less IPv4 header. */
static __always_inline __sum16 geneve_ipv4_csum(const struct iphdr *ip4)
{
	const __u16 *words = (const __u16 *)ip4;
	__u32 sum = 0;
	int i;

#pragma unroll
	for (i = 0; i < (int)(sizeof(*ip4) / sizeof(*words)); i++)
		sum += words[i];

	return csum_fold(sum);
}

/* Map a flow hash onto the configured outer UDP source port range with the
 * arithmetic of the kernel's udp_flow_src_port(). Fed with the same hash
 * (see geneve_flow_hash()), the native datapath therefore picks the same
 * source port as the kernel geneve device for a given flow, which keeps
 * ECMP placement stable while nodes switch between the two paths.
 *
 * low = high = 0 selects 1-65535, the range of a geneve device created
 * without a port range (which is what the agent does when
 * --tunnel-source-port-range is not set). Any other range with low >= high
 * yields low as the only port, whereas the kernel would fall back to
 * ip_local_port_range, which BPF cannot read.
 */
static __always_inline __be16 geneve_src_port(__u32 hash)
{
	__u32 low = CONFIG(tunnel_src_port_low);
	__u32 high = CONFIG(tunnel_src_port_high);

	if (!low && !high) {
		low = 1;
		high = 65535;
	} else if (low >= high) {
		return bpf_htons((__u16)low);
	}

	/* Only the upper 16 bits of the hash end up in the port; fold the
	 * lower ones in like the kernel does.
	 */
	hash ^= hash << 16;
	return bpf_htons((__u16)((((__u64)hash * (high - low)) >> 32) + low));
}

/* Flow hash for source port selection: skb_get_hash(), the hash the kernel
 * geneve device uses. For the rare packets without one (hash 0, e.g. ARP)
 * the kernel hashes the inner MAC addresses, whereas we hash the VNI and the
 * remote endpoint; both are stable per flow but yield different ports.
 */
static __always_inline __u32
geneve_flow_hash(struct __ctx_buff *ctx, __u32 vni, __u32 daddr)
{
	__u32 hash = get_hash_recalc(ctx);

	if (!hash)
		hash = jhash_2words(vni, daddr, 0);

	return hash;
}

/* Outer TOS / traffic class for an inner packet with TOS / traffic class
 * @inner_tos (0 for non-IP packets): RFC 6040 normal mode, which is what
 * the kernel geneve device does without "tos inherit"
 * (INET_ECN_encapsulate(0, inner)). The DSCP is not copied; the ECN field
 * is, except that CE is sent as ECT(0).
 */
static __always_inline __u8 geneve_outer_tos(__u8 inner_tos)
{
	__u8 ecn = inner_tos & GENEVE_ECN_MASK;

	return ecn == GENEVE_ECN_CE ? GENEVE_ECN_ECT_0 : ecn;
}

/* ECN field of the inner packet after decapsulation, RFC 6040 section 4.2
 * normal mode, as INET_ECN_decapsulate() does on the kernel path: an outer
 * CE mark is carried over into an ECN-capable inner packet and outer ECT(1)
 * turns inner ECT(0) into ECT(1). Returns -1 for a CE-marked outer header
 * with a non-ECN-capable inner packet, which must be dropped.
 */
static __always_inline int geneve_ecn_decap(__u8 outer_ecn, __u8 inner_ecn)
{
	if (inner_ecn == GENEVE_ECN_NOT_ECT)
		return outer_ecn == GENEVE_ECN_CE ? -1 : GENEVE_ECN_NOT_ECT;
	if (outer_ecn == GENEVE_ECN_CE)
		return GENEVE_ECN_CE;
	if (outer_ecn == GENEVE_ECN_ECT_1 && inner_ecn == GENEVE_ECN_ECT_0)
		return GENEVE_ECN_ECT_1;
	return inner_ecn;
}

/* Number of bytes the encapsulation inserts behind the outer Ethernet
 * header: @base_len (outer IP, UDP and Geneve headers), @opt_len bytes of
 * TLVs and, in Ethernet mode, the inner Ethernet header (the original one
 * becomes the outer Ethernet header).
 */
static __always_inline __u16 geneve_encap_room(__u16 base_len, __u32 opt_len)
{
	return (__u16)(base_len + opt_len +
		       (geneve_inner_is_eth() ? ETH_HLEN : 0));
}

/* Common part of the IPv4/IPv6 header builders: validate the inner packet
 * and the TLV length and compute the room needed in front of the inner L3
 * header. Does not modify the packet.
 */
static __always_inline int
__geneve_encap_prepare(struct __ctx_buff *ctx, struct ethhdr *inner_eth,
		       __u32 opt_len, __u16 base_len, __u16 *room_len,
		       __u8 *inner_tos)
{
	void *data, *data_end;

	if (opt_len > GENEVE_OPT_MAX_LEN || (opt_len & 3))
		return DROP_INVALID;

	if (ctx_load_bytes(ctx, 0, inner_eth, ETH_HLEN) < 0)
		return DROP_INVALID;

	*inner_tos = 0;
	switch (inner_eth->h_proto) {
	case bpf_htons(ETH_P_IP): {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		*inner_tos = ip4->tos;
		break;
	}
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		*inner_tos = (__u8)((ip6->priority << 4) | (ip6->flow_lbl[0] >> 4));
		break;
	}
	default:
		/* Only Ethernet mode can carry non-IP (e.g. VTEP ARP). */
		if (!geneve_inner_is_eth())
			return DROP_UNKNOWN_L3;
		break;
	}

	*room_len = geneve_encap_room(base_len, opt_len);
	return 0;
}

static __always_inline __u64 __geneve_encap_room_flags(__u64 l3_flag)
{
	/* FIXED_GSO: the inner MSS was already derived from the tunnel
	 * device MTU, which accounts for the encapsulation overhead.
	 */
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET |
		      BPF_F_ADJ_ROOM_ENCAP_L4_UDP | l3_flag;

	if (geneve_inner_is_eth())
		flags |= BPF_F_ADJ_ROOM_ENCAP_L2(ETH_HLEN) |
			 BPF_F_ADJ_ROOM_ENCAP_L2_ETH;
	return flags;
}

/* Write the UDP and Geneve headers plus TLVs and, in Ethernet mode, the
 * inner Ethernet header behind them. @off is the offset of the UDP header.
 * Runs on the grown packet, so failures are DROP_GENEVE_ENCAP_FAILED.
 */
static __always_inline int
__geneve_encap_finish(struct __ctx_buff *ctx, __u32 off, __u16 udp_len,
		      __be16 sport, __u32 vni, const struct ethhdr *inner_eth,
		      const __u8 *opt, __u32 opt_len)
{
	struct {
		struct udphdr udp;
		struct genevehdr geneve;
	} __packed hdr __align_stack_8;

	hdr.udp.source = sport;
	hdr.udp.dest = bpf_htons(CONFIG(tunnel_port));
	hdr.udp.len = bpf_htons(udp_len);
	/* Zero UDP checksum. Over IPv4 the kernel path sends zero as well
	 * (BPF_F_ZERO_CSUM_TX in ctx_set_encap_info4()). Over IPv6 this is a
	 * deliberate wire difference: the kernel path checksums, as
	 * ctx_set_encap_info6() leaves IP_TUNNEL_CSUM_BIT set (v6.18
	 * drivers/net/geneve.c L774, L1016-1021), but BPF can neither checksum
	 * the outer header of a GSO packet nor request
	 * SKB_GSO_UDP_TUNNEL_CSUM. RFC 8926 section 3.3 permits a zero
	 * checksum over IPv6 (RFC 6935, RFC 6936), and geneve devices created
	 * without IFLA_GENEVE_REMOTE6, as the agent creates them, accept it
	 * (use_udp6_rx_checksums defaults to false, L1663).
	 */
	hdr.udp.check = 0;
	geneve_hdr_init(&hdr.geneve,
			geneve_inner_is_eth() ? bpf_htons(ETH_P_TEB) : inner_eth->h_proto,
			vni, (__u8)(opt_len >> 2));

	if (ctx_store_bytes(ctx, off, &hdr, sizeof(hdr), 0) < 0)
		return DROP_GENEVE_ENCAP_FAILED;
	off += sizeof(hdr);

	if (opt_len && geneve_store_opts(ctx, off, opt, opt_len) < 0)
		return DROP_GENEVE_ENCAP_FAILED;
	off += opt_len;

	if (geneve_inner_is_eth() &&
	    ctx_store_bytes(ctx, off, inner_eth, ETH_HLEN, 0) < 0)
		return DROP_GENEVE_ENCAP_FAILED;

	return 0;
}

/* Encapsulate the packet in Geneve over IPv4.
 *
 * @sport is the outer UDP source port in network byte order (see
 * geneve_src_port()). @opt/@opt_len are the TLVs to emit, @opt_len being a
 * multiple of 4 and at most GENEVE_OPT_MAX_LEN. The outer Ethernet header
 * is a copy of the inner one with the ethertype updated; callers are
 * expected to rewrite the MAC addresses when redirecting.
 *
 * Returns 0 on success or a DROP_* reason. DROP_GENEVE_ENCAP_FAILED means
 * that encapsulation failed after the packet was modified. With any other
 * reason the packet is unmodified, so the caller may still pass it on. That
 * includes every bpf_skb_adjust_room() failure: in v6.18 all error returns
 * of bpf_skb_adjust_room() (net/core/filter.c L3703-3742) and
 * bpf_skb_net_grow() (L3499-3529) precede the header push at L3533, which
 * cannot fail (L3268), and the only later failure (skb_linearize() at
 * L3592) cannot happen with BPF_F_ADJ_ROOM_FIXED_GSO.
 */
static __always_inline int
geneve_encap4(struct __ctx_buff *ctx, __be32 saddr, __be32 daddr, __u32 vni,
	      __be16 sport, const __u8 *opt, __u32 opt_len)
{
	struct ethhdr inner_eth;
	struct ethhdr *eth;
	struct iphdr ip4 __align_stack_8;
	void *data, *data_end;
	__u16 room_len, udp_len;
	__u8 inner_tos;
	int ret;

	ret = __geneve_encap_prepare(ctx, &inner_eth, opt_len,
				     sizeof(struct geneve_encaphdr4), &room_len,
				     &inner_tos);
	if (ret < 0)
		return ret;

	/* Outer UDP length: everything from the UDP header to the end of the
	 * (inner) packet. For GSO packets the kernel rewrites the outer
	 * lengths per segment.
	 */
	udp_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN + room_len -
			  sizeof(struct iphdr));

	if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC,
			     __geneve_encap_room_flags(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4)))
		return DROP_INVALID;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(ip4) > data_end)
		return DROP_GENEVE_ENCAP_FAILED;

	eth = data;
	*eth = inner_eth;
	eth->h_proto = bpf_htons(ETH_P_IP);

	memset(&ip4, 0, sizeof(ip4));
	ip4.version = IPVERSION;
	ip4.ihl = sizeof(ip4) >> 2;
	ip4.tos = geneve_outer_tos(inner_tos);
	ip4.tot_len = bpf_htons((__u16)(udp_len + sizeof(ip4)));
	/* Ethernet mode: DF clear, as on the kernel path: Cilium never passes
	 * BPF_F_DONT_FRAGMENT, and geneve devices default to "df unset".
	 * Packets that exceed the route MTU are not encapsulated here but
	 * handed to the tunnel device (see geneve_handle_encap4()).
	 *
	 * ip mode: DF set. ip mode requires the path MTU between nodes to be
	 * at least the device MTU (see GENEVE_INNER_PROTO_IP): a packet that
	 * fits the route but not the path is lost with either DF value.
	 * Without DF it would be fragmented on the path, reassembled by the
	 * receiver's IP stack, which bypasses native decapsulation, and then
	 * dropped by the receiver's tunnel device, which only accepts Ethernet
	 * frames (v6.18 drivers/net/geneve.c L394-397). With DF the hop with
	 * the smaller MTU drops it right away and reports it with an ICMP
	 * error, sparing the path and the receiver the fragments.
	 */
	ip4.frag_off = geneve_inner_is_eth() ? 0 : bpf_htons(IP_DF);
	/* A fresh ID for every packet, as iptunnel_xmit() selects on the
	 * kernel path (v6.18 net/ipv4/ip_tunnel_core.c L82). Without DF the
	 * packet may be fragmented on the path, and RFC 6864 section 4.1
	 * forbids reusing its ID within the datagram lifetime: receivers
	 * reassemble by addresses, protocol and ID, so the fragments of
	 * packets sharing an ID would get mixed up. The kernel draws IDs from
	 * counters selected by a keyed hash of the addresses and protocol
	 * (net/ipv4/route.c L492-507), which BPF cannot access; a random ID
	 * serves the same purpose. GSO segmentation
	 * derives the IDs of the following segments from it, as on the kernel
	 * path (net/ipv4/af_inet.c L1424-1439). With DF (ip mode) the packet
	 * is atomic and any ID is valid; it is random there as well.
	 */
	ip4.id = bpf_htons((__u16)get_prandom_u32());
	ip4.ttl = IPDEFTTL;
	ip4.protocol = IPPROTO_UDP;
	ip4.saddr = saddr;
	ip4.daddr = daddr;
	ip4.check = geneve_ipv4_csum(&ip4);

	if (ctx_store_bytes(ctx, ETH_HLEN, &ip4, sizeof(ip4), 0) < 0)
		return DROP_GENEVE_ENCAP_FAILED;

	return __geneve_encap_finish(ctx, ETH_HLEN + sizeof(ip4), udp_len, sport,
				     vni, &inner_eth, opt, opt_len);
}

/* IPv6 counterpart of geneve_encap4(), with the same return values. */
static __always_inline int
geneve_encap6(struct __ctx_buff *ctx, const union v6addr *saddr,
	      const union v6addr *daddr, __u32 vni, __be16 sport,
	      const __u8 *opt, __u32 opt_len)
{
	struct ethhdr inner_eth;
	struct ethhdr *eth;
	struct ipv6hdr ip6 __align_stack_8;
	void *data, *data_end;
	__u16 room_len, udp_len;
	__u8 inner_tos, tos;
	int ret;

	ret = __geneve_encap_prepare(ctx, &inner_eth, opt_len,
				     sizeof(struct geneve_encaphdr6), &room_len,
				     &inner_tos);
	if (ret < 0)
		return ret;

	udp_len = (__u16)(ctx_full_len(ctx) - ETH_HLEN + room_len -
			  sizeof(struct ipv6hdr));

	if (ctx_adjust_hroom(ctx, room_len, BPF_ADJ_ROOM_MAC,
			     __geneve_encap_room_flags(BPF_F_ADJ_ROOM_ENCAP_L3_IPV6)))
		return DROP_INVALID;

	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + ETH_HLEN + sizeof(ip6) > data_end)
		return DROP_GENEVE_ENCAP_FAILED;

	eth = data;
	*eth = inner_eth;
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	tos = geneve_outer_tos(inner_tos);
	memset(&ip6, 0, sizeof(ip6));
	ip6.version = 6;
	ip6.priority = tos >> 4;
	ip6.flow_lbl[0] = (__u8)(tos << 4);
	ip6.payload_len = bpf_htons(udp_len);
	ip6.nexthdr = IPPROTO_UDP;
	ip6.hop_limit = IPDEFTTL;
	ipv6_addr_copy((union v6addr *)&ip6.saddr, saddr);
	ipv6_addr_copy((union v6addr *)&ip6.daddr, daddr);

	if (ctx_store_bytes(ctx, ETH_HLEN, &ip6, sizeof(ip6), 0) < 0)
		return DROP_GENEVE_ENCAP_FAILED;

	return __geneve_encap_finish(ctx, ETH_HLEN + sizeof(ip6), udp_len, sport,
				     vni, &inner_eth, opt, opt_len);
}
