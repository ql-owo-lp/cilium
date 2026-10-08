/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Native (BPF-built) Geneve datapath, program side. See geneve.h for the
 * wire format and the header builders.
 *
 * Egress: geneve_encap_and_redirect() replaces the redirect to the kernel
 * tunnel device. It stages the tunnel key and TLVs in the per-CPU egress
 * metadata slot and tail calls into bpf_overlay's pinned prog array
 * (cilium_calls_bpf_overlay). There, tail_geneve_to_overlay() runs the same
 * pipeline as cil_to_overlay (NodePort rev-DNAT/SNAT; the bandwidth manager
 * is left to cil_to_netdev, see handle_to_overlay()).
 * Every CTX_ACT_OK exit of that pipeline goes through
 * geneve_overlay_egress_exit(), which hands packets marked with
 * TC_INDEX_F_BPF_GENEVE_ENCAP to tail_geneve_encap4/6() for encapsulation
 * and a FIB redirect to the underlay device. Packets that cannot be
 * encapsulated natively are redirected to the kernel tunnel device instead.
 *
 * Ingress: cil_from_netdev (bpf_host) recognises Geneve packets addressed
 * to this node, applies host firewall ingress policy to the outer packet,
 * decapsulates with geneve_decap4/6() (tunnel key into the per-CPU ingress
 * slot, TC_INDEX_F_BPF_GENEVE_DECAP set) and tail calls
 * tail_geneve_from_overlay(), which behaves like cil_from_overlay except
 * that the tunnel key is read from the slot.
 *
 * The kernel tunnel device stays in place: cil_from_overlay/cil_to_overlay
 * keep serving packets that still take the kernel path (e.g. multicast, or
 * received packets the native datapath leaves to the kernel).
 */

#include "common.h"

#if __ctx_is == __ctx_skb && defined(ENABLE_BPF_GENEVE)

#include "geneve.h"
#include "tailcall.h"
#include "dbg.h"
#include "eps.h"
#include "fib.h"
#include "identity.h"
#include "ipv4.h"
#include "ipv6.h"
#include "l4.h"
#include "vtep.h"

/* Slots of cilium_calls_bpf_overlay. The map is created and populated by
 * bpf_overlay and entered from bpf_host (ingress) and from every object that
 * encapsulates (egress).
 */
#define GENEVE_CALL_FROM_OVERLAY	0
#define GENEVE_CALL_TO_OVERLAY		1
#define GENEVE_CALL_SIZE		2

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, GENEVE_CALL_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, int ());
} cilium_calls_bpf_overlay __section_maps_btf;

/* Egress entry point, called where the kernel path would redirect to the
 * tunnel device (see __encap_with_nodeid()). Does not return on success.
 * DROP_MISSED_TAIL_CALL means that bpf_overlay has not populated the prog
 * array (yet).
 *
 * @opt_len must be a compile time constant (it is: the only TLV emitted is
 * the DSR option).
 */
static __always_inline int
geneve_encap_and_redirect(struct __ctx_buff *ctx,
			  const struct remote_endpoint_info *info,
			  __u32 seclabel, __u32 vni, const void *opt, __u32 opt_len)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);

	if (!meta)
		return DROP_INVALID;
	if (opt_len > GENEVE_OPT_MAX_LEN || (opt_len & 3))
		return DROP_INVALID;

	if (info->flag_ipv6_tunnel_ep) {
		meta->family = AF_INET6;
		meta->vni = get_tunnel_id(seclabel);
		/* Word by word like ctx_set_encap_info6(): @info can live on
		 * the stack (fake_info), where the tunnel endpoint is only 4
		 * byte aligned and wider loads are rejected by the verifier.
		 */
		meta->ip6.daddr.p1 = info->tunnel_endpoint.ip6.p1;
		meta->ip6.daddr.p2 = info->tunnel_endpoint.ip6.p2;
		meta->ip6.daddr.p3 = info->tunnel_endpoint.ip6.p3;
		meta->ip6.daddr.p4 = info->tunnel_endpoint.ip6.p4;
	} else {
		meta->family = AF_INET;
		/* Same VNI selection as ctx_set_encap_info4(). */
		if (CONFIG(enable_vtep) && vni != NOT_VTEP_DST)
			meta->vni = get_tunnel_id(vni);
		else
			meta->vni = get_tunnel_id(seclabel);
		meta->ip4.daddr = info->tunnel_endpoint.ip4.be32;
		cilium_dbg(ctx, DBG_ENCAP, meta->ip4.daddr, seclabel);
	}

	meta->opt_len = (__u8)opt_len;
	if (opt_len)
		__bpf_memcpy_builtin(meta->raw_opts, opt, opt_len);
	meta->magic = GENEVE_META_MAGIC;

	tail_call_static(ctx, cilium_calls_bpf_overlay, GENEVE_CALL_TO_OVERLAY);
	meta->magic = 0;
	return DROP_MISSED_TAIL_CALL;
}

#ifdef IS_BPF_OVERLAY
/* Replacement for ctx_get_tunnel_opt() on the from-overlay path. Natively
 * decapsulated packets carry no kernel tunnel metadata, their TLVs are in
 * the ingress slot instead. All other packets come from the kernel tunnel
 * device.
 *
 * Mirrors the bpf_skb_get_tunnel_opt() helper exactly: -ENOENT without
 * options and -ENOMEM if @size is smaller than the options, with @opt zeroed
 * in both cases; otherwise the options are copied, the remainder of @opt is
 * zeroed and the length of the options is returned.
 *
 * @size must be a compile time constant multiple of 4 and @opt 4 byte
 * aligned, which holds for the DSR option structs this is used with.
 */
static __always_inline int
geneve_get_tunnel_opt(struct __ctx_buff *ctx, void *opt, const __u32 size)
{
	const struct geneve_metadata *meta;
	__u32 *words = opt;
	int ret;
	__u32 i;

	if (!ctx_bpf_geneve_decap_is_set(ctx))
		return ctx_get_tunnel_opt(ctx, opt, size);

	meta = geneve_meta_slot(GENEVE_META_INGRESS);
	if (!meta || meta->magic != GENEVE_META_MAGIC || !meta->opt_len)
		ret = -ENOENT;
	else if (size < meta->opt_len)
		ret = -ENOMEM;
	else
		ret = meta->opt_len;

#pragma unroll
	for (i = 0; i < size / 4; i++) {
		if (meta && ret > 0 && i * 4 < (__u32)ret)
			words[i] = ((const __u32 *)meta->raw_opts)[i];
		else
			words[i] = 0;
	}

	return ret;
}

/* Last step of the to-overlay pipeline for packets that entered through
 * tail_geneve_to_overlay(): they must not leave with CTX_ACT_OK, as that
 * would hand them un-encapsulated to the stack of the device the chain
 * started on. They are passed to tail_geneve_encap4/6() instead. All other
 * verdicts, and packets on the kernel path, pass through unchanged.
 *
 * Invariant: the to-overlay pipeline can only return CTX_ACT_OK from the
 * end of handle_to_overlay() (bpf_overlay.c) and from the ends of
 * tail_handle_nat_fwd_ipv4/6() and tail_handle_snat_fwd_ipv4/6()
 * (nodeport_egress.h), which handle_nat_fwd() calls or tail calls into. Each
 * of them passes its verdict through this function. Any new CTX_ACT_OK exit
 * of the to-overlay pipeline must do the same.
 *
 * The outer family is the underlay family, which the agent only allows to
 * be an enabled IP family; hence the ENABLE_IPV4/6 guards.
 */
static __always_inline int
geneve_overlay_egress_exit(struct __ctx_buff *ctx, int ret, __s8 *ext_err)
{
	const struct geneve_metadata *meta;

	if (ret != CTX_ACT_OK || !ctx_bpf_geneve_encap_is_set(ctx))
		return ret;

	meta = geneve_meta_slot(GENEVE_META_EGRESS);
	if (!meta || meta->magic != GENEVE_META_MAGIC)
		return DROP_NO_TUNNEL_KEY;

#ifdef ENABLE_IPV6
	if (meta->family == AF_INET6)
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_ENCAP6, ext_err);
#endif
#ifdef ENABLE_IPV4
	if (meta->family == AF_INET)
		return tail_call_internal(ctx, CILIUM_CALL_GENEVE_ENCAP4, ext_err);
#endif
	return DROP_NO_TUNNEL_KEY;
}

/* Outer L3 length of the packet once @encap_len bytes of encapsulation (see
 * geneve_encap_room()) are added. For a GSO packet this is the length of its
 * largest segment, computed like dsr_wire_len() from the inner L3 and L4
 * header lengths and gso_size. GSO packets whose headers cannot be parsed
 * are accounted with their full length, which at worst makes them take the
 * kernel tunnel device.
 */
static __always_inline __u32
geneve_wire_len(struct __ctx_buff *ctx, __u32 encap_len)
{
	__u32 len = encap_len + (__u32)ctx_full_len(ctx) - ETH_HLEN;
	__u32 gso_size = ctx_gso_size(ctx);
	__u32 l3_len, l4_len;
	__be16 proto;
	__u8 nexthdr;

	if (!gso_size)
		return len;
	if (ctx_load_bytes(ctx, offsetof(struct ethhdr, h_proto), &proto,
			   sizeof(proto)) < 0)
		return len;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct iphdr ip4;

		if (ctx_load_bytes(ctx, ETH_HLEN, &ip4, sizeof(ip4)) < 0)
			return len;
		l3_len = ipv4_hdrlen(&ip4);
		nexthdr = ip4.protocol;
		break;
	}
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		int hdrlen;

		if (ctx_load_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr),
				   &nexthdr, sizeof(nexthdr)) < 0)
			return len;
		hdrlen = ipv6_hdrlen(ctx, &nexthdr);
		if (hdrlen < 0)
			return len;
		l3_len = hdrlen;
		break;
	}
#endif
	default:
		return len;
	}

	switch (nexthdr) {
	case IPPROTO_TCP:
		if (l4_load_tcp_hdrlen(ctx, ETH_HLEN + l3_len, &l4_len) < 0)
			return len;
		break;
	case IPPROTO_UDP:
		l4_len = sizeof(struct udphdr);
		break;
	default:
		return len;
	}

	return encap_len + l3_len + l4_len + gso_size;
}

/* Look up the underlay route to @daddr for a Geneve packet with UDP source
 * port @sport and an outer L3 length of @wire_len.
 *
 * The flow is the one the kernel path looks up in udp_tunnel_dst_lookup()
 * and udp_tunnel6_dst_lookup() (v6.18 net/ipv4/udp_tunnel_core.c L230-276,
 * net/ipv6/ip6_udp_tunnel.c L135-182): UDP to the tunnel port, without a
 * source address since the kernel path never sets one. Multipath routes thus
 * pick the same next hop for a flow on both paths. Two differences remain:
 * like all of Cilium's FIB lookups this is an input lookup on the device the
 * program runs on, and policy routing rules on the packet mark (flowi4_mark
 * on the kernel path) are not applied.
 *
 * With @wire_len, the kernel checks the packet against the route MTU, PMTU
 * exceptions included, and returns BPF_FIB_LKUP_RET_FRAG_NEEDED if it does
 * not fit. With BPF_FIB_LOOKUP_SRC, it returns the preferred source address
 * of the route, the address the kernel path would use.
 */
static __always_inline int
geneve_fib_lookup(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib_params,
		  int family, const void *daddr, __be16 sport, __u16 wire_len)
{
	int flags = CONFIG(supports_fib_lookup_src) ? BPF_FIB_LOOKUP_SRC : 0;

	fib_params->l.l4_protocol = IPPROTO_UDP;
	fib_params->l.sport = sport;
	fib_params->l.dport = bpf_htons(CONFIG(tunnel_port));
	fib_params->l.tot_len = wire_len;

#ifdef ENABLE_IPV6
	if (family == AF_INET6) {
		struct in6_addr zero = {};

		return fib_lookup_v6(ctx, fib_params, &zero, daddr, flags);
	}
#endif
#ifdef ENABLE_IPV4
	if (family == AF_INET)
		return fib_lookup_v4(ctx, fib_params, 0, *(const __be32 *)daddr,
				     flags);
#endif
	return BPF_FIB_LKUP_RET_NOT_FWDED;
}

/* Hand a packet that cannot be encapsulated natively, and has not been
 * modified, to the kernel tunnel device instead. It gets the tunnel key and
 * options that ctx_set_encap_info4/6() set on the kernel path (@meta holds
 * the VNI those would pick), so from here on the tunnel device treats it
 * like any packet of the kernel path: route lookup, PMTU handling,
 * fragmentation, ICMP errors. As the packet has completed the to-overlay
 * pipeline already, the marker makes cil_to_overlay let it through (see
 * geneve_fallback_to_overlay()).
 */
static __always_inline int
geneve_encap_fallback(struct __ctx_buff *ctx, struct geneve_metadata *meta)
{
	struct bpf_tunnel_key key = {};
	__u32 flags = BPF_F_ZERO_CSUM_TX;
	int ret;

	key.tunnel_id = meta->vni;
	if (meta->family == AF_INET6) {
		key.remote_ipv6[0] = meta->ip6.daddr.p1;
		key.remote_ipv6[1] = meta->ip6.daddr.p2;
		key.remote_ipv6[2] = meta->ip6.daddr.p3;
		key.remote_ipv6[3] = meta->ip6.daddr.p4;
		flags = BPF_F_TUNINFO_IPV6;
	} else {
		key.remote_ipv4 = bpf_ntohl(meta->ip4.daddr);
	}

	ret = ctx_set_encap_info(ctx, &key, TUNNEL_KEY_WITHOUT_SRC_IP,
				 meta->raw_opts, meta->opt_len, flags);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	ctx_bpf_geneve_fallback_set(ctx);
	return (int)ctx_redirect(ctx, ENCAP_IFINDEX, 0);
}

#ifdef ENABLE_IPV4
/* Body of tail_geneve_encap4(): consume the egress slot, encapsulate and
 * redirect to the underlay device. Native egress must not drop packets that
 * the kernel path would send, so packets that cannot take this path while
 * still unmodified go to the tunnel device (geneve_encap_fallback()):
 *  - packets that exceed the route MTU, which the kernel path fragments or
 *    answers with ICMP errors;
 *  - FIB results other than SUCCESS and NO_NEIGH, so that the kernel path
 *    produces its usual outcome;
 *  - packets without a usable outer source address;
 *  - packets geneve_encap4() fails to encapsulate without modifying them
 *    (any reason but DROP_GENEVE_ENCAP_FAILED), e.g. because
 *    bpf_skb_adjust_room() fails with -EALREADY for an skb that has
 *    skb->encapsulation set already.
 * Returns the redirect verdict or a DROP_* reason.
 */
static __always_inline int
geneve_handle_encap4(struct __ctx_buff *ctx, __s8 *ext_err)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	struct bpf_fib_lookup_padded fib_params = {};
	__u32 vni, opt_len, wire_len;
	__be32 saddr, daddr;
	__be16 sport;
	int ret, fib_ret;

	/* Leaving the to-overlay pipeline, the marker has done its job. */
	ctx_bpf_geneve_encap_clear(ctx);

	if (!meta || meta->magic != GENEVE_META_MAGIC || meta->family != AF_INET)
		return DROP_NO_TUNNEL_KEY;
	/* Consume the slot; its contents stay valid until this program ends. */
	meta->magic = 0;
	vni = meta->vni;
	daddr = meta->ip4.daddr;
	opt_len = meta->opt_len;

	/* Chosen before the FIB lookup, which takes it into account. */
	sport = geneve_src_port(geneve_flow_hash(ctx, vni, daddr));
	wire_len = geneve_wire_len(ctx, geneve_encap_room(sizeof(struct geneve_encaphdr4),
							  opt_len));
	if (wire_len > 0xffff)
		goto fallback;

	fib_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET, &daddr, sport,
				    (__u16)wire_len);
	if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS &&
	    fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		goto fallback;

	/* Without BPF_FIB_LOOKUP_SRC the lookup leaves ipv4_src at 0. Use the
	 * address of the direct routing device then, which is the address
	 * remote nodes know this node by.
	 */
	saddr = fib_params.l.ipv4_src;
	if (!saddr)
		saddr = CONFIG(ipv4_direct_routing).be32;
	if (!saddr)
		goto fallback;

	ret = geneve_encap4(ctx, saddr, daddr, vni, sport, meta->raw_opts, opt_len);
	if (ret == DROP_GENEVE_ENCAP_FAILED)
		return ret;
	if (ret < 0)
		goto fallback;

	return fib_do_redirect(ctx, false, &fib_params, false, fib_ret,
			       fib_params.l.ifindex, ext_err);
fallback:
	return geneve_encap_fallback(ctx, meta);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/* IPv6 counterpart of geneve_handle_encap4(). */
static __always_inline int
geneve_handle_encap6(struct __ctx_buff *ctx, __s8 *ext_err)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_EGRESS);
	struct bpf_fib_lookup_padded fib_params = {};
	__u32 vni, opt_len, wire_len;
	union v6addr saddr, daddr;
	__be16 sport;
	int ret, fib_ret;

	ctx_bpf_geneve_encap_clear(ctx);

	if (!meta || meta->magic != GENEVE_META_MAGIC || meta->family != AF_INET6)
		return DROP_NO_TUNNEL_KEY;
	meta->magic = 0;
	vni = meta->vni;
	ipv6_addr_copy(&daddr, &meta->ip6.daddr);
	opt_len = meta->opt_len;

	sport = geneve_src_port(geneve_flow_hash(ctx, vni, daddr.p4));
	wire_len = geneve_wire_len(ctx, geneve_encap_room(sizeof(struct geneve_encaphdr6),
							  opt_len));
	if (wire_len > 0xffff)
		goto fallback;

	fib_ret = geneve_fib_lookup(ctx, &fib_params, AF_INET6, &daddr, sport,
				    (__u16)wire_len);
	if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS &&
	    fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH)
		goto fallback;

	ipv6_addr_copy(&saddr, (const union v6addr *)&fib_params.l.ipv6_src);
	if (!(saddr.d1 | saddr.d2))
		saddr = CONFIG(ipv6_direct_routing);
	if (!(saddr.d1 | saddr.d2))
		goto fallback;

	ret = geneve_encap6(ctx, &saddr, &daddr, vni, sport, meta->raw_opts, opt_len);
	if (ret == DROP_GENEVE_ENCAP_FAILED)
		return ret;
	if (ret < 0)
		goto fallback;

	return fib_do_redirect(ctx, false, &fib_params, false, fib_ret,
			       fib_params.l.ifindex, ext_err);
fallback:
	return geneve_encap_fallback(ctx, meta);
}
#endif /* ENABLE_IPV6 */
#endif /* IS_BPF_OVERLAY */

#ifdef IS_BPF_HOST
/* Inner protocols the native datapath decapsulates. Everything else is left
 * to the kernel tunnel device and cil_from_overlay, exactly as without the
 * native datapath. That includes ARP (VTEP): tail_handle_arp() requires the
 * kernel's tunnel key, and only for IP can skb->protocol be updated to the
 * inner protocol (see geneve_strip()).
 */
static __always_inline bool geneve_inner_proto_ok(__be16 inner_proto)
{
	switch (inner_proto) {
	case bpf_htons(ETH_P_IP):
		return is_defined(ENABLE_IPV4);
	case bpf_htons(ETH_P_IPV6):
		return is_defined(ENABLE_IPV6);
	default:
		return false;
	}
}

/* Checks on the UDP and Geneve base headers at @off (and on the inner
 * protocol) that decide whether a packet is natively decapsulated. Anything
 * failing them continues on the regular path exactly like before, and is
 * decapsulated by the kernel. OAM (control) frames are among those: the
 * kernel device delivers them like data frames.
 */
static __always_inline bool
geneve_ingress_hdr_ok(struct __ctx_buff *ctx, __u32 off)
{
	struct {
		struct udphdr udp;
		struct genevehdr geneve;
	} __packed hdr;
	__be16 inner_proto;

	if (ctx_load_bytes(ctx, off, &hdr, sizeof(hdr)) < 0)
		return false;
	if (hdr.udp.dest != bpf_htons(CONFIG(tunnel_port)) ||
	    hdr.geneve.ver != GENEVE_VERSION || hdr.geneve.control)
		return false;

	inner_proto = hdr.geneve.protocol_type;
	if (inner_proto == bpf_htons(ETH_P_TEB) &&
	    ctx_load_bytes(ctx, off + sizeof(hdr) + (hdr.geneve.opt_len << 2) +
			   offsetof(struct ethhdr, h_proto),
			   &inner_proto, sizeof(inner_proto)) < 0)
		return false;

	return geneve_inner_proto_ok(inner_proto);
}

/* Is this a Geneve packet addressed to this node that the native datapath
 * should decapsulate? Only the common case is taken: no IP options or
 * extension headers, not a fragment, received on a device with an Ethernet
 * header and, in Ethernet mode, not a GSO packet. The destination check
 * mirrors how remote nodes address us: the direct routing address first,
 * then any other local host address known to the ipcache.
 *
 * GSO packets are GRO aggregates built by the kernel's UDP tunnel GRO. Their
 * skb->encapsulation and SKB_GSO_UDP_TUNNEL state is reset by the kernel
 * tunnel device on decapsulation (v6.18 iptunnel_pull_offloads(),
 * include/net/ip_tunnels.h L631-645); left stale, it would break
 * segmentation of the inner packet when it is forwarded. Only
 * bpf_skb_adjust_room() with BPF_F_ADJ_ROOM_DECAP_L4_UDP, added in bpf-next
 * by 3a39c214fd2c and ec20dee2f2c4
 * (https://lore.kernel.org/bpf/20260812083115.73100-1-nhudson@akamai.com/),
 * resets it as well. In Ethernet mode they are therefore left to the kernel
 * device; using that flag where available would lift this restriction. In
 * ip mode the kernel device would drop them (v6.18 drivers/net/geneve.c
 * L394-397), so they are decapsulated natively, with that flag (see
 * geneve_strip()).
 *
 * L2-less devices are left to the kernel device as well: the decapsulated
 * packet continues in bpf_overlay, which expects an Ethernet header.
 *
 * So are frames sent to another host's MAC address (PACKET_OTHERHOST, seen
 * in promiscuous mode), which the stack drops (v6.18 net/ipv4/ip_input.c
 * L469-473, net/ipv6/ip6_input.c L156-160): the native datapath must
 * neither accept what the kernel path drops nor drop what it delivers.
 */
#ifdef ENABLE_IPV4
static __always_inline bool
geneve_is_native_ingress4(struct __ctx_buff *ctx, const struct iphdr *ip4)
{
	const struct remote_endpoint_info *info;

	if (THIS_IS_L3_DEV || ctx->pkt_type == PACKET_OTHERHOST)
		return false;
	if (ip4->protocol != IPPROTO_UDP || ipv4_hdrlen(ip4) != sizeof(*ip4) ||
	    (ip4->frag_off & ~bpf_htons(IP_DF)) ||
	    (geneve_inner_is_eth() && ctx_gso_size(ctx)))
		return false;
	if (!geneve_ingress_hdr_ok(ctx, ETH_HLEN + sizeof(*ip4)))
		return false;

	if (ip4->daddr == CONFIG(ipv4_direct_routing).be32)
		return true;
	info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
	return info && info->sec_identity == HOST_ID;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline bool
geneve_is_native_ingress6(struct __ctx_buff *ctx, const struct ipv6hdr *ip6)
{
	const struct remote_endpoint_info *info;
	union v6addr direct_routing = CONFIG(ipv6_direct_routing);

	if (THIS_IS_L3_DEV || ctx->pkt_type == PACKET_OTHERHOST)
		return false;
	/* Extension headers are never emitted by Cilium's encapsulation. */
	if (ip6->nexthdr != IPPROTO_UDP ||
	    (geneve_inner_is_eth() && ctx_gso_size(ctx)))
		return false;
	if (!geneve_ingress_hdr_ok(ctx, ETH_HLEN + sizeof(*ip6)))
		return false;

	if (ipv6_addr_equals((const union v6addr *)&ip6->daddr, &direct_routing))
		return true;
	info = lookup_ip6_remote_endpoint((const union v6addr *)&ip6->daddr, 0);
	return info && info->sec_identity == HOST_ID;
}
#endif /* ENABLE_IPV6 */

/* Validate the Geneve header behind the outer UDP header @udp at @l4_off,
 * @l4_len being the L3 payload length, and stage its TLVs in @meta. On
 * success @eth is the Ethernet header of the decapsulated packet (the inner
 * one in Ethernet mode, a copy of the outer one with the inner ethertype
 * otherwise) and @strip_len the number of bytes to remove behind the outer
 * Ethernet header.
 *
 * The TLVs are validated in the slot itself, which is still invalid
 * (magic 0) at this point; it only becomes valid once the packet has been
 * decapsulated, so a dropped packet never leaves a valid-looking slot.
 */
static __always_inline int
geneve_decap_prepare(struct __ctx_buff *ctx, struct geneve_metadata *meta,
		     const struct udphdr *udp, const struct genevehdr *geneve,
		     __u32 l4_len, __u32 l4_off, struct ethhdr *eth,
		     __u32 *strip_len)
{
	__u32 opt_len = (__u32)geneve->opt_len << 2;
	__u32 opts_off = l4_off + sizeof(*udp) + sizeof(*geneve);
	bool teb = geneve->protocol_type == bpf_htons(ETH_P_TEB);
	__u32 udp_len = bpf_ntohs(udp->len);

	if (udp->dest != bpf_htons(CONFIG(tunnel_port)) ||
	    geneve->ver != GENEVE_VERSION || geneve->control)
		return DROP_GENEVE_HDR_INVALID;
	if (udp_len > l4_len ||
	    udp_len < sizeof(*udp) + sizeof(*geneve) + opt_len + (teb ? ETH_HLEN : 0))
		return DROP_GENEVE_HDR_INVALID;

	*strip_len = opts_off + opt_len - ETH_HLEN;
	if (teb) {
		if (ctx_load_bytes(ctx, opts_off + opt_len, eth, ETH_HLEN) < 0)
			return DROP_GENEVE_HDR_INVALID;
		*strip_len += ETH_HLEN;
	} else {
		if (ctx_load_bytes(ctx, 0, eth, ETH_HLEN) < 0)
			return DROP_INVALID;
		eth->h_proto = geneve->protocol_type;
	}
	if (!geneve_inner_proto_ok(eth->h_proto))
		return DROP_UNKNOWN_L3;

	meta->vni = geneve_hdr_vni(geneve);
	meta->opt_len = 0;
	if (opt_len) {
		if (geneve_load_opts(ctx, opts_off, meta->raw_opts, opt_len) < 0)
			return DROP_GENEVE_HDR_INVALID;
		if (!geneve_validate_opts(meta->raw_opts, opt_len))
			return DROP_GENEVE_OPT_INVALID;
		meta->opt_len = (__u8)opt_len;
	}

	return 0;
}

/* RFC 6040 section 4.2 (normal mode), as INET_ECN_decapsulate() applies it
 * on the kernel path: merge the ECN field of the removed outer header,
 * @outer_ecn, into the inner IP header (see geneve_ecn_decap()). A CE mark
 * on a packet whose inner header is not ECN-capable cannot be propagated,
 * RFC 6040 requires such packets to be dropped.
 */
static __always_inline int
geneve_decap_ecn(struct __ctx_buff *ctx, __u8 outer_ecn, __be16 inner_proto)
{
	__u8 old, new;
	int ecn;

	/* Never changes the inner header. */
	if (outer_ecn == GENEVE_ECN_NOT_ECT)
		return 0;

	switch (inner_proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		const __u32 off = ETH_HLEN + offsetof(struct iphdr, tos);

		if (ctx_load_bytes(ctx, off, &old, sizeof(old)) < 0)
			return DROP_INVALID;
		ecn = geneve_ecn_decap(outer_ecn, old & GENEVE_ECN_MASK);
		if (ecn < 0)
			return DROP_INVALID;
		new = (__u8)((old & ~GENEVE_ECN_MASK) | ecn);
		if (new == old)
			return 0;

		/* Together with the header checksum update the change is
		 * checksum neutral, a CHECKSUM_COMPLETE value stays valid.
		 * The TOS is the second byte of its 16 bit word.
		 */
		if (ctx_store_bytes(ctx, off, &new, sizeof(new), 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv4_csum_update_by_value(ctx, ETH_HLEN, bpf_htons(old),
					      bpf_htons(new), 2) < 0)
			return DROP_CSUM_L3;
		return 0;
	}
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		/* The ECN field is in bits 5:4 of the second byte. */
		const __u32 off = ETH_HLEN + offsetof(struct ipv6hdr, flow_lbl);

		if (ctx_load_bytes(ctx, off, &old, sizeof(old)) < 0)
			return DROP_INVALID;
		ecn = geneve_ecn_decap(outer_ecn, (old >> 4) & GENEVE_ECN_MASK);
		if (ecn < 0)
			return DROP_INVALID;
		new = (__u8)((old & ~(GENEVE_ECN_MASK << 4)) | (ecn << 4));
		if (new == old)
			return 0;

		/* No header checksum here, so let the helper keep a
		 * CHECKSUM_COMPLETE value valid.
		 */
		if (ctx_store_bytes(ctx, off, &new, sizeof(new),
				    BPF_F_RECOMPUTE_CSUM) < 0)
			return DROP_WRITE_ERROR;
		return 0;
	}
#endif /* ENABLE_IPV6 */
	default:
		return 0;
	}
}

/* Remove @strip_len bytes of encapsulation behind the Ethernet header,
 * install @eth as the new Ethernet header and apply the ECN field of the
 * removed outer header, @outer_ecn, to the inner one.
 */
static __always_inline int
geneve_strip(struct __ctx_buff *ctx, __u32 strip_len, __u8 outer_family,
	     __u8 outer_ecn, const struct ethhdr *eth)
{
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET;
	__be16 inner_proto = eth->h_proto;
	void *data, *data_end;
	__u32 pull_len;

	/* skb->protocol still describes the outer header and both the stack
	 * and redirect_neigh() dispatch on it. When the inner family differs,
	 * let the kernel fix it up (requires BPF_F_ADJ_ROOM_DECAP_L3_*,
	 * Linux 6.3+, which the agent checks for); otherwise it is already
	 * correct.
	 */
	if (outer_family == AF_INET && inner_proto == bpf_htons(ETH_P_IPV6))
		flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV6;
	else if (outer_family == AF_INET6 && inner_proto == bpf_htons(ETH_P_IP))
		flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4;

	/* ip mode decapsulates GSO packets as well (see
	 * geneve_is_native_ingress4()), whose UDP tunnel GSO state must be
	 * reset as the kernel tunnel device does: BPF_F_ADJ_ROOM_DECAP_L4_UDP
	 * clears it, and skb->encapsulation unless other tunnel GSO types
	 * remain. It combines with the DECAP_L3 flags and requires removing
	 * at least the outer IP and UDP headers, which always holds here.
	 * Kernels without it reject the flag; the agent defines
	 * HAVE_DECAP_L4_UDP to 0 when the kernel probe fails.
	 *
	 * On non-GSO packets it clears skb->encapsulation too, which drivers
	 * may set on receive (v6.18 drivers/net/ethernet/mellanox/mlx5/core/
	 * en_rx.c L1552-1554). Ethernet mode leaves it set: forwarded back
	 * into the tunnel, such a packet cannot be encapsulated natively
	 * (net/core/filter.c L3523-3524) and takes the tunnel device instead
	 * (see geneve_handle_encap4()).
	 */
#ifndef HAVE_DECAP_L4_UDP
# define HAVE_DECAP_L4_UDP 1
#endif
	if (!geneve_inner_is_eth() && HAVE_DECAP_L4_UDP)
		flags |= BPF_F_ADJ_ROOM_DECAP_L4_UDP;

	if (ctx_adjust_hroom(ctx, -(__s32)strip_len, BPF_ADJ_ROOM_MAC, flags) < 0)
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, 0, eth, ETH_HLEN, 0) < 0)
		return DROP_WRITE_ERROR;

	/* The outer UDP header is gone. The kernel's UDP receive path would
	 * have consumed one level of CHECKSUM_UNNECESSARY for it; do the same
	 * so that the inner L4 checksum is not taken as verified when the
	 * device only verified the outer one.
	 */
	csum_level(ctx, BPF_CSUM_LEVEL_DEC);

	/* The remaining side effects of the kernel's decapsulation, v6.18
	 * __iptunnel_pull_header() (net/ipv4/ip_tunnel_core.c L94-124) and
	 * geneve_rx() (drivers/net/geneve.c L224-337), besides the protocol,
	 * checksum, GSO and ECN handling here and the tunnel metadata, which
	 * the ingress slot carries instead:
	 *  - The VLAN tag is cleared (ip_tunnel_core.c L119). Only priority
	 *    tags (VLAN ID 0) get here, cil_from_netdev returns early for
	 *    other tagged packets. The kernel path removes such tags right
	 *    after tc ingress (net/core/dev.c L5982-6017) and so never
	 *    forwards them along with the decapsulated packet.
	 *  - The receive queue recorded by the underlay device is forgotten
	 *    (ip_tunnel_core.c L120). It would otherwise select the transmit
	 *    queue of a forwarded packet (net/core/dev.c L3503-3511), and the
	 *    bandwidth manager would take it for an endpoint's aggregate (see
	 *    edt_get_aggregate()).
	 *  - The hash is kept. The kernel keeps L4 hashes too and clears
	 *    others (ip_tunnel_core.c L118), which skb_get_hash() recomputes
	 *    from the inner headers either way (include/linux/skbuff.h
	 *    L1659-1665).
	 *  - skb_scrub_packet() (ip_tunnel_core.c L121, net/core/skbuff.c
	 *    L6174-6195) has nothing else to reset at tc ingress: no route or
	 *    conntrack entry is attached yet, and the mark and timestamp are
	 *    kept as the tunnel device is in the same namespace.
	 *  - pkt_type keeps the value of the outer frame, PACKET_HOST for
	 *    frames sent to this node's MAC address (frames sent to other
	 *    addresses take the kernel path, see geneve_is_native_ingress4()).
	 *    The kernel path sets it from the inner destination MAC address
	 *    instead (geneve.c L269), usually to PACKET_OTHERHOST, which
	 *    bpf_overlay overrides wherever it passes such packets to the
	 *    stack.
	 *  - The packet is not received again on the tunnel device (geneve.c
	 *    L329): it keeps the underlay device as skb->dev and ingress
	 *    ifindex (see tail_geneve_decap4() in bpf_host.c for what that
	 *    means for packets passed to the stack), the tunnel device
	 *    statistics are not updated, inner packets get no second GRO
	 *    pass, and there is no check against the tunnel device's own MAC
	 *    address (geneve.c L273-277), which catches looped multicast and
	 *    does not concern unicast addressed to this node.
	 */
	if (ctx->vlan_present && skb_vlan_pop(ctx) < 0)
		return DROP_INVALID;
	ctx->queue_mapping = 0;

	/* The programs that follow expect the inner L3 header to be linear. */
	pull_len = ETH_HLEN + (inner_proto == bpf_htons(ETH_P_IPV6) ?
			       sizeof(struct ipv6hdr) : sizeof(struct iphdr));
	data = ctx_data(ctx);
	data_end = ctx_data_end(ctx);
	if (data + pull_len > data_end && ctx_pull_data(ctx, pull_len) < 0)
		return DROP_INVALID;

	return geneve_decap_ecn(ctx, outer_ecn, inner_proto);
}

#ifdef ENABLE_IPV4
/* Validate and strip an IPv4 Geneve encapsulation. On success the packet
 * starts with the decapsulated Ethernet header and the ingress slot holds
 * the tunnel key.
 *
 * Like the kernel UDP receive path, a zero outer UDP checksum is accepted.
 * A non-zero one is not verified (that would require summing the whole
 * packet); the inner L4 checksum is still verified by the stack. The outer
 * IPv4 header checksum, which the IP layer would verify, is.
 */
static __always_inline int geneve_decap4(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);
	struct geneve_encaphdr4 *hdr;
	struct ethhdr eth;
	void *data, *data_end;
	__u32 strip_len, l3_len;
	__u8 outer_ecn;
	int ret;

	if (!meta)
		return DROP_INVALID;
	meta->magic = 0;

	if (!revalidate_data_pull(ctx, &data, &data_end, &hdr))
		return DROP_INVALID;

	if (hdr->ip.protocol != IPPROTO_UDP || hdr->ip.ihl != sizeof(hdr->ip) >> 2 ||
	    (hdr->ip.frag_off & ~bpf_htons(IP_DF)))
		return DROP_GENEVE_HDR_INVALID;
	if (geneve_ipv4_csum(&hdr->ip))
		return DROP_CSUM_L3;
	l3_len = bpf_ntohs(hdr->ip.tot_len);
	if (l3_len < sizeof(*hdr) || ETH_HLEN + l3_len > ctx_full_len(ctx))
		return DROP_INVALID;

	meta->family = AF_INET;
	meta->ip4.saddr = hdr->ip.saddr;
	meta->ip4.daddr = hdr->ip.daddr;
	outer_ecn = hdr->ip.tos & GENEVE_ECN_MASK;
	ret = geneve_decap_prepare(ctx, meta, &hdr->udp, &hdr->geneve,
				   l3_len - sizeof(hdr->ip),
				   ETH_HLEN + sizeof(hdr->ip), &eth, &strip_len);
	if (ret < 0)
		return ret;

	ret = geneve_strip(ctx, strip_len, AF_INET, outer_ecn, &eth);
	if (ret < 0)
		return ret;

	meta->magic = GENEVE_META_MAGIC;
	return 0;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int geneve_decap6(struct __ctx_buff *ctx)
{
	struct geneve_metadata *meta = geneve_meta_slot(GENEVE_META_INGRESS);
	struct geneve_encaphdr6 *hdr;
	struct ethhdr eth;
	void *data, *data_end;
	__u32 strip_len, l4_len;
	__u8 outer_ecn;
	int ret;

	if (!meta)
		return DROP_INVALID;
	meta->magic = 0;

	if (!revalidate_data_pull(ctx, &data, &data_end, &hdr))
		return DROP_INVALID;

	if (hdr->ip6.nexthdr != IPPROTO_UDP)
		return DROP_GENEVE_HDR_INVALID;
	l4_len = bpf_ntohs(hdr->ip6.payload_len);
	if (l4_len < sizeof(*hdr) - sizeof(hdr->ip6) ||
	    ETH_HLEN + sizeof(hdr->ip6) + l4_len > ctx_full_len(ctx))
		return DROP_INVALID;

	meta->family = AF_INET6;
	ipv6_addr_copy(&meta->ip6.saddr, (const union v6addr *)&hdr->ip6.saddr);
	ipv6_addr_copy(&meta->ip6.daddr, (const union v6addr *)&hdr->ip6.daddr);
	outer_ecn = (hdr->ip6.flow_lbl[0] >> 4) & GENEVE_ECN_MASK;
	ret = geneve_decap_prepare(ctx, meta, &hdr->udp, &hdr->geneve, l4_len,
				   ETH_HLEN + sizeof(hdr->ip6), &eth, &strip_len);
	if (ret < 0)
		return ret;

	ret = geneve_strip(ctx, strip_len, AF_INET6, outer_ecn, &eth);
	if (ret < 0)
		return ret;

	meta->magic = GENEVE_META_MAGIC;
	return 0;
}
#endif /* ENABLE_IPV6 */
#endif /* IS_BPF_HOST */

#endif /* __ctx_is == __ctx_skb && ENABLE_BPF_GENEVE */

#if !(__ctx_is == __ctx_skb && defined(ENABLE_BPF_GENEVE) && defined(IS_BPF_OVERLAY))
/* Without the native datapath, and outside bpf_overlay, the to-overlay
 * pipeline ends in the kernel tunnel device, which also provides all tunnel
 * options.
 */
static __always_inline int
geneve_overlay_egress_exit(struct __ctx_buff *ctx __maybe_unused, int ret,
			   __s8 *ext_err __maybe_unused)
{
	return ret;
}

# if __ctx_is == __ctx_skb
static __always_inline int
geneve_get_tunnel_opt(struct __ctx_buff *ctx, void *opt, const __u32 size)
{
	return ctx_get_tunnel_opt(ctx, opt, size);
}
# endif
#endif
