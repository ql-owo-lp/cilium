#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include <bpf/config/global.h>
#include "lib/common.h"
#include "lib/encap.h"
#include "lib/eth.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"
// bpf/lib/udp.h was not found, but linux/udp.h is included via bpf/lib/common.h
// #include "lib/udp.h"

#include "lib/eps.h"      // For remote_endpoint_info, IPV4_DIRECT_ROUTING
#include "lib/trace.h"    // For enum trace_reason, TRACE_PAYLOAD_LEN
#include "lib/l4.h"       // For l4_load_tcp_flags, TCP_FLAG_SYN (used by callers)
// #include "bpf/node_config.h" // For MTU (as THIS_MTU), WORLD_IPV4_ID, WORLD_IPV6_ID - Already included via common.h
#include "lib/fib.h"      // For add_l2_hdr

// Return codes for decap functions
#define DECAP_SUCCESS 0 // CTX_ACT_OK can be used if preferred and semantically equivalent
#define DECAP_SKIPPED 1 // Indicates packet was not decapsulated, but no error occurred.

// ETH_P_TEB Trans-Ethernet Bridging, used by Geneve
#ifndef ETH_P_TEB
#define ETH_P_TEB 0x6558
#endif

// Standard EtherType values if not available from included headers
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// struct genevehdr is defined in lib/tunnel.h, which is included via common.h
// struct genevehdr {
//	__u8 opt_len:6,
//	     ver:2;
//	__u8 flags; // Contains Critical bit, OAM bit, and Reserved bits
//	__be16 protocol_type;
//	__u8 vni[3];
//	__u8 rsvd; // Reserved
// };


static __always_inline int add_l2_hdr_if_needed(struct __ctx_buff *ctx) {
    if (ETH_HLEN == 0) { // If no L2 header is accounted for (e.g., XDP)
        return add_l2_hdr(ctx); // add_l2_hdr is in lib/fib.h
    }
    return 0; // If ETH_HLEN > 0, assume L2 space is present or managed by caller
}

static __always_inline bool geneve_mtu_check(struct __ctx_buff *ctx __maybe_unused, __u16 expanded_len)
{
/* MTU is defined in bpf/node_config.h, typically reflects device MTU */
#if defined(MTU) && defined(ENABLE_DSR_ICMP_ERRORS)
	if (expanded_len > MTU) {
		return true; /* Packet is too big */
	}
#endif
	return false; /* Packet is not too big or check is disabled */
}


/**
 * Decapsulates a GENEVE header.
 *
 * @param ctx Pointer to the context buffer.
 * @param l3_off_param Pointer to the L3 offset, will be updated to inner L3 offset on success.
 * @param data Pointer to the start of packet data, will be updated on success.
 * @param data_end Pointer to the end of packet data, will be updated on success.
 * @param ip4_param Pointer to store the IPv4 header, will be updated to inner IPv4 header on success.
 * @return DECAP_SUCCESS (0) on successful decapsulation.
 * @return DECAP_SKIPPED (1) if packet is not GENEVE or has options (no error, packet not modified by this function).
 * @return Negative error code (e.g., DROP_INVALID) on error.
 */
static __always_inline int geneve_decap(struct __ctx_buff *ctx, int *l3_off_param, void **data, void **data_end, struct iphdr **ip4_param)
{
	// Placeholder implementation before filling from bpf_xdp.c
	struct iphdr *outer_ip4 = *ip4_param; // Assuming ip4_param initially points to outer IP
	int current_l3_off = *l3_off_param;
	int l4_off;
	struct udphdr *udph;
	struct genevehdr *geneveh;
	__be16 dport;
	__sum16 udp_csum;
	__u16 inner_proto;
	int inner_l2_off;

	// 1. Check if outer IP protocol is UDP
	if (outer_ip4->protocol != IPPROTO_UDP) {
		goto no_decap;
	}

	// 2. Check for IP options
	if (ipv4_hdrlen(outer_ip4) != sizeof(*outer_ip4)) {
		goto no_decap;
	}

	// 3. Calculate l4_off
	l4_off = current_l3_off + sizeof(*outer_ip4);

	// 4. Load UDP destination port
	// Ensure udphdr is accessible
	if ((*data) + l4_off + sizeof(*udph) > (*data_end)) {
		return DROP_INVALID;
	}
	udph = (struct udphdr *)((*data) + l4_off);
	dport = udph->dest; // Direct access after ensuring bounds

	if (dport != bpf_htons(TUNNEL_PORT)) {
		goto no_decap;
	}

	// 5. Load UDP checksum
	udp_csum = udph->check; // Direct access

	// 6. If UDP checksum is not zero
	if (udp_csum != 0) {
		goto no_decap;
	}

	// 7. Load Geneve header
	// Ensure geneve header is accessible
	if ((*data) + l4_off + sizeof(*udph) + sizeof(*geneveh) > (*data_end)) {
		return DROP_INVALID;
	}
	geneveh = (struct genevehdr *)((*data) + l4_off + sizeof(*udph));
	
	// 8. Check geneve.protocol_type
	if (geneveh->protocol_type != bpf_htons(ETH_P_TEB)) {
		goto no_decap;
	}

	// 9. Check geneve.opt_len
	if (geneveh->opt_len != 0) {
		goto no_decap;
	}

	// 10. Calculate inner_l2_off
	inner_l2_off = l4_off + sizeof(*udph) + sizeof(*geneveh);

	// 11. Validate ethertype of inner packet
	if (!validate_ethertype_l2_off(ctx, inner_l2_off, &inner_proto)) {
		// This means header too short or unsupported ethertype by the function
		goto no_decap; 
	}
	if (inner_proto != bpf_htons(ETH_P_IP)) {
		goto no_decap;
	}

	// 12. Update *l3_off_param
	*l3_off_param = inner_l2_off + ETH_HLEN;

	// 13. Revalidate data for inner L3
	// The revalidate_data_l3_off function expects *ip4_param to be updated.
	// It also updates *data and *data_end internally if needed due to ctx_pull_data.
	// We need to ensure the pointers passed to it are the ones it expects to modify.
	if (!revalidate_data_l3_off(ctx, data, data_end, ip4_param, *l3_off_param)) {
		return DROP_INVALID;
	}

	return DECAP_SUCCESS; // Successfully decapsulated

no_decap:
	return DECAP_SKIPPED; // Not a Geneve packet for XDP or has options
}

/**
 * Encapsulates a packet with a GENEVE header (IPv4).
 *
 * @param ctx Pointer to the context buffer.
 * @param ip4 Pointer to the inner IPv4 header.
 * @param needs_options Whether Geneve options need to be added.
 * @param geneve_options Pointer to pre-constructed Geneve options (e.g., struct geneve_dsr_opt4).
 * @param geneve_opt_len Length of Geneve options.
 * @param info Pointer to remote endpoint information for the outer tunnel.
 * @param ct_reason Trace reason for observability.
 * @param monitor Monitor aggregation value.
 * @param ifindex Pointer to store the interface index for redirection.
 * @param ohead Pointer to store the overhead length if packet is too big.
 * @return CTX_ACT_REDIRECT on success, DROP_FRAG_NEEDED if too big, or other error code.
 */
static __always_inline int geneve_encap4(struct __ctx_buff *ctx, struct iphdr *ip4,
					 bool needs_options, void *geneve_options, int geneve_opt_len,
					 struct remote_endpoint_info *info,
					 enum trace_reason ct_reason, __u32 monitor,
					 int *ifindex, __u16 *ohead)
{
	__u16 payload_len = bpf_ntohs(ip4->tot_len);
	__u16 encap_len;
	int ret;

	/* Base encap length: OuterIP + UDP + Geneve + InnerEther */
	if (info->flag_ipv6_tunnel_ep)
		encap_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(struct genevehdr) + ETH_HLEN;
	else
		encap_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct genevehdr) + ETH_HLEN;

	if (needs_options) {
		encap_len += geneve_opt_len;
	}

	if (geneve_mtu_check(ctx, payload_len + encap_len)) {
		*ohead = encap_len;
		return DROP_FRAG_NEEDED;
	}

	ret = add_l2_hdr_if_needed(ctx);
	if (ret < 0)
		return ret;

	if (info->flag_ipv6_tunnel_ep) {
		// Inner is IPv4, Outer is IPv6
		if (needs_options) {
			ret = __encap_with_nodeid_opt6(ctx, &info->tunnel_endpoint.ip6,
						       WORLD_IPV4_ID, info->sec_identity,
						       geneve_options, geneve_opt_len,
						       ct_reason, monitor, ifindex);
		} else {
			ret = __encap_with_nodeid6(ctx, &info->tunnel_endpoint.ip6,
						   WORLD_IPV4_ID, info->sec_identity,
						   ct_reason, monitor, ifindex);
		}
	} else {
		// Inner is IPv4, Outer is IPv4
		if (needs_options) {
			ret = __encap_with_nodeid_opt4(ctx, IPV4_DIRECT_ROUTING, 0 /* src_port */,
						       info->tunnel_endpoint.ip4,
						       WORLD_IPV4_ID, info->sec_identity, NOT_VTEP_DST,
						       geneve_options, geneve_opt_len,
						       ct_reason, monitor, ifindex);
		} else {
			ret = __encap_with_nodeid4(ctx, IPV4_DIRECT_ROUTING, 0 /* src_port */,
						   info->tunnel_endpoint.ip4,
						   WORLD_IPV4_ID, info->sec_identity, NOT_VTEP_DST,
						   ct_reason, monitor, ifindex);
		}
	}
	return ret;
}

/**
 * Encapsulates a packet with a GENEVE header (IPv6 inner).
 *
 * @param ctx Pointer to the context buffer.
 * @param ip6 Pointer to the inner IPv6 header.
 * @param tunnel_src_port Source port for the outer UDP header (if outer is IPv4).
 * @param needs_options Whether Geneve options need to be added.
 * @param geneve_options Pointer to pre-constructed Geneve options (e.g., struct geneve_dsr_opt6).
 * @param geneve_opt_len Length of Geneve options.
 * @param info Pointer to remote endpoint information for the outer tunnel.
 * @param ct_reason Trace reason for observability.
 * @param monitor Monitor aggregation value.
 * @param ifindex Pointer to store the interface index for redirection.
 * @param ohead Pointer to store the overhead length if packet is too big.
 * @return CTX_ACT_REDIRECT on success, DROP_FRAG_NEEDED if too big, or other error code.
 */
static __always_inline int geneve_encap6(struct __ctx_buff *ctx, struct ipv6hdr *ip6,
					 __be16 tunnel_src_port, bool needs_options,
					 void *geneve_options, int geneve_opt_len,
					 struct remote_endpoint_info *info,
					 enum trace_reason ct_reason, __u32 monitor,
					 int *ifindex, __u16 *ohead)
{
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
	__u16 encap_len;
	int ret;

	/* Base encap length: OuterIP + UDP + Geneve + InnerEther */
	if (info->flag_ipv6_tunnel_ep)
		encap_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(struct genevehdr) + ETH_HLEN;
	else
		encap_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct genevehdr) + ETH_HLEN;


	if (needs_options) {
		encap_len += geneve_opt_len;
	}

	if (geneve_mtu_check(ctx, payload_len + encap_len)) {
		*ohead = encap_len;
		return DROP_FRAG_NEEDED;
	}

	ret = add_l2_hdr_if_needed(ctx);
	if (ret < 0)
		return ret;
	
	if (info->flag_ipv6_tunnel_ep) {
		// Inner is IPv6, Outer is IPv6
		if (needs_options) {
			ret = __encap_with_nodeid_opt6(ctx, &info->tunnel_endpoint.ip6,
						       WORLD_IPV6_ID, info->sec_identity,
						       geneve_options, geneve_opt_len,
						       ct_reason, monitor, ifindex);
		} else {
			ret = __encap_with_nodeid6(ctx, &info->tunnel_endpoint.ip6,
						   WORLD_IPV6_ID, info->sec_identity,
						   ct_reason, monitor, ifindex);
		}
	} else {
		// Inner is IPv6, Outer is IPv4
		if (needs_options) {
			ret = __encap_with_nodeid_opt4(ctx, IPV4_DIRECT_ROUTING, tunnel_src_port,
						       info->tunnel_endpoint.ip4,
						       WORLD_IPV6_ID, info->sec_identity, NOT_VTEP_DST,
						       geneve_options, geneve_opt_len,
						       ct_reason, monitor, ifindex);
		} else {
			ret = __encap_with_nodeid4(ctx, IPV4_DIRECT_ROUTING, tunnel_src_port,
						   info->tunnel_endpoint.ip4,
						   WORLD_IPV6_ID, info->sec_identity, NOT_VTEP_DST,
						   ct_reason, monitor, ifindex);
		}
	}
	return ret;
}
