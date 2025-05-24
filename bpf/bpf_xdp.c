// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include <bpf/api.h>

#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include <netdev_config.h>
#include <filter_config.h>

#define IS_BPF_XDP 1

/* WORLD_IPV{4,6}_ID varies based on dualstack being enabled. Real values are
 * written into node_config.h at runtime. */
#define SECLABEL WORLD_ID
#define SECLABEL_IPV4 WORLD_IPV4_ID
#define SECLABEL_IPV6 WORLD_IPV6_ID

/* Controls the inclusion of the CILIUM_CALL_HANDLE_ICMP6_NS section in the
 * bpf_lxc object file.
 */
#define SKIP_ICMPV6_NS_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED section
 * in the bpf_lxc object file. This is needed for all callers of
 * ipv6_local_delivery, which calls into the IPv6 L3 handling.
 */
#define SKIP_ICMPV6_HOPLIMIT_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

/* The XDP datapath does not take care of health probes from the local node,
 * thus do not compile it in.
 */
#undef ENABLE_HEALTH_CHECK

#include "lib/common.h"
#include "lib/eps.h"
#include "lib/events.h"
#include "lib/nodeport.h"
#include "lib/tailcall.h"
#include "lib/geneve.h"

#ifdef ENABLE_PREFILTER
#ifdef CIDR4_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_cidr_v4_fix __section_maps_btf;

#ifdef CIDR4_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_cidr_v4_dyn __section_maps_btf;

#endif /* CIDR4_LPM_PREFILTER */
#endif /* CIDR4_FILTER */

#ifdef CIDR6_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_cidr_v6_fix __section_maps_btf;

#ifdef CIDR6_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_cidr_v6_dyn __section_maps_btf;
#endif /* CIDR6_LPM_PREFILTER */
#endif /* CIDR6_FILTER */
#endif /* ENABLE_PREFILTER */

static __always_inline __maybe_unused int
bpf_xdp_exit(struct __ctx_buff *ctx, const int verdict)
{
	if (verdict == CTX_ACT_OK)
		ctx_move_xfer(ctx);

	return verdict;
}

#ifdef ENABLE_IPV4
#ifdef ENABLE_NODEPORT_ACCELERATION
__declare_tail(CILIUM_CALL_IPV4_FROM_NETDEV)
int tail_lb_ipv4(struct __ctx_buff *ctx)
{
	bool punt_to_stack = false;
	int ret = CTX_ACT_OK;
	__s8 ext_err = 0;

	if (!ctx_skip_nodeport(ctx)) {
		int l3_off = ETH_HLEN;
		void *data, *data_end;
		struct iphdr *ip4;
		bool __maybe_unused is_dsr = false;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto out;
		}

#if defined(ENABLE_DSR) && !defined(ENABLE_DSR_HYBRID) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
		{
			// Existing variables: l3_off, data, data_end, ip4 are already initialized.
			// data, data_end, and ip4 are pointers to the current (outer) packet view.
			// l3_off is the current L3 offset.
			
			int decap_ret = geneve_decap(ctx, &l3_off, &data, &data_end, &ip4);

			if (decap_ret < 0) { // Error like DROP_INVALID
				ret = decap_ret;
				goto out;
			}
			if (decap_ret == DECAP_SKIPPED) { // DECAP_SKIPPED = 1
				goto no_encap;
			}
			// if decap_ret == DECAP_SUCCESS (0), l3_off, data, data_end, and ip4 are now updated
			// and point to the inner packet. Processing continues.
		}
no_encap:
#endif /* ENABLE_DSR && !ENABLE_DSR_HYBRID && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE */

		ret = nodeport_lb4(ctx, ip4, l3_off, UNKNOWN_ID, &punt_to_stack, &ext_err, &is_dsr);
		if (ret == NAT_46X64_RECIRC)
			ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV,
						 &ext_err);
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err,
						  METRIC_INGRESS);

	return bpf_xdp_exit(ctx, ret);
}

static __always_inline int check_v4_lb(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
	int ret;

	ret = tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_NETDEV, &ext_err);
	return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, METRIC_INGRESS);
}
#else
static __always_inline int check_v4_lb(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct lpm_v4_key pfx __maybe_unused;

	if (ctx_no_room(ipv4_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR4_FILTER
	memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 32;

#ifdef CIDR4_LPM_PREFILTER
	if (map_lookup_elem(&cilium_cidr_v4_dyn, &pfx))
		return CTX_ACT_DROP;
#endif /* CIDR4_LPM_PREFILTER */
	return map_lookup_elem(&cilium_cidr_v4_fix, &pfx) ?
		CTX_ACT_DROP : check_v4_lb(ctx);
#else
	return check_v4_lb(ctx);
#endif /* CIDR4_FILTER */
}
#else
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
	return check_v4_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT_ACCELERATION
__declare_tail(CILIUM_CALL_IPV6_FROM_NETDEV)
int tail_lb_ipv6(struct __ctx_buff *ctx)
{
	bool punt_to_stack = false;
	int ret = CTX_ACT_OK;
	__s8 ext_err = 0;

	if (!ctx_skip_nodeport(ctx)) {
		void *data, *data_end;
		struct ipv6hdr *ip6;
		bool is_dsr = false;

		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		ret = nodeport_lb6(ctx, ip6, UNKNOWN_ID, &punt_to_stack, &ext_err, &is_dsr);
		if (IS_ERR(ret))
			goto drop_err;
	}

	return bpf_xdp_exit(ctx, ret);

drop_err:
	return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, METRIC_INGRESS);
}

static __always_inline int check_v6_lb(struct __ctx_buff *ctx)
{
	__s8 ext_err = 0;
	int ret;

	ret = tail_call_internal(ctx, CILIUM_CALL_IPV6_FROM_NETDEV, &ext_err);
	return send_drop_notify_error_ext(ctx, UNKNOWN_ID, ret, ext_err, METRIC_INGRESS);
}
#else
static __always_inline int check_v6_lb(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ipv6hdr *ipv6_hdr = data + sizeof(struct ethhdr);
	struct lpm_v6_key pfx __maybe_unused;

	if (ctx_no_room(ipv6_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR6_FILTER
	__bpf_memcpy_builtin(pfx.lpm.data, &ipv6_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 128;

#ifdef CIDR6_LPM_PREFILTER
	if (map_lookup_elem(&cilium_cidr_v6_dyn, &pfx))
		return CTX_ACT_DROP;
#endif /* CIDR6_LPM_PREFILTER */
	return map_lookup_elem(&cilium_cidr_v6_fix, &pfx) ?
		CTX_ACT_DROP : check_v6_lb(ctx);
#else
	return check_v6_lb(ctx);
#endif /* CIDR6_FILTER */
}
#else
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
	return check_v6_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV6 */

#ifndef xdp_early_hook
#define xdp_early_hook(ctx, proto) CTX_ACT_OK
#endif

static __always_inline int check_filters(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	ctx_store_meta(ctx, XFER_MARKER, 0);
	ctx_skip_nodeport_clear(ctx);

	ret = xdp_early_hook(ctx, proto);
	if (ret != CTX_ACT_OK)
		return ret;

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = check_v4(ctx);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = check_v6(ctx);
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}

	return bpf_xdp_exit(ctx, ret);
}

__section_entry
int cil_xdp_entry(struct __ctx_buff *ctx)
{
	return check_filters(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
