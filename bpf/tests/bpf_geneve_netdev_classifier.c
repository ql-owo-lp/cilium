// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* B2: the TRACE_TO_NETWORK notification of cil_to_netdev classifies a
 * packet as overlay traffic (CLS_FLAG_GENEVE, which Hubble reports as the
 * tunnel encapsulation and which selects trace_payload_len_overlay) by the
 * MARK_MAGIC_OVERLAY mark alone: ctx_classify() does not parse headers at
 * this observation point. Natively encapsulated Geneve packets arrive as
 * tail_geneve_encap4() emits them, carrying the mark that
 * handle_to_overlay() sets.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1
#define TUNNEL_MODE		1
#define ENCAP_IFINDEX		42
#define ENABLE_BPF_GENEVE	1

#define SRC_NODE_V4		v4_node_one
#define DST_NODE_V4		v4_node_two
#define SRC_POD_V4		v4_pod_one
#define DST_POD_V4		v4_pod_one_on_node_two
#define SRC_POD_SEC_IDENTITY	0x1234
#define GENEVE_SPORT		bpf_htons(50000)

/* Record the classifier flags of the TRACE_TO_NETWORK notification. */
static __u32 to_network_traces;
static __u8 to_network_flags;

#define TRACE_EXTENSION
#define trace_extension_hook(ctx, msg)				\
	do {							\
		if ((msg).subtype == TRACE_TO_NETWORK) {	\
			to_network_traces++;			\
			to_network_flags = (msg).flags;		\
		}						\
	} while (0)

#include "lib/bpf_host.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(bool, enable_trace_notify, true)

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

/* Encapsulate as tail_geneve_encap4() does (VNI = source identity, no
 * TLVs), mark the packet as handle_to_overlay() does if @overlay_mark and
 * send it to cil_to_netdev.
 */
static __always_inline int
send_geneve_packet(struct __ctx_buff *ctx, bool overlay_mark)
{
	int ret;

	to_network_traces = 0;
	to_network_flags = 0;

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
check_trace(const struct __ctx_buff *ctx, cls_flags_t expected_flags)
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
	assert(to_network_traces == 1);
	assert(to_network_flags == expected_flags);

	test_finish();
}

/* B2: the marked outer packet is traced as Geneve traffic. */
PKTGEN("tc", "geneve_trace_v4_overlay_mark_classified")
int geneve_trace_v4_overlay_mark_classified_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_trace_v4_overlay_mark_classified")
int geneve_trace_v4_overlay_mark_classified_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, true);
}

CHECK("tc", "geneve_trace_v4_overlay_mark_classified")
int geneve_trace_v4_overlay_mark_classified_check(const struct __ctx_buff *ctx)
{
	return check_trace(ctx, CLS_FLAG_GENEVE);
}

/* B2 contrast: the unmarked outer packet is traced as plain UDP. */
PKTGEN("tc", "geneve_trace_v4_no_mark_unclassified")
int geneve_trace_v4_no_mark_unclassified_pktgen(struct __ctx_buff *ctx)
{
	return build_inner_packet(ctx);
}

SETUP("tc", "geneve_trace_v4_no_mark_unclassified")
int geneve_trace_v4_no_mark_unclassified_setup(struct __ctx_buff *ctx)
{
	return send_geneve_packet(ctx, false);
}

CHECK("tc", "geneve_trace_v4_no_mark_unclassified")
int geneve_trace_v4_no_mark_unclassified_check(const struct __ctx_buff *ctx)
{
	return check_trace(ctx, CLS_FLAG_NONE);
}
