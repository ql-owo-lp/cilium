// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include "common.h"
#include "pktgen.h"

/* XDP NodePort acceleration for a service whose selected backend sits behind
 * a tunnel endpoint with an IPv6 address.
 *
 * XDP cannot encapsulate towards an IPv6 tunnel endpoint: ctx_set_encap_info6()
 * in bpf/lib/overloadable_xdp.h is a stub. It used to return 0, which
 * tail_nodeport_nat_egress_ipv4/6() took for success: they went on with an
 * AF_INET FIB lookup over the unencapsulated packet (for IPv6 requests, over
 * bytes of the IPv6 header) and redirected it. The request must be dropped
 * with DROP_INVALID instead, before any FIB lookup and with nothing prepended
 * to the packet.
 *
 * Unlike xdp_encap_v6.c, which calls the stub directly, these tests run the
 * bpf_xdp.c pipeline: cil_xdp_entry -> tail_lb_ipv4/6 -> nodeport_lb4/6 ->
 * tail_nodeport_nat_egress_ipv4/6 -> nodeport_add_tunnel_encap().
 */

#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_NODEPORT			1
#define ENABLE_NODEPORT_ACCELERATION	1
#define TUNNEL_MODE			1
#define ENCAP_IFINDEX			42

#define CLIENT_MAC		mac_one
#define LB_MAC			mac_two
#define CLIENT_PORT		__bpf_htons(111)
#define FRONTEND_PORT		tcp_svc_one
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_ID		124
#define BACKEND_IDENTITY	112233
#define REVNAT_ID		1

#define CLIENT_IP		v4_ext_one
#define FRONTEND_IP		v4_svc_two
#define BACKEND_IP		v4_pod_two
#define ROUTER_IP		v4_pod_three

#define CLIENT_IP6		v6_ext_node_one
#define FRONTEND_IP6_ADDR	v6_svc_one_addr
#define BACKEND_IP6_ADDR	v6_pod_two_addr
#define ROUTER_IP6_ADDR		v6_pod_three_addr

/* IPv6 address of the node that hosts the backends. */
#define TUNNEL_EP_ADDR		v6_node_two_addr

#define FIB_IFINDEX		24

#define PKT_LEN4	(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))
#define PKT_LEN6	(sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
			 sizeof(struct tcphdr) + sizeof(default_data))

static __u32 fib_lookups;

#define fib_lookup mock_fib_lookup

/* Routes everything, so that a request that wrongly gets to the FIB redirect
 * is redirected, and the test fails on the verdict as well as on the count.
 */
long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	fib_lookups++;

	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ifindex = FIB_IFINDEX;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_xdp.h"

#include "lib/ipcache.h"
#include "lib/lb.h"
#include "lib/metrics.h"

ASSIGN_CONFIG(__u8, tunnel_protocol, TUNNEL_PROTOCOL_GENEVE)
ASSIGN_CONFIG(__u16, tunnel_port, 6081)
ASSIGN_CONFIG(union v4addr, router_ipv4, { .be32 = ROUTER_IP })
ASSIGN_CONFIG(union v6addr, router_ipv6, { .addr = ROUTER_IP6_ADDR })

/* Set port ranges to have deterministic source port selection */
#include "nodeport_defaults.h"

/* B10/PR-1: IPv4 service, remote IPv4 backend behind an IPv6 tunnel endpoint
 * (tail_nodeport_nat_egress_ipv4).
 */
PKTGEN(PROG_TYPE, "xdp_nodeport_lb4_tunnel_ep_v6_drop")
int nodeport_lb4_tunnel_ep_v6_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC, (__u8 *)LB_MAC,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "xdp_nodeport_lb4_tunnel_ep_v6_drop")
int nodeport_lb4_tunnel_ep_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr tunnel_ep = { .addr = TUNNEL_EP_ADDR };

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, REVNAT_ID);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, BACKEND_ID,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, 0);
	ipcache_v4_add_entry_ipv6_underlay(BACKEND_IP, 0, BACKEND_IDENTITY,
					   &tunnel_ep, 0);

	metrics_del_entry(-DROP_INVALID, METRIC_EGRESS);
	fib_lookups = 0;

	return xdp_receive_packet(ctx);
}

CHECK(PROG_TYPE, "xdp_nodeport_lb4_tunnel_ep_v6_drop")
int nodeport_lb4_tunnel_ep_v6_check(const struct __ctx_buff *ctx)
{
	struct metrics_key key = {
		.reason = -DROP_INVALID,
		.dir = METRIC_EGRESS,
	};
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Dropped with the reason returned by ctx_set_encap_info6(), not
	 * routed and XDP_TX'ed / XDP_REDIRECTed.
	 */
	assert(*status_code == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(fib_lookups == 0);

	l2 = data + sizeof(__u32);
	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	/* DNATed to the backend and SNATed to the router IP, which only the
	 * tunnel branch of the NAT egress tail does: the encap dropped it.
	 */
	assert(l3->daddr == BACKEND_IP);
	assert(l3->saddr == ROUTER_IP);

	/* Nothing was prepended. */
	assert(l2->h_proto == bpf_htons(ETH_P_IP));
	assert((void *)l2 + PKT_LEN4 == data_end);

	test_finish();
}

/* B10/PR-1: IPv6 service, remote IPv6 backend behind an IPv6 tunnel endpoint
 * (tail_nodeport_nat_egress_ipv6, which used to "goto fib_ipv4").
 */
PKTGEN(PROG_TYPE, "xdp_nodeport_lb6_tunnel_ep_v6_drop")
int nodeport_lb6_tunnel_ep_v6_pktgen(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = { .addr = FRONTEND_IP6_ADDR };
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC, (__u8 *)LB_MAC,
					  (__u8 *)CLIENT_IP6, frontend_ip.addr,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP(PROG_TYPE, "xdp_nodeport_lb6_tunnel_ep_v6_drop")
int nodeport_lb6_tunnel_ep_v6_setup(struct __ctx_buff *ctx)
{
	union v6addr frontend_ip = { .addr = FRONTEND_IP6_ADDR };
	union v6addr backend_ip = { .addr = BACKEND_IP6_ADDR };
	union v6addr tunnel_ep = { .addr = TUNNEL_EP_ADDR };

	lb_v6_add_service(&frontend_ip, FRONTEND_PORT, IPPROTO_TCP, 1, REVNAT_ID);
	lb_v6_add_backend(&frontend_ip, FRONTEND_PORT, 1, BACKEND_ID,
			  &backend_ip, BACKEND_PORT, IPPROTO_TCP, 0);
	ipcache_v6_add_entry_ipv6_underlay(&backend_ip, 0, BACKEND_IDENTITY,
					   &tunnel_ep, 0);

	metrics_del_entry(-DROP_INVALID, METRIC_EGRESS);
	fib_lookups = 0;

	return xdp_receive_packet(ctx);
}

CHECK(PROG_TYPE, "xdp_nodeport_lb6_tunnel_ep_v6_drop")
int nodeport_lb6_tunnel_ep_v6_check(const struct __ctx_buff *ctx)
{
	union v6addr backend_ip = { .addr = BACKEND_IP6_ADDR };
	union v6addr router_ip = { .addr = ROUTER_IP6_ADDR };
	struct metrics_key key = {
		.reason = -DROP_INVALID,
		.dir = METRIC_EGRESS,
	};
	void *data, *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct ipv6hdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;

	/* Dropped with the reason returned by ctx_set_encap_info6(), not
	 * routed and XDP_TX'ed / XDP_REDIRECTed.
	 */
	assert(*status_code == CTX_ACT_DROP);
	assert_metrics_count(key, 1);
	assert(fib_lookups == 0);

	l2 = data + sizeof(__u32);
	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	/* DNATed to the backend and SNATed to the router IP, which only the
	 * tunnel branch of the NAT egress tail does: the encap dropped it.
	 */
	assert(!memcmp(&l3->daddr, &backend_ip, sizeof(backend_ip)));
	assert(!memcmp(&l3->saddr, &router_ip, sizeof(router_ip)));

	/* Nothing was prepended. */
	assert(l2->h_proto == bpf_htons(ETH_P_IPV6));
	assert((void *)l2 + PKT_LEN6 == data_end);

	test_finish();
}
