// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Unit tests for geneve_src_port() (lib/geneve.h) with a configured outer
 * UDP source port range.
 */

#include <bpf/ctx/skb.h>
#include "common.h"

#define ENABLE_BPF_GENEVE	1

#include "lib/common.h"
#include "lib/geneve.h"

ASSIGN_CONFIG(__u16, tunnel_src_port_low, 32768)
ASSIGN_CONFIG(__u16, tunnel_src_port_high, 61000)

/* L1-09: a configured range is mapped with the arithmetic of the kernel's
 * udp_flow_src_port(): hash ^= hash << 16;
 * port = (((u64)hash * (max - min)) >> 32) + min. The expected ports were
 * computed with that formula.
 */
CHECK("tc", "geneve_src_port_range")
int geneve_src_port_range_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("matches_udp_flow_src_port", {
		assert(geneve_src_port(0) == bpf_htons(32768));
		assert(geneve_src_port(1) == bpf_htons(32768));
		assert(geneve_src_port(0x12345678) == bpf_htons(40300));
		assert(geneve_src_port(0xffffffff) == bpf_htons(32768));
		assert(geneve_src_port(0x80000000) == bpf_htons(46884));
	});

	TEST("stays_within_low_high", {
		/* The port grows with the folded hash: folded hash 0 yields
		 * low and 0xffffffff (hash 0x0000ffff) high - 1, the range is
		 * [low, high) as in the kernel.
		 */
		assert(geneve_src_port(0x00000000) == bpf_htons(32768));
		assert(geneve_src_port(0x0000ffff) == bpf_htons(60999));
	});

	test_finish();
}
