// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Unit tests for geneve_src_port() (lib/geneve.h) with a source port range
 * whose low end is not below its high end.
 *
 * low = 50000 > high = 40000: with low == high the general formula would
 * yield low as well, so only low > high shows that the branch for low >=
 * high is taken; without it, high - low would wrap around.
 */

#include <bpf/ctx/skb.h>
#include "common.h"

#define ENABLE_BPF_GENEVE	1

#include "lib/common.h"
#include "lib/geneve.h"

ASSIGN_CONFIG(__u16, tunnel_src_port_low, 50000)
ASSIGN_CONFIG(__u16, tunnel_src_port_high, 40000)

/* L1-09: low >= high (other than 0/0) yields low as the only port, a
 * documented deviation: the kernel would fall back to ip_local_port_range,
 * which BPF cannot read.
 */
CHECK("tc", "geneve_src_port_single")
int geneve_src_port_single_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("always_low", {
		assert(geneve_src_port(0) == bpf_htons(50000));
		assert(geneve_src_port(1) == bpf_htons(50000));
		assert(geneve_src_port(0x12345678) == bpf_htons(50000));
		assert(geneve_src_port(0xffffffff) == bpf_htons(50000));
		assert(geneve_src_port(0x0000ffff) == bpf_htons(50000));
		assert(geneve_src_port(0x80000000) == bpf_htons(50000));
	});

	test_finish();
}
