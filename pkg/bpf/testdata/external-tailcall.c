#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

#include <bpf/tailcall.h>
#include <lib/tailcall.h>

// A program array shared with other objects. Nothing in this object tail calls
// into it; it is only populated here and called from elsewhere.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int ());
} shared_calls __section_maps_btf;

// Equivalent of __declare_tail_in(shared_calls, index).
#define __declare_shared_tail(index) \
	__section(PROG_TYPE "/tail") \
	__attribute__((btf_decl_tag("tail:shared_calls/" __stringify(index))))

#define TAIL_A 0
#define TAIL_B 1
#define TAIL_C 2

#define SHARED_A 0

// Only reachable through shared_calls, i.e. from another object.
__declare_shared_tail(SHARED_A)
static int shared_a(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_B);
        return 0;
}

// Only reachable from shared_a.
__declare_tail(TAIL_B)
static int b(void *ctx) {
        return 0;
}

// Only reachable from the entrypoint.
__declare_tail(TAIL_A)
static int a(void *ctx) {
        return 0;
}

// Not reachable from anything.
__declare_tail(TAIL_C)
static int c(void *ctx) {
        return 0;
}

__section_entry
static int cil_entry(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_A);
        return 0;
}
