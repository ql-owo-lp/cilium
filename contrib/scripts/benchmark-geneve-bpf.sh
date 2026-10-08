#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# Benchmark of Cilium's Geneve tunnel datapaths on any Kubernetes cluster
# (multi-node clusters on GCE/AWS/Azure VMs, GKE, EKS, AKS, kubeadm, or a local
# Kind cluster).
#
# Modes, selected with MODES (comma-separated, default "kernel,eth,ip"):
#   kernel  kernel Geneve device (cilium_geneve, collect_md): enable-bpf-geneve=false
#   eth     native BPF Geneve with inner Ethernet: enable-bpf-geneve=true,
#           geneve-inner-protocol=eth
#   ip      native BPF Geneve with inner IP: enable-bpf-geneve=true,
#           geneve-inner-protocol=ip. Before the first iteration, Cilium is
#           switched to ip once; the mode is skipped, and the reason reported,
#           if the agents reject it.
#
# Every iteration runs each mode once. The mode order is rotated by one
# position per iteration, so that drift over time is spread across modes.
# Mode switches are performed by patching enable-bpf-geneve and
# geneve-inner-protocol in the cilium-config ConfigMap and restarting the
# cilium DaemonSet (using the same Cilium image across all modes).
# After a mode switch the benchmark pods are recreated and their default route
# MTU is checked: underlay MTU - 50 for kernel and eth, - 36 for ip (IPv4
# underlay). Each mode is then checked for MTU parity with the kernel device:
# with both pods' route MTUs temporarily raised to the underlay MTU, a ping of
# underlay MTU - 32 bytes with DF set must get through in every mode, and one
# of underlay MTU - 36 bytes must be fragmented on the sending node
# (IpFragCreates) in kernel and eth mode, but not in ip mode.
#
# Workloads per mode and iteration (16 runs; same-node client pod and server
# pod on SERVER_NODE, cross-node client pod on CLIENT_NODE, NodePort via
# NODEPORT_NODE):
#    1    TCP (same node, no tunnel), 4 streams
#    2-4  TCP (cross-node), 1, 4 and 8 streams
#    5    TCP, bidirectional, 4 streams
#    6    TCP, 128-byte writes with TCP_NODELAY, 4 streams
#    7    TCP via the ClusterIP service, 4 streams
#    8    TCP via the NodePort of another node (NODEPORT_NODE), 4 streams
#    9    TCP at a fixed 4 x 2.5 Gbit/s
#   10    UDP, 64-byte datagrams at a fixed 4 x 6.4 Mbit/s
#   11-14 UDP, 64, 512, 1380 and 4000-byte datagrams, unlimited rate, 4 streams
#   15-16 ICMP echo with 56 and 1400-byte (or underlay MTU - 100) payload,
#         500 requests 2 ms apart
# Throughput is measured at the receiver. CPU usage is reported as iperf3
# process CPU (client and server processes, getrusage) and as node-wide
# softirq time from /proc/stat across the benchmarked client and server nodes
# (deduplicated when nodes share a single host kernel, as in Kind).
#
# Side effects: patches enable-bpf-geneve and geneve-inner-protocol in the
# cilium-config ConfigMap and restarts the cilium DaemonSet for every mode
# switch, restoring the original values at the end; recreates the pods
# iperf3-server, iperf3-client-local, and iperf3-client-cp and applies the
# service iperf3-svc in the default namespace. Host sysctls and host iptables
# are not changed. When run against a local Kind cluster with kind-fast volume
# mounts (/cilium-binaries), builds daemon/cilium-agent and copies it and the
# agent BPF sources into the nodes before running; on managed or image-based
# clusters, runs directly against the deployed Cilium image.
#
# Usage:
#   # Run against the current kubectl context (any managed cluster or Kind):
#   contrib/scripts/benchmark-geneve-bpf.sh
#
#   # Run against a specific kubeconfig or context with all 3 modes:
#   KUBECONFIG=/path/to/kubeconfig MODES=kernel,eth,ip contrib/scripts/benchmark-geneve-bpf.sh
#
# Environment variables (optional):
#   KUBE_CONTEXT=<context>                   kubectl context (defaults to current context
#                                            if a Cilium cluster is reachable, else
#                                            kind-${CLUSTER_NAME})
#   CLUSTER_NAME=geneve-perf                 Kind cluster name (when using Kind)
#   CLIENT_NODE=<node>                       Node for the cross-node client pod
#                                            (auto-discovered if unset)
#   SERVER_NODE=<node>                       Node for the server and same-node client pods
#                                            (auto-discovered if unset)
#   NODEPORT_NODE=<node>                     Node whose InternalIP:NodePort is tested
#                                            (auto-discovered if unset)
#   MODES=kernel,eth                         Modes to compare (kernel, eth, ip)
#   ITERATIONS=5                             Iterations, each runs every mode once
#   IPERF_DURATION=5                         Seconds per iperf3 run
#   BENCH_IMAGE=nicolaka/netshoot:latest     Image with iperf3, ping, ip, and iptables
#                                            for the benchmark pods
#   OUTPUT_FILE=/tmp/geneve_benchmark_results.md   Markdown report

set -euo pipefail
# Also stop on errors in command substitutions, e.g. in out="$(func)".
shopt -s inherit_errexit

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
MODES="${MODES:-kernel,eth,ip}"
ITERATIONS="${ITERATIONS:-5}"
IPERF_DURATION="${IPERF_DURATION:-5}"
BENCH_IMAGE="${BENCH_IMAGE:-docker.io/nicolaka/netshoot:latest}"
OUTPUT_FILE="${OUTPUT_FILE:-/tmp/geneve_benchmark_results.md}"

CP_NODE="${CLIENT_NODE:-${CP_NODE:-}}"
WORKER_NODE="${SERVER_NODE:-${WORKER_NODE:-}}"
WORKER2_NODE="${NODEPORT_NODE:-${WORKER2_NODE:-}}"
CLIENT_POD="iperf3-client-cp"
LOCAL_CLIENT_POD="iperf3-client-local"
SERVER_POD="iperf3-server"
SERVICE_NAME="iperf3-svc"
NODEPORT_PORT="31201"
# RFC 2544 benchmark address used inside CLIENT_POD's private network namespace
# to DNAT to WORKER2_IP:NODEPORT_PORT after connect(), so Cilium's cgroup
# socket-LB (cil_sock4_connect) on CLIENT_NODE does not intercept the socket
# and packets traverse WORKER2_NODE's packet-level NodePort datapath.
NODEPORT_DUMMY_IP="198.18.0.1"
NODE_CONFIG_H="/var/run/cilium/state/globals/node_config.h"
# Host paths of the kind-fast volumes (contrib/testing/kind-fast.yaml).
NODE_AGENT_BIN="/cilium-binaries/cilium-agent"
NODE_BPF_DIR="/cilium-binaries/var/lib/cilium/bpf"
# Stands for a key missing from cilium-config.
ABSENT="<absent>"
# Digest of the paths and contents of all BPF source files below the current
# directory (excluding include/bpf/features*.h, which cilium-agent overwrites
# at startup, and non-runtime files), computed the same way on the host and in
# the agent pods.
MANIFEST_CMD='find . -type f ! -path "./include/bpf/features*.h" ! -path "./.gitignore" ! -path "./Makefile*" ! -path "./tests/*" ! -path "./complexity-tests/*" ! -path "./custom/*" ! -name "*.o" ! -name "*.tmp" -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | cut -d" " -f1'

# Run-time state.
WORK_DIR=""
USE_KIND=0
SHARED_KERNEL=1
RUN_MODES=()
CILIUM_PODS=()
STAT_NODES=()
CUR_ITER=0
CURRENT_MODE=""
PODS_MODE=""
MODE_REJECTED=""
CONFIG_TOUCHED=0
RESTORED=0
ORIG_ENABLE_BPF_GENEVE=""
ORIG_INNER_PROTO=""
START_DATE=""
START_LOAD=""
UNDERLAY_DEV=""
UNDERLAY_MTU=""
ICMP_BIG_PAYLOAD=1400
SERVER_IP=""
SVC_IP=""
WORKER2_IP=""
GIT_COMMIT=""
GIT_DIRTY=""
AGENT_SHA=""
BPF_SHA=""
BPF_FILES=""

# Parses iperf3 and ping output and computes softirq deltas. Prints KEY=VALUE
# tokens (values with 4 decimals, "nan" when undefined).
PY_HELPER="$(
	cat <<'PY'
import json
import math
import os
import re
import sys
import time


def fmt(value):
    return "nan" if value is None or math.isnan(value) else f"{value:.4f}"


def div(num, den):
    return num / den if den else math.nan


def emit(prefix, pairs):
    print(" ".join(f"{prefix}_{key}={fmt(val)}" for key, val in pairs))


def host_counters(files):
    # Sum softirq ticks (/proc/stat col 8) and NET_RX softirqs across the
    # sampled nodes (1 node when sharing a kernel on Kind, 2 nodes when
    # client and server run on separate VMs/hosts).
    softirq_ticks = 0
    net_rx = 0
    for path in files:
        with open(path, encoding="utf-8") as f:
            parts = f.read().split()
            if len(parts) >= 2:
                softirq_ticks += int(parts[0])
                net_rx += int(parts[1])
    return f"{time.monotonic_ns()},{softirq_ticks},{net_rx}"


def window(start, end):
    # Softirq time of all sampled CPUs between two snapshots, in % of one CPU,
    # and the number of NET_RX softirqs in between.
    t0, sirq0, rx0 = (int(x) for x in start.split(","))
    t1, sirq1, rx1 = (int(x) for x in end.split(","))
    seconds = (t1 - t0) / 1e9
    sirq_pct = div((sirq1 - sirq0) / os.sysconf("SC_CLK_TCK"), seconds) * 100
    return sirq_pct, rx1 - rx0


def ping_counts(text):
    # iputils: "5 packets transmitted, 5 received", busybox: "... 5 packets received"
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def iperf(kind, prefix, args):
    eff = "--eff" in args
    snaps = [a for a in args if a != "--eff"]
    report = json.load(sys.stdin)
    if "error" in report:
        sys.exit(f"iperf3 error: {report['error']}")
    end = report["end"]
    pairs = []
    if kind == "udp":
        rcv = end["sum_received"]
        rx_pkts = rcv["packets"] - rcv["lost_packets"]
        rx_kpps = div(rx_pkts, rcv["seconds"]) / 1000
        pairs += [("RX_KPPS", rx_kpps), ("RX_GBPS", rcv["bits_per_second"] / 1e9),
                  ("LOSS_PCT", rcv["lost_percent"])]
    else:
        bps = end["sum_received"]["bits_per_second"]
        if kind == "bidir":
            bps += end["sum_received_bidir_reverse"]["bits_per_second"]
        gbps = bps / 1e9
        pairs.append(("GBPS", gbps))
    if snaps:
        cpu = (end["cpu_utilization_percent"]["host_total"] +
               end["cpu_utilization_percent"]["remote_total"])
        sirq, net_rx = window(*snaps)
        pairs += [("PROC_CPU_PCT", cpu), ("SIRQ_PCT", sirq)]
        if eff and kind == "tcp":
            pairs += [("GBPS_PER_PROC_CPU", div(gbps, cpu / 100)),
                      ("GBPS_PER_SIRQ", div(gbps, sirq / 100))]
        if eff and kind == "udp":
            pairs += [("RX_KPPS_PER_PROC_CPU", div(rx_kpps, cpu / 100)),
                      ("PROC_CPU_US_PER_PKT", div(cpu / 100 * 1e6, rx_kpps * 1000)),
                      ("NETRX_PER_KPKT", div(net_rx, rx_pkts / 1000))]
    emit(prefix, pairs)


def rtt(prefix):
    text = sys.stdin.read()
    times = sorted(float(x) for x in re.findall(r"time=([0-9.]+) ms", text))
    if not times:
        sys.exit(f"no ICMP echo replies: {text.strip()[-300:]}")
    tx, rx = ping_counts(text)
    p99 = times[math.ceil(0.99 * len(times)) - 1]  # nearest rank
    emit(prefix, [("MS", sum(times) / len(times)), ("P99_MS", p99),
                  ("LOSS_PCT", div(tx - rx, tx) * 100)])


cmd, args = sys.argv[1], sys.argv[2:]
try:
    if cmd == "hoststat":
        print(host_counters(args))
    elif cmd == "pingcount":
        print(*ping_counts(sys.stdin.read()))
    elif cmd in ("tcp", "bidir", "udp"):
        iperf(cmd, args[0], args[1:])
    elif cmd == "rtt":
        rtt(args[0])
    else:
        sys.exit(f"unknown command {cmd}")
except (KeyError, ValueError) as e:
    sys.exit(f"cannot parse the {cmd} output: {e!r}")
PY
)"

# Builds the Markdown report from the files in the work directory.
PY_REPORT="$(
	cat <<'PY'
import math
import os
import statistics
import sys

work_dir, out_path, iterations, duration, big_payload, shared_kernel, client_node, server_node, nodeport_node = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]),
    int(sys.argv[6]), sys.argv[7], sys.argv[8], sys.argv[9]
)
big_l3 = big_payload + 28

MODES = ["kernel", "eth", "ip"]
NAMES = {
    "kernel": "Kernel Geneve",
    "eth": "BPF Geneve (eth)",
    "ip": "BPF Geneve (ip)",
}
LABELS = {
    "kernel": "Kernel Geneve (baseline, `cilium_geneve` device, `collect_md`)",
    "eth": "BPF Geneve (`eth` mode, inner Ethernet packet)",
    "ip": "BPF Geneve (`ip` mode, inner IP packet)",
}
ALL_PAIRS = [
    ("eth", "kernel", "BPF Geneve (eth) vs Kernel"),
    ("ip", "kernel", "BPF Geneve (ip) vs Kernel"),
    ("ip", "eth", "BPF Geneve (ip) vs BPF Geneve (eth)"),
]
PROC = "iperf3 process CPU (client+server, getrusage)"
SIRQ = (
    "host-wide softirq ticks from /proc/stat (all host CPUs, includes unrelated host activity)"
    if shared_kernel else
    "combined node softirq ticks from /proc/stat (client+server nodes)"
)
CPU = "% of one CPU"

# (label, key, unit, better, decimals)
ROWS = [
    ("TCP (same node, no tunnel), 4 streams", "TCP_SAME_NODE_P4_GBPS", "Gbit/s", "higher", 2),
    ("TCP, 1 stream", "TCP_P1_GBPS", "Gbit/s", "higher", 2),
    ("TCP, 4 streams", "TCP_P4_GBPS", "Gbit/s", "higher", 2),
    ("TCP, 8 streams", "TCP_P8_GBPS", "Gbit/s", "higher", 2),
    (f"TCP, 8 streams: {PROC}", "TCP_P8_PROC_CPU_PCT", CPU, "lower", 1),
    (f"TCP, 8 streams: {SIRQ}", "TCP_P8_SIRQ_PCT", CPU, "lower", 1),
    ("TCP, 8 streams: throughput per iperf3 process CPU", "TCP_P8_GBPS_PER_PROC_CPU",
     "Gbit/s per CPU", "higher", 2),
    ("TCP, 8 streams: throughput per host-wide softirq CPU", "TCP_P8_GBPS_PER_SIRQ",
     "Gbit/s per CPU", "higher", 2),
    ("TCP, bidirectional, 4 streams (sum of both directions)", "TCP_BIDIR_P4_GBPS", "Gbit/s",
     "higher", 2),
    ("TCP, 128-byte writes, TCP_NODELAY, 4 streams", "TCP_128B_P4_GBPS", "Gbit/s", "higher", 3),
    ("TCP via ClusterIP service, 4 streams", "SVC_CLUSTERIP_P4_GBPS", "Gbit/s", "higher", 2),
    ("TCP via NodePort of another node, 4 streams", "SVC_NODEPORT_P4_GBPS", "Gbit/s", "higher", 2),
    ("TCP at fixed 4 x 2.5 Gbit/s: achieved", "ISO_TCP_10G_GBPS", "Gbit/s", "higher", 2),
    (f"TCP at fixed 4 x 2.5 Gbit/s: {PROC}", "ISO_TCP_10G_PROC_CPU_PCT", CPU, "lower", 1),
    (f"TCP at fixed 4 x 2.5 Gbit/s: {SIRQ}", "ISO_TCP_10G_SIRQ_PCT", CPU, "lower", 1),
    ("UDP 64 B at fixed 4 x 6.4 Mbit/s: received", "ISO_UDP_50KPPS_RX_KPPS", "kpps", "higher", 1),
    ("UDP 64 B at fixed 4 x 6.4 Mbit/s: loss", "ISO_UDP_50KPPS_LOSS_PCT", "%", "lower", 2),
    (f"UDP 64 B at fixed 4 x 6.4 Mbit/s: {PROC}", "ISO_UDP_50KPPS_PROC_CPU_PCT", CPU, "lower", 1),
    (f"UDP 64 B at fixed 4 x 6.4 Mbit/s: {SIRQ}", "ISO_UDP_50KPPS_SIRQ_PCT", CPU, "lower", 1),
    ("UDP 64 B, unlimited, 4 streams: received", "UDP_64B_RX_KPPS", "kpps", "higher", 1),
    ("UDP 64 B, unlimited, 4 streams: loss", "UDP_64B_LOSS_PCT", "%", "lower", 1),
    (f"UDP 64 B, unlimited, 4 streams: {PROC}", "UDP_64B_PROC_CPU_PCT", CPU, "lower", 1),
    (f"UDP 64 B, unlimited, 4 streams: {SIRQ}", "UDP_64B_SIRQ_PCT", CPU, "lower", 1),
    ("UDP 64 B, unlimited, 4 streams: received per iperf3 process CPU",
     "UDP_64B_RX_KPPS_PER_PROC_CPU", "kpps per CPU", "higher", 1),
    ("UDP 64 B, unlimited, 4 streams: iperf3 process CPU per received datagram",
     "UDP_64B_PROC_CPU_US_PER_PKT", "µs", "lower", 3),
    ("UDP 64 B, unlimited, 4 streams: host-wide NET_RX softirqs per 1000 received datagrams",
     "UDP_64B_NETRX_PER_KPKT", "count", "lower", 1),
]
for size in (512, 1380, 4000):
    name = f"UDP {size} B, unlimited, 4 streams"
    if size == 4000:
        name += " (IP-fragmented in the pod)"
    ROWS += [
        (f"{name}: received", f"UDP_{size}B_RX_GBPS", "Gbit/s", "higher", 2),
        (f"{name}: received", f"UDP_{size}B_RX_KPPS", "kpps", "higher", 1),
        (f"{name}: loss", f"UDP_{size}B_LOSS_PCT", "%", "lower", 1),
    ]
for key, payload, size in (("RTT_64B", 56, 84), ("RTT_1428B", big_payload, big_l3)):
    name = f"ICMP echo, {payload}-byte payload ({size}-byte IPv4 packet)"
    ROWS += [
        (f"{name}: mean RTT", f"{key}_MS", "ms", "lower", 3),
        (f"{name}: p99 RTT", f"{key}_P99_MS", "ms", "lower", 3),
        (f"{name}: loss", f"{key}_LOSS_PCT", "%", "lower", 1),
    ]

DEFINITIONS = [
    "Throughput in Gbit/s is measured at the receiver: iperf3 `end.sum_received.bits_per_second`, "
    "for the bidirectional run summed over both directions.",
    "UDP `received` in kpps is `(sum_received.packets - sum_received.lost_packets) / "
    "sum_received.seconds` and `loss` is `sum_received.lost_percent`, both reported by the "
    "receiving iperf3.",
    f"{PROC}: `cpu_utilization_percent.host_total + remote_total` as reported by iperf3, i.e. the "
    "CPU time of the client and the server process in % of one CPU. Kernel work done for them in "
    "softirq context is only partly included.",
    f"{SIRQ}: increase of the softirq time summed over the sampled node CPUs from just before to "
    "just after the `kubectl exec` that runs iperf3, divided by that interval, in % of one CPU.",
    "Throughput per CPU: Gbit/s (or received kpps) divided by the matching CPU figure / 100, "
    "i.e. per CPU of iperf3 process time or per CPU of softirq time.",
    "iperf3 process CPU per received datagram: iperf3 process CPU / 100 divided by the received "
    "datagrams per second, in µs; it includes the sender's CPU time for datagrams that were lost.",
    "Host-wide NET_RX softirqs: increase of the NET_RX row of /proc/softirqs over the "
    "same interval, per 1000 received datagrams.",
    "RTT: mean and nearest-rank p99 of the `time=` values of 500 ICMP echo requests sent 2 ms "
    "apart (`ping -i 0.002 -c 500`); loss is the share of requests without reply.",
    "Fixed-rate runs use `iperf3 -b` per stream: 4 x 2.5 Gbit/s for TCP, 4 x 6.4 Mbit/s of 64-byte "
    "datagrams (about 50,000 datagrams/s in total) for UDP.",
]

if shared_kernel:
    CAVEATS = [
        "Single host: all Kind nodes are containers sharing one kernel and one set of CPUs, and the "
        "underlay is a veth/Linux bridge network with no physical NIC, hence no hardware offloads. "
        "Absolute numbers do not carry over to real networks; differences between modes are "
        "indicative only.",
        "The pods, the Cilium agents and unrelated host processes compete for the same CPUs; the "
        "host-wide softirq figures include all of them.",
    ]
else:
    CAVEATS = [
        f"Multi-node cluster: cross-node client pod on `{client_node}`, server and same-node "
        f"client pods on `{server_node}`, and NodePort forwarder on `{nodeport_node}`.",
        "Softirq CPU % and NET_RX softirq counts are summed across both the client node and the "
        "server node from `/proc/stat` and `/proc/softirqs` snapshots taken before and after each "
        "workload.",
        "On cloud VMs with a per-VM hypervisor egress cap (e.g. 10 Gbit/s on 4-vCPU GCE VMs, "
        "~8.8–8.9 Gbit/s inner TCP goodput ceiling), multi-stream bulk TCP saturates the NIC "
        "cap in all modes so datapath savings appear in lower softirq CPU % and higher Gbit/s "
        "per softirq CPU, while a single hypervisor token-bucket tail drop during slow-start "
        "can lower a short 5 s iperf3 run.",
    ]
CAVEATS += [
    "On kernels without `BPF_F_ADJ_ROOM_DECAP_L4_UDP`, `BPF Geneve (eth)` leaves GRO-merged "
    "incoming TCP segments to `cilium_geneve` on ingress, whereas non-GRO workloads (128-byte "
    "`TCP_NODELAY`, UDP, ICMP) and `BPF Geneve (ip)` run natively on both egress and ingress. "
    "On natively decapsulated TCP segments with a zero outer UDP checksum, `geneve_strip()` "
    "decrements `csum_level` (`BPF_CSUM_LEVEL_DEC`), shifting inner TCP checksum verification "
    "from softirq context into the receiving `iperf3` process's `read()` syscall (`getrusage`).",
    "Each iteration runs every mode once, in an order rotated per iteration. Mode switches "
    "only patch `enable-bpf-geneve` and `geneve-inner-protocol` in the `cilium-config` ConfigMap "
    "against the same Cilium image. The pods are recreated after every mode switch: they stay on "
    "the same nodes, but their IPs change.",
    "Values are means over few iterations without significance testing; differences within the "
    "standard deviations are not meaningful.",
]

WORKLOADS = [
    f"TCP (same node on `{server_node}`, no tunnel), 4 streams",
    f"TCP (cross-node `{client_node}` -> `{server_node}`), 1, 4 and 8 streams",
    "TCP, bidirectional, 4 streams",
    "TCP, 128-byte writes with TCP_NODELAY, 4 streams",
    "TCP via the ClusterIP service, 4 streams",
    f"TCP via the NodePort of `{nodeport_node}`, 4 streams",
    "TCP at a fixed 4 x 2.5 Gbit/s",
    "UDP, 64-byte datagrams at a fixed 4 x 6.4 Mbit/s",
    "UDP, 64, 512, 1380 and 4000-byte datagrams, unlimited rate, 4 streams",
    f"ICMP echo with 56 and {big_payload}-byte payload, 500 requests 2 ms apart",
]


def read_lines(name):
    path = os.path.join(work_dir, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def tokens(line):
    return dict(tok.split("=", 1) for tok in line.split() if "=" in tok)


def md(text):
    return text.replace("|", "\\|")


raw = {m: read_lines(f"bench_{m}.txt") for m in MODES}
ran = [m for m in MODES if raw[m]]
values = {m: {} for m in ran}
for m in ran:
    for line in raw[m]:
        for key, val in tokens(line).items():
            if key in ("ITER", "POS", "MODE"):
                continue
            try:
                x = float(val)
            except ValueError:
                continue
            if not math.isnan(x):
                values[m].setdefault(key, []).append(x)

pairs = [(m, b, title) for m, b, title in ALL_PAIRS if m in ran and b in ran]
env = [line.split("\t", 1) for line in read_lines("env.tsv")]
orders = [tokens(line) for line in read_lines("order.txt")]
skipped = [line.split("\t", 1) for line in read_lines("skipped.tsv")]

title_suffix = "Kind" if shared_kernel else "Kubernetes cluster"
out = [f"# Geneve tunnel datapath benchmark ({title_suffix})", ""]
summary = f"Modes measured: {', '.join(NAMES[m] for m in ran) if ran else 'none'}"
if skipped:
    summary += f"; skipped: {', '.join(NAMES.get(s[0], s[0]) for s in skipped)}"
out += [summary + f". {iterations} iterations, {duration} s per iperf3 run. Generated by "
        "`contrib/scripts/benchmark-geneve-bpf.sh`.", ""]
for m in ran:
    out.append(f"- **{NAMES[m]}** (`{m}`): {LABELS[m]}")
out.append("")

out += ["## Workloads", "",
        f"Cross-node client pod on `{client_node}`, server pod and same-node client pod on "
        f"`{server_node}`, NodePort via `{nodeport_node}`; run in this order for every mode and "
        "iteration:", ""]
out += [f"{i}. {w}" for i, w in enumerate(WORKLOADS, 1)] + [""]

out += ["## Environment", "", "| Item | Value |", "| --- | --- |"]
for item in env:
    out.append(f"| {md(item[0])} | {md(item[1] if len(item) > 1 else '')} |")
order_text = "; ".join(f"{o.get('ITER', '?')}: {o.get('ORDER', '').replace(',', ', ')}"
                       for o in orders)
out.append(f"| Mode order per iteration | {order_text} |")
for mode, reason in (s if len(s) == 2 else (s[0], "") for s in skipped):
    out.append(f"| Skipped mode {NAMES.get(mode, mode)} | {md(reason)} |")
out.append("")

out += ["## Caveats", ""] + [f"- {c}" for c in CAVEATS]
for item in env:
    if item[0].startswith("Host kernel.bpf_stats_enabled") and item[1:] and item[1].startswith("1"):
        out.append("- kernel.bpf_stats_enabled was 1 on the host: every BPF program ran with "
                   "run-time statistics enabled, which adds overhead to all modes.")
out.append("")

mtu_rows = [tokens(line) for line in read_lines("mtu.txt")]
overhead = {r["MODE"]: r["OVERHEAD"] for r in mtu_rows}
out += ["## Pod route MTU", "",
        "Default route MTU of the client and server pods, checked before every measurement; the "
        "run stops on a mismatch.", "",
        "| Mode | Expected (underlay MTU - overhead) | Observed | Route checks |",
        "| --- | --- | --- | --- |"]
for m in ran:
    rows = [r for r in mtu_rows if r.get("MODE") == m]
    if not rows:
        continue
    expected = sorted({f"{r['EXPECTED']} ({r['UNDERLAY']} - {r['OVERHEAD']})" for r in rows})
    observed = {}
    for r in rows:
        observed.setdefault(f"{r['POD']} IPv{r['FAMILY']}", set()).add(r["MTU"])
    observed_text = ", ".join(f"{k}: {'/'.join(sorted(v))}" for k, v in sorted(observed.items()))
    out.append(f"| {NAMES[m]} | {', '.join(expected)} | {observed_text} | {len(rows)} |")
out.append("")

parity = [tokens(line) for line in read_lines("parity.txt")]
if parity:
    big, exact = parity[0]["BIG_L3"], parity[0]["EXACT_L3"]

    def modes_expecting(expect):
        ms = [m for m in ran if any(r.get("MODE") == m and r["EXPECTED_DELTA"] == expect
                                    for r in parity)]
        return " and ".join(f"{NAMES[m]} ({overhead.get(m, '?')} bytes of overhead)" for m in ms)

    text = ("Both pods' IPv4 default route MTUs are raised to the underlay MTU for this check and "
            f"restored afterwards. A {big}-byte IPv4 packet with DF set must reach the server in "
            "every mode: where the encapsulated packet exceeds the underlay MTU, the outer packet "
            "is fragmented, as with the kernel Geneve device.")
    frag, no_frag = modes_expecting(">0"), modes_expecting("=0")
    if frag:
        text += (f" Encapsulated by {frag}, a {exact}-byte packet exceeds the underlay MTU, so "
                 "IpFragCreates of the sending node must increase.")
    if no_frag:
        text += (f" Encapsulated by {no_frag}, a {exact}-byte packet fits the underlay MTU, so "
                 "IpFragCreates of the sending node must not change.")
    out += ["## MTU parity and fragmentation", "",
            text + " IpFragCreates is read from /proc/net/snmp of the sending node. The check runs "
            "once per iteration and mode; replies are summed over all checks, the IpFragCreates "
            "increase is listed per check.", "",
            f"| Mode | {big}-byte DF ping, replies | {exact}-byte DF ping, replies | "
            f"IpFragCreates increase during the {exact}-byte pings | Expected increase | Result |",
            "| --- | --- | --- | --- | --- | --- |"]
    for m in ran:
        rows = [r for r in parity if r.get("MODE") == m]
        if not rows:
            continue
        big_replies = (f"{sum(int(r['BIG_RX']) for r in rows)}/"
                       f"{sum(int(r['BIG_TX']) for r in rows)}")
        exact_replies = (f"{sum(int(r['EXACT_RX']) for r in rows)}/"
                         f"{sum(int(r['EXACT_TX']) for r in rows)}")
        deltas = ", ".join(r["FRAG_CREATES_DELTA"] for r in rows)
        expected = "0" if rows[0]["EXPECTED_DELTA"] == "=0" else "> 0"
        result = "pass" if all(r["RESULT"] == "pass" for r in rows) else "FAIL"
        out.append(f"| {NAMES[m]} | {big_replies} | {exact_replies} | {deltas} | {expected} | {result} |")
    out.append("")

out += ["## Results", "",
        f"Mean ± sample standard deviation over the iterations (n is shown where it differs from "
        f"{iterations})."]
if pairs:
    out.append("Comparison columns give the relative change of BPF Geneve over the Kernel Geneve baseline (`BPF Geneve (eth) vs Kernel`, `BPF Geneve (ip) vs Kernel`), plus `BPF Geneve (ip) vs BPF Geneve (eth)`.")
out.append("")
header = (["Workload / metric", "Unit", "Better"] +
          ["Kernel Geneve (Baseline)" if m == "kernel" else NAMES[m] for m in ran] +
          [title for _, _, title in pairs])
out += ["| " + " | ".join(header) + " |", "| " + " | ".join(["---"] * len(header)) + " |"]
for label, key, unit, better, dec in ROWS:
    cells, means = [], {}
    for m in ran:
        xs = values[m].get(key, [])
        if not xs:
            cells.append("n/a")
            continue
        means[m] = statistics.fmean(xs)
        cell = f"{means[m]:.{dec}f}"
        if len(xs) > 1:
            cell += f" ± {statistics.stdev(xs):.{dec}f}"
        if len(xs) != iterations:
            cell += f" (n={len(xs)})"
        cells.append(cell)
    if not means:
        continue
    for m, b, _ in pairs:
        if m in means and b in means and means[b]:
            cells.append(f"{(means[m] - means[b]) / abs(means[b]) * 100:+.1f} %")
        else:
            cells.append("n/a")
    out.append("| " + " | ".join([label, unit, better] + cells) + " |")
out.append("")

out += ["## Metric definitions", ""] + [f"- {d}" for d in DEFINITIONS] + [""]

out += ["## Raw data", "",
        "One line per iteration and mode; `POS` is the position of the mode in the order of that "
        "iteration.", ""]
for m in ran:
    out += [f"### {NAMES[m]} (`{m}`)", "", "```text"] + raw[m] + ["```", ""]
for name, title in (("mtu.txt", "Route MTU checks"), ("parity.txt", "MTU parity checks")):
    lines = read_lines(name)
    if lines:
        out += [f"### {title}", "", "```text"] + lines + ["```", ""]

report = "\n".join(out)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(report)
print(report)
PY
)"

log() {
	echo "[$(date +'%H:%M:%S')] $*" >&2
}

die() {
	log "ERROR: $*"
	exit 1
}

k() {
	if [[ -n "${KUBE_CONTEXT}" ]]; then
		kubectl --context "${KUBE_CONTEXT}" "$@"
	else
		kubectl "$@"
	fi
}

ks() {
	k -n kube-system "$@"
}

py() {
	python3 -c "${PY_HELPER}" "$@"
}

# cilium_pod_on_node NODE prints the running cilium-agent pod name on NODE.
cilium_pod_on_node() {
	local pod
	pod="$(ks get pods -l k8s-app=cilium --field-selector "spec.nodeName=$1" -o json |
		jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name' | head -n1)"
	[[ -n "${pod}" ]] || die "no cilium-agent pod found on node $1"
	echo "${pod}"
}

# node_exec NODE CMD... runs CMD in the cilium-agent container (hostNetwork) on NODE.
node_exec() {
	local pod
	pod="$(cilium_pod_on_node "$1")"
	shift
	ks exec "${pod}" -c cilium-agent -- "$@"
}

# node_epoch prints the current epoch seconds on CP_NODE, falling back to local
# date +%s if the cilium-agent container is currently restarting.
node_epoch() {
	node_exec "${CP_NODE}" date +%s 2>/dev/null || date +%s
}

# hoststat snapshots softirq ticks and NET_RX softirqs across STAT_NODES.
hoststat() {
	local i node
	local -a files=()
	for i in "${!STAT_NODES[@]}"; do
		node="${STAT_NODES[$i]}"
		files+=("${WORK_DIR}/hs_${i}")
		# shellcheck disable=SC2016 # Expanded by awk in the agent container.
		node_exec "${node}" awk '
			FILENAME=="/proc/stat" && FNR==1 { s=$8 }
			FILENAME=="/proc/softirqs" && $1=="NET_RX:" { r=0; for (i=2; i<=NF; i++) r+=$i }
			END { printf "%s %s\n", s, r }
		' /proc/stat /proc/softirqs >"${WORK_DIR}/hs_${i}" &
	done
	wait
	py hoststat "${files[@]}"
}

# word_after WORD prints the word that follows WORD on the first line of stdin
# that contains it.
word_after() {
	awk -v w="$1" '{ for (i = 1; i < NF; i++) if ($i == w) { print $(i + 1); exit } }'
}

# route_mtu prints the "mtu" attribute of the route on stdin ("mtu lock N" too).
route_mtu() {
	awk '{ for (i = 1; i < NF; i++) if ($i == "mtu") { v = $(i + 1); if (v == "lock") v = $(i + 2); print v; exit } }'
}

# retry COUNT DELAY CMD... runs CMD until it succeeds, at most COUNT times.
retry() {
	local count="$1" delay="$2" i
	shift 2
	for ((i = 1; i <= count; i++)); do
		if "$@"; then
			return 0
		fi
		sleep "${delay}"
	done
	return 1
}

require_tools() {
	local tool
	local -a missing=()
	for tool in "$@"; do
		command -v "${tool}" >/dev/null 2>&1 || missing+=("${tool}")
	done
	((${#missing[@]} == 0)) || die "missing tools: ${missing[*]}"
}

resolve_cluster_mode() {
	if [[ -n "${KUBE_CONTEXT}" ]]; then
		if [[ "${KUBE_CONTEXT}" == kind-* && -z "${CLUSTER_NAME}" ]]; then
			CLUSTER_NAME="${KUBE_CONTEXT#kind-}"
		fi
	elif [[ -n "${CLUSTER_NAME}" ]]; then
		KUBE_CONTEXT="kind-${CLUSTER_NAME}"
	elif kubectl -n kube-system get ds cilium >/dev/null 2>&1; then
		KUBE_CONTEXT="$(kubectl config current-context 2>/dev/null || true)"
		if [[ "${KUBE_CONTEXT}" == kind-* ]]; then
			CLUSTER_NAME="${KUBE_CONTEXT#kind-}"
		fi
	else
		CLUSTER_NAME="geneve-perf"
		KUBE_CONTEXT="kind-${CLUSTER_NAME}"
	fi

	if [[ "${KUBE_CONTEXT}" == kind-* && -n "${CLUSTER_NAME}" ]]; then
		USE_KIND=1
	else
		USE_KIND=0
	fi
}

check_inputs() {
	local m seen=","

	require_tools kubectl jq python3 sha256sum awk
	[[ "${ITERATIONS}" =~ ^[1-9][0-9]*$ ]] || die "ITERATIONS must be a positive integer"
	[[ "${IPERF_DURATION}" =~ ^[1-9][0-9]*$ ]] || die "IPERF_DURATION must be a positive integer"

	IFS=',' read -r -a RUN_MODES <<<"${MODES// /}"
	((${#RUN_MODES[@]} > 0)) || die "MODES is empty"
	for m in "${RUN_MODES[@]}"; do
		case "${m}" in
		kernel | eth | ip) ;;
		*) die "unknown mode '${m}' in MODES (valid: kernel, eth, ip)" ;;
		esac
		[[ "${seen}" != *",${m},"* ]] || die "mode '${m}' is listed twice in MODES"
		seen+="${m},"
	done
}

# mode_config MODE prints the enable-bpf-geneve and geneve-inner-protocol
# values of MODE.
mode_config() {
	case "$1" in
	kernel) echo "false eth" ;;
	eth) echo "true eth" ;;
	ip) echo "true ip" ;;
	esac
}

# mode_overhead MODE prints the encapsulation overhead of MODE over an IPv4
# underlay: outer IPv4 (20), UDP (8) and Geneve (8) headers, plus the inner
# Ethernet header (14) unless the inner protocol is ip.
mode_overhead() {
	case "$1" in
	ip) echo 36 ;;
	*) echo 50 ;;
	esac
}

mode_active() {
	local m
	for m in "${RUN_MODES[@]}"; do
		if [[ "${m}" == "$1" ]]; then
			return 0
		fi
	done
	return 1
}

# rotated_modes ITER prints the modes of iteration ITER (1-based): RUN_MODES
# rotated left by ITER - 1 positions.
rotated_modes() {
	local iter="$1" n=${#RUN_MODES[@]} i
	local -a order=()
	for ((i = 0; i < n; i++)); do
		order+=("${RUN_MODES[$(((iter - 1 + i) % n))]}")
	done
	echo "${order[*]}"
}

# config_value KEY prints the value of KEY in cilium-config, or ABSENT.
config_value() {
	ks get configmap cilium-config -o json |
		jq -r --arg key "$1" --arg absent "${ABSENT}" '.data[$key] // $absent'
}

# current_mode prints the mode cilium-config is set to.
current_mode() {
	local enable inner
	enable="$(config_value enable-bpf-geneve)"
	inner="$(config_value geneve-inner-protocol)"
	if [[ "${enable}" != true ]]; then
		echo kernel
	elif [[ "${inner}" == ip ]]; then
		echo ip
	else
		echo eth
	fi
}

ensure_cluster() {
	local clusters
	resolve_cluster_mode
	if ((USE_KIND)); then
		require_tools kind docker
		clusters="$(kind get clusters 2>/dev/null || true)"
		if ! grep -qxF "${CLUSTER_NAME}" <<<"${clusters}"; then
			require_tools helm git make go
			log "Creating Kind cluster '${CLUSTER_NAME}' (1 control-plane node, 2 workers)..."
			"${REPO_ROOT}/contrib/scripts/kind.sh" 1 2 "${CLUSTER_NAME}" >&2
			KIND_CLUSTERS="${CLUSTER_NAME}" make -C "${REPO_ROOT}" kind-image-fast >&2
			helm upgrade --install cilium "${REPO_ROOT}/install/kubernetes/cilium" \
				--kube-context "${KUBE_CONTEXT}" \
				--namespace kube-system \
				-f "${REPO_ROOT}/contrib/testing/kind-common.yaml" \
				-f "${REPO_ROOT}/contrib/testing/kind-fast.yaml" \
				--set routingMode=tunnel \
				--set tunnelProtocol=geneve \
				--set kubeProxyReplacement=true >&2
		else
			log "Using the existing Kind cluster '${CLUSTER_NAME}' (context '${KUBE_CONTEXT}')"
		fi
	else
		log "Using the existing Kubernetes cluster (context '${KUBE_CONTEXT:-current}')"
	fi
	ks rollout status ds/cilium --timeout=300s >/dev/null || die "the cilium DaemonSet is not ready"
}

# discover_nodes auto-selects CP_NODE (cross-node client), WORKER_NODE (server
# and same-node client), and WORKER2_NODE (NodePort forwarder) when not set.
discover_nodes() {
	local all_json cilium_nodes_json b0 b1
	local -a all_nodes=() workers=()

	load_cilium_pods
	cilium_nodes_json="$(ks get pods -l k8s-app=cilium -o json |
		jq -c '[.items[] | select(.metadata.deletionTimestamp == null) | .spec.nodeName]')"
	all_json="$(k get nodes -o json)"

	mapfile -t all_nodes < <(jq -r --argjson cn "${cilium_nodes_json}" '
		.items[]
		| select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
		| select(.metadata.name as $n | $cn | index($n))
		| .metadata.name
	' <<<"${all_json}")
	((${#all_nodes[@]} >= 2)) ||
		die "the benchmark requires at least 2 Ready nodes running Cilium (found ${#all_nodes[@]})"

	mapfile -t workers < <(jq -r --argjson cn "${cilium_nodes_json}" '
		.items[]
		| select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
		| select(.metadata.name as $n | $cn | index($n))
		| select((.metadata.labels["node-role.kubernetes.io/control-plane"] // null) == null and
		         (.metadata.labels["node-role.kubernetes.io/master"] // null) == null)
		| .metadata.name
	' <<<"${all_json}")

	if [[ -z "${CP_NODE}" || -z "${WORKER_NODE}" || -z "${WORKER2_NODE}" ]]; then
		if ((USE_KIND)) &&
			printf '%s\n' "${all_nodes[@]}" | grep -qxF "${CLUSTER_NAME}-control-plane" &&
			printf '%s\n' "${all_nodes[@]}" | grep -qxF "${CLUSTER_NAME}-worker" &&
			printf '%s\n' "${all_nodes[@]}" | grep -qxF "${CLUSTER_NAME}-worker2"; then
			CP_NODE="${CP_NODE:-${CLUSTER_NAME}-control-plane}"
			WORKER_NODE="${WORKER_NODE:-${CLUSTER_NAME}-worker}"
			WORKER2_NODE="${WORKER2_NODE:-${CLUSTER_NAME}-worker2}"
		elif ((${#workers[@]} >= 3)); then
			CP_NODE="${CP_NODE:-${workers[0]}}"
			WORKER_NODE="${WORKER_NODE:-${workers[1]}}"
			WORKER2_NODE="${WORKER2_NODE:-${workers[2]}}"
		elif ((${#all_nodes[@]} >= 3)); then
			CP_NODE="${CP_NODE:-${all_nodes[0]}}"
			WORKER_NODE="${WORKER_NODE:-${all_nodes[1]}}"
			WORKER2_NODE="${WORKER2_NODE:-${all_nodes[2]}}"
		else
			CP_NODE="${CP_NODE:-${all_nodes[0]}}"
			WORKER_NODE="${WORKER_NODE:-${all_nodes[1]}}"
			WORKER2_NODE="${WORKER2_NODE:-${all_nodes[0]}}"
		fi
	fi

	log "Selected nodes: client=${CP_NODE}, server=${WORKER_NODE}, nodeport=${WORKER2_NODE}"

	b0="$(node_exec "${CP_NODE}" cat /proc/sys/kernel/random/boot_id | tr -d '[:space:]')"
	b1="$(node_exec "${WORKER_NODE}" cat /proc/sys/kernel/random/boot_id | tr -d '[:space:]')"
	if [[ "${b0}" == "${b1}" ]]; then
		SHARED_KERNEL=1
		STAT_NODES=("${CP_NODE}")
	else
		SHARED_KERNEL=0
		STAT_NODES=("${CP_NODE}" "${WORKER_NODE}")
	fi
}

# check_cluster_config checks the cilium-config settings the benchmark relies
# on; absent keys take the agent defaults.
check_cluster_config() {
	local value
	value="$(config_value routing-mode)"
	[[ "${value}" == tunnel || "${value}" == "${ABSENT}" ]] ||
		die "cilium-config has routing-mode=${value}, the benchmark needs tunnel"
	value="$(config_value tunnel-protocol)"
	[[ "${value}" == geneve ]] || die "cilium-config has tunnel-protocol=${value}, the benchmark needs geneve"
	# The expected MTUs and the parity check assume an IPv4 underlay.
	value="$(config_value enable-ipv4)"
	[[ "${value}" == true || "${value}" == "${ABSENT}" ]] ||
		die "cilium-config has enable-ipv4=${value}, the benchmark needs an IPv4 underlay"
	value="$(config_value underlay-protocol)"
	[[ "${value}" != ipv6 ]] || die "cilium-config has underlay-protocol=ipv6, the benchmark needs an IPv4 underlay"
}

# load_cilium_pods sets CILIUM_PODS to the cilium agent pods that are not
# being deleted.
load_cilium_pods() {
	local pods
	pods="$(ks get pods -l k8s-app=cilium -o json |
		jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name')"
	[[ -n "${pods}" ]] || die "no cilium agent pods found"
	mapfile -t CILIUM_PODS <<<"${pods}"
}

# has_kind_fast_mounts returns 0 when running on a local Kind cluster whose
# cilium DaemonSet mounts NODE_AGENT_BIN and NODE_BPF_DIR from the nodes.
has_kind_fast_mounts() {
	local paths
	((USE_KIND)) || return 1
	paths="$(ks get ds cilium -o json | jq -r '.spec.template.spec.volumes[]?.hostPath.path // empty')"
	grep -qxF "${NODE_AGENT_BIN}" <<<"${paths}" && grep -qxF "${NODE_BPF_DIR}" <<<"${paths}"
}

# stage_bpf_sources copies the agent BPF sources to WORK_DIR/bpf-stage/bpf:
# the files the agent image installs into /var/lib/cilium/bpf (BPF_SRCFILES in
# Makefile.defs), including untracked ones, so local changes are benchmarked.
stage_bpf_sources() {
	local f rel stage="${WORK_DIR}/bpf-stage/bpf"

	rm -rf "${stage}"
	mkdir -p "${stage}"
	while IFS= read -r -d '' f; do
		case "${f}" in
		bpf/.gitignore | bpf/Makefile | bpf/Makefile.bpf | bpf/tests/* | bpf/complexity-tests/* | bpf/custom/*)
			continue
			;;
		esac
		# Tracked files deleted in the working tree.
		[[ -f "${REPO_ROOT}/${f}" ]] || continue
		rel="${f#bpf/}"
		mkdir -p "${stage}/$(dirname "${rel}")"
		cp "${REPO_ROOT}/${f}" "${stage}/${rel}"
	done < <(git -C "${REPO_ROOT}" ls-files -z --cached --others --exclude-standard -- bpf/)

	BPF_FILES="$(find "${stage}" -type f | wc -l)"
	((BPF_FILES > 0)) || die "no BPF sources found in ${REPO_ROOT}/bpf"
	BPF_SHA="$(cd "${stage}" && bash -c "${MANIFEST_CMD}")"
}

# running_agent_sha POD prints the sha256 of the cilium-agent binary running in
# POD (not of the file, which may have been replaced since it started).
running_agent_sha() {
	# shellcheck disable=SC2016 # Expanded by the shell in the agent container.
	ks exec "$1" -c cilium-agent -- sh -c 'sha256sum "/proc/$(pgrep -o -x cilium-agent)/exe"' | cut -d' ' -f1
}

# stage_and_install_sources either builds and copies local sources into a
# kind-fast cluster, or records and verifies the image-deployed Cilium binaries
# and BPF sources across all nodes in a managed cluster.
stage_and_install_sources() {
	local node pod node_sha node_bpf since restart=0
	local -a nodes

	if has_kind_fast_mounts; then
		require_tools kind docker git make go
		log "Building daemon/cilium-agent..."
		make -C "${REPO_ROOT}/daemon" GOOS=linux >&2
		AGENT_SHA="$(sha256sum "${REPO_ROOT}/daemon/cilium-agent" | cut -d' ' -f1)"
		stage_bpf_sources
		GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
		GIT_DIRTY="$(git -C "${REPO_ROOT}" status --porcelain | wc -l)"

		mapfile -t nodes < <(kind get nodes --name "${CLUSTER_NAME}")
		((${#nodes[@]} > 0)) || die "no nodes found for the Kind cluster ${CLUSTER_NAME}"
		for node in "${nodes[@]}"; do
			node_sha="$(docker exec "${node}" sha256sum "${NODE_AGENT_BIN}" 2>/dev/null | cut -d' ' -f1 || true)"
			if [[ "${node_sha}" != "${AGENT_SHA}" ]]; then
				log "${node}: installing daemon/cilium-agent"
				docker exec "${node}" rm -f "${NODE_AGENT_BIN}"
				docker cp "${REPO_ROOT}/daemon/cilium-agent" "${node}:${NODE_AGENT_BIN}"
				docker exec "${node}" chmod 0755 "${NODE_AGENT_BIN}"
				restart=1
			fi
			node_bpf="$(docker exec "${node}" sh -c "cd '${NODE_BPF_DIR}' && ${MANIFEST_CMD}" 2>/dev/null || true)"
			if [[ "${node_bpf}" != "${BPF_SHA}" ]]; then
				log "${node}: installing the agent BPF sources (${BPF_FILES} files)"
				docker exec "${node}" sh -c "mkdir -p '${NODE_BPF_DIR}' && find '${NODE_BPF_DIR}' -mindepth 1 -delete"
				docker cp "${WORK_DIR}/bpf-stage/bpf/." "${node}:${NODE_BPF_DIR}/"
				docker exec "${node}" find "${NODE_BPF_DIR}" -type f -exec chmod 0644 {} +
				restart=1
			fi
		done
		load_cilium_pods
		for pod in "${CILIUM_PODS[@]}"; do
			[[ "$(running_agent_sha "${pod}")" == "${AGENT_SHA}" ]] || restart=1
		done

		if ((restart)); then
			log "Restarting the cilium DaemonSet to run the local build..."
			since="$(node_epoch)"
			ks rollout restart ds/cilium >/dev/null
			wait_rollout
			[[ -z "${MODE_REJECTED}" ]] ||
				die "the local build refuses the current cilium-config: ${MODE_REJECTED}; set geneve-inner-protocol=eth and rerun"
			wait_datapath_ready "${since}"
		fi
	else
		load_cilium_pods
		AGENT_SHA="$(running_agent_sha "${CILIUM_PODS[0]}")"
		BPF_FILES="$(ks exec "${CILIUM_PODS[0]}" -c cilium-agent -- sh -c \
			'cd /var/lib/cilium/bpf && find . -type f ! -path "./include/bpf/features*.h" ! -path "./.gitignore" ! -path "./Makefile*" ! -path "./tests/*" ! -path "./complexity-tests/*" ! -path "./custom/*" ! -name "*.o" ! -name "*.tmp" | wc -l' | tr -d '[:space:]')"
		BPF_SHA="$(ks exec "${CILIUM_PODS[0]}" -c cilium-agent -- sh -c "cd /var/lib/cilium/bpf && ${MANIFEST_CMD}")"
		GIT_COMMIT="$(ks exec "${CILIUM_PODS[0]}" -c cilium-agent -- cilium-dbg version 2>/dev/null |
			awk '/^Cilium / { print $NF; exit }' || true)"
		if [[ -z "${GIT_COMMIT}" ]] && command -v git >/dev/null 2>&1; then
			GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
		fi
		GIT_DIRTY="0"
		log "Using the deployed Cilium DaemonSet image (cilium-agent sha256 ${AGENT_SHA:0:12}...)"
	fi

	load_cilium_pods
	for pod in "${CILIUM_PODS[@]}"; do
		[[ "$(running_agent_sha "${pod}")" == "${AGENT_SHA}" ]] ||
			die "${pod} does not run the expected cilium-agent binary (sha256 ${AGENT_SHA})"
		[[ "$(ks exec "${pod}" -c cilium-agent -- sh -c "cd /var/lib/cilium/bpf && ${MANIFEST_CMD}")" == "${BPF_SHA}" ]] ||
			die "${pod} does not have the expected BPF sources in /var/lib/cilium/bpf (manifest ${BPF_SHA})"
	done
}

# wait_datapath_ready SINCE waits until every agent has written node_config.h
# at or after SINCE (epoch seconds), all its endpoints are ready and no BPF
# compilation is running.
wait_datapath_ready() {
	local since="$1" pod i mtime states
	load_cilium_pods
	for pod in "${CILIUM_PODS[@]}"; do
		for ((i = 0; i < 90; i++)); do
			mtime="$(ks exec "${pod}" -c cilium-agent -- stat -c %Y "${NODE_CONFIG_H}" 2>/dev/null || true)"
			[[ "${mtime}" =~ ^[0-9]+$ ]] || mtime=0
			states="$(ks exec "${pod}" -c cilium-agent -- cilium-dbg endpoint list -o json 2>/dev/null |
				jq -r '[.[].status.state] | unique | join(",")' 2>/dev/null || true)"
			if ((mtime >= since)) && [[ "${states}" == ready ]] &&
				! ks exec "${pod}" -c cilium-agent -- pgrep clang >/dev/null 2>&1; then
				continue 2
			fi
			sleep 2
		done
		die "${pod}: datapath not ready after 180s (node_config.h written at ${mtime}, want >= ${since}; endpoint states '${states}')"
	done
}

# assert_node_config MODE checks the BPF Geneve defines of every agent.
assert_node_config() {
	local mode="$1" pod defines want
	case "${mode}" in
	kernel) want="" ;;
	eth) want=$'#define ENABLE_BPF_GENEVE 1\n#define GENEVE_INNER_PROTOCOL 1' ;;
	ip) want=$'#define ENABLE_BPF_GENEVE 1\n#define GENEVE_INNER_PROTOCOL 2' ;;
	esac
	load_cilium_pods
	for pod in "${CILIUM_PODS[@]}"; do
		# grep exits with 1 if nothing matches (kernel mode), 2 on errors.
		defines="$(ks exec "${pod}" -c cilium-agent -- sh -c \
			"grep -E '^#define (ENABLE_BPF_GENEVE|GENEVE_INNER_PROTOCOL) ' '${NODE_CONFIG_H}' || [ \$? -eq 1 ]")" ||
			die "${pod}: cannot read ${NODE_CONFIG_H}"
		[[ "$(sort <<<"${defines}")" == "$(sort <<<"${want}")" ]] ||
			die "${pod}: unexpected node_config.h defines for mode ${mode}: '${defines//$'\n'/; }'"
	done
}

# patch_cilium_config ENABLE INNER sets enable-bpf-geneve and
# geneve-inner-protocol in cilium-config; ABSENT removes the key.
patch_cilium_config() {
	local patch
	patch="$(jq -cn --arg e "$1" --arg i "$2" --arg absent "${ABSENT}" \
		'{data: {"enable-bpf-geneve": (if $e == $absent then null else $e end),
		         "geneve-inner-protocol": (if $i == $absent then null else $i end)}}')"
	CONFIG_TOUCHED=1
	ks patch configmap cilium-config --type merge -p "${patch}" >/dev/null
}

# template_pods prints the cilium pods created from the current pod template,
# recognized by the annotation that "kubectl rollout restart" sets on it.
template_pods() {
	local restarted
	restarted="$(ks get ds cilium -o json |
		jq -r '.spec.template.metadata.annotations["kubectl.kubernetes.io/restartedAt"] // ""')"
	ks get pods -l k8s-app=cilium -o json |
		jq -r --arg restarted "${restarted}" '.items[] | select(.metadata.deletionTimestamp == null) |
			select((.metadata.annotations["kubectl.kubernetes.io/restartedAt"] // "") == $restarted) |
			.metadata.name'
}

# wait_rollout waits for the cilium DaemonSet rollout. If an agent refuses to
# start because the kernel lacks what geneve-inner-protocol=ip needs (see
# checkBPFGeneveRequirements), it sets MODE_REJECTED to the agent's error
# instead of waiting for the timeout. Only agents of the current pod template
# are checked: when switching away from a rejected mode, the agents that are
# still crash-looping with the previous configuration log the same error.
wait_rollout() {
	local deadline=$((SECONDS + 300)) pod logs
	MODE_REJECTED=""
	until ks rollout status ds/cilium --timeout=10s >/dev/null 2>&1; do
		for pod in $(template_pods); do
			logs="$(ks logs "${pod}" -c cilium-agent --tail=300 2>/dev/null || true)"
			logs+=$'\n'"$(ks logs "${pod}" -c cilium-agent --previous --tail=300 2>/dev/null || true)"
			MODE_REJECTED="$(grep -o 'geneve-inner-protocol=ip requires[^"]*' <<<"${logs}" | head -n1 || true)"
			if [[ -n "${MODE_REJECTED}" ]]; then
				return 0
			fi
		done
		((SECONDS < deadline)) || die "the cilium DaemonSet rollout did not complete within 300s"
	done
}

# apply_mode_config MODE switches Cilium to MODE. Sets MODE_REJECTED and leaves
# CURRENT_MODE unchanged if the agents refuse MODE.
apply_mode_config() {
	local mode="$1" since enable inner
	read -r enable inner <<<"$(mode_config "${mode}")"
	log "Switching Cilium to mode ${mode} (enable-bpf-geneve=${enable}, geneve-inner-protocol=${inner})..."
	since="$(node_epoch)"
	patch_cilium_config "${enable}" "${inner}"
	ks rollout restart ds/cilium >/dev/null
	wait_rollout
	if [[ -n "${MODE_REJECTED}" ]]; then
		return 0
	fi
	wait_datapath_ready "${since}"
	assert_node_config "${mode}"
	CURRENT_MODE="${mode}"
}

ensure_image() {
	local node load=0
	local -a nodes
	((USE_KIND)) || return 0
	command -v kind >/dev/null 2>&1 && command -v docker >/dev/null 2>&1 || return 0
	mapfile -t nodes < <(kind get nodes --name "${CLUSTER_NAME}" 2>/dev/null || true)
	((${#nodes[@]} > 0)) || return 0
	docker image inspect "${BENCH_IMAGE}" >/dev/null 2>&1 || docker pull "${BENCH_IMAGE}" >&2
	for node in "${nodes[@]}"; do
		docker exec "${node}" crictl inspecti "${BENCH_IMAGE}" >/dev/null 2>&1 || load=1
	done
	if ((load)); then
		log "Loading ${BENCH_IMAGE} into the Kind nodes..."
		kind load docker-image "${BENCH_IMAGE}" --name "${CLUSTER_NAME}" >&2
	fi
}

# prepare_endpoints sets up the service and resolves the addresses the
# workloads use.
prepare_endpoints() {
	ensure_image
	k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${SERVICE_NAME}
spec:
  type: NodePort
  selector:
    app: iperf3-server
  ports:
  - name: iperf3-tcp
    port: 5201
    targetPort: 5201
    nodePort: ${NODEPORT_PORT}
    protocol: TCP
  - name: iperf3-udp
    port: 5201
    targetPort: 5201
    nodePort: ${NODEPORT_PORT}
    protocol: UDP
EOF
	SVC_IP="$(k get svc "${SERVICE_NAME}" -o jsonpath='{.spec.clusterIP}')"
	WORKER2_IP="$(k get node "${WORKER2_NODE}" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' |
		tr ' ' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$' || true)"
	[[ -n "${WORKER2_IP}" ]] || die "${WORKER2_NODE} has no IPv4 InternalIP"
}

# underlay_mtu NODE prints the device and MTU of the IPv4 default route of NODE.
underlay_mtu() {
	local node="$1" route dev mtu
	route="$(node_exec "${node}" ip -4 route show default)"
	dev="$(word_after dev <<<"${route}")"
	[[ -n "${dev}" ]] || die "${node} has no IPv4 default route"
	mtu="$(node_exec "${node}" cat "/sys/class/net/${dev}/mtu")"
	[[ "${mtu}" =~ ^[1-9][0-9]*$ ]] || die "cannot read the MTU of ${dev} on ${node}"
	echo "${dev} ${mtu}"
}

# frag_creates NODE prints the IpFragCreates counter of NODE's network namespace.
frag_creates() {
	# Read all input: exiting early could fail the writer with SIGPIPE.
	node_exec "$1" cat /proc/net/snmp |
		awk '$1 == "Ip:" { n++; if (n == 1) for (i = 2; i <= NF; i++) idx[$i] = i; else if (n == 2) print $idx["FragCreates"] }'
}

# recreate_pods deletes and recreates the benchmark pods (server + same-node
# client on WORKER_NODE, cross-node client on CP_NODE), so that they get the
# route MTU of the current mode, and waits until they are reachable.
recreate_pods() {
	log "Recreating the benchmark pods..."
	k delete pod "${CLIENT_POD}" "${LOCAL_CLIENT_POD}" "${SERVER_POD}" --ignore-not-found --wait=true --timeout=120s >/dev/null
	k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${SERVER_POD}
  labels:
    app: iperf3-server
spec:
  nodeName: ${WORKER_NODE}
  terminationGracePeriodSeconds: 1
  tolerations:
  - operator: Exists
  containers:
  - name: iperf3
    image: ${BENCH_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["iperf3", "-s"]
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${LOCAL_CLIENT_POD}
spec:
  nodeName: ${WORKER_NODE}
  terminationGracePeriodSeconds: 1
  tolerations:
  - operator: Exists
  containers:
  - name: iperf3
    image: ${BENCH_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "infinity"]
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${CLIENT_POD}
spec:
  nodeName: ${CP_NODE}
  terminationGracePeriodSeconds: 1
  tolerations:
  - operator: Exists
  containers:
  - name: iperf3
    image: ${BENCH_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "infinity"]
    securityContext:
      capabilities:
        add: ["NET_ADMIN"]
EOF
	k wait --for=condition=Ready "pod/${SERVER_POD}" "pod/${LOCAL_CLIENT_POD}" "pod/${CLIENT_POD}" --timeout=180s >/dev/null
	SERVER_IP="$(k get pod "${SERVER_POD}" -o jsonpath='{.status.podIPs[*].ip}' |
		tr ' ' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$' || true)"
	[[ -n "${SERVER_IP}" ]] || die "${SERVER_POD} has no IPv4 address"
	# In CLIENT_POD's private network namespace, DNAT NODEPORT_DUMMY_IP:NODEPORT_PORT
	# to WORKER2_IP:NODEPORT_PORT after connect() so Cilium's cgroup socket-LB
	# does not rewrite the destination to SERVER_IP at connect() time.
	k exec "${CLIENT_POD}" -- iptables -t nat -A OUTPUT -d "${NODEPORT_DUMMY_IP}" \
		-p tcp --dport "${NODEPORT_PORT}" -j DNAT --to-destination "${WORKER2_IP}:${NODEPORT_PORT}"
	wait_datapath_ready 0
	retry 60 1 service_has_endpoint "${SERVER_IP}" || die "${SERVICE_NAME} has no endpoint ${SERVER_IP}"
}

service_has_endpoint() {
	local addrs
	addrs="$(k get endpointslices -l "kubernetes.io/service-name=${SERVICE_NAME}" \
		-o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null || true)"
	[[ " ${addrs} " == *" $1 "* ]]
}

# assert_pod_mtus MODE checks the default route MTU of the benchmark pods (IPv4,
# and IPv6 if the pod has an IPv6 default route).
assert_pod_mtus() {
	local mode="$1" overhead expected pod family route mtu
	overhead="$(mode_overhead "${mode}")"
	expected=$((UNDERLAY_MTU - overhead))
	for pod in "${CLIENT_POD}" "${LOCAL_CLIENT_POD}" "${SERVER_POD}"; do
		for family in 4 6; do
			route="$(k exec "${pod}" -- ip "-${family}" route show default)"
			if [[ -z "${route}" ]]; then
				[[ "${family}" == 6 ]] || die "${pod} has no IPv4 default route"
				continue
			fi
			mtu="$(route_mtu <<<"${route}")"
			printf 'ITER=%s MODE=%s POD=%s FAMILY=%s MTU=%s EXPECTED=%s UNDERLAY=%s OVERHEAD=%s\n' \
				"${CUR_ITER}" "${mode}" "${pod}" "${family}" "${mtu:-none}" "${expected}" \
				"${UNDERLAY_MTU}" "${overhead}" >>"${WORK_DIR}/mtu.txt"
			[[ "${mtu}" == "${expected}" ]] ||
				die "${pod}: IPv${family} default route MTU is '${mtu:-none}' in mode ${mode}, expected ${expected} (underlay ${UNDERLAY_MTU} - ${overhead})"
		done
	done
}

# enter_mode MODE switches Cilium to MODE if needed and makes sure that the
# benchmark pods were created in MODE.
enter_mode() {
	local mode="$1"
	if [[ "${mode}" != "${CURRENT_MODE}" ]]; then
		apply_mode_config "${mode}"
		[[ -z "${MODE_REJECTED}" ]] || die "the agents rejected mode ${mode}: ${MODE_REJECTED}"
	fi
	if [[ "${PODS_MODE}" != "${mode}" ]]; then
		recreate_pods
		PODS_MODE="${mode}"
	fi
	assert_pod_mtus "${mode}"
}

# precheck_ip_mode switches to mode ip once before the first iteration if it
# was requested. The agents refuse to start in mode ip on kernels without
# bpf_skb_adjust_room() support for BPF_F_ADJ_ROOM_DECAP_L4_UDP; the mode is
# then dropped from RUN_MODES and Cilium is switched back.
precheck_ip_mode() {
	local m
	local -a kept=()
	if ! mode_active ip || [[ "${CURRENT_MODE}" == ip ]]; then
		return 0
	fi
	log "Checking whether the agents accept mode ip..."
	apply_mode_config ip
	if [[ -z "${MODE_REJECTED}" ]]; then
		return 0
	fi
	log "Skipping mode ip: the agents rejected it: ${MODE_REJECTED}"
	printf 'ip\t%s\n' "${MODE_REJECTED}" >>"${WORK_DIR}/skipped.tsv"
	for m in "${RUN_MODES[@]}"; do
		[[ "${m}" == ip ]] || kept+=("${m}")
	done
	RUN_MODES=("${kept[@]}")
	# The exit handler restores cilium-config.
	((${#RUN_MODES[@]} > 0)) || die "no mode left to benchmark"
	# CURRENT_MODE still is the mode the agents ran in before.
	apply_mode_config "${CURRENT_MODE}"
	[[ -z "${MODE_REJECTED}" ]] || die "the agents also rejected mode ${CURRENT_MODE}: ${MODE_REJECTED}"
}

warmup() {
	k exec "${LOCAL_CLIENT_POD}" -- iperf3 -c "${SERVER_IP}" -t 1 -P 2 >/dev/null ||
		die "same-node iperf3 warm-up from ${LOCAL_CLIENT_POD} to ${SERVER_IP} failed"
	k exec "${CLIENT_POD}" -- ping -c 3 -W 2 -q "${SERVER_IP}" >/dev/null ||
		die "no ICMP connectivity from ${CLIENT_POD} to ${SERVER_IP}"
	k exec "${CLIENT_POD}" -- iperf3 -c "${SERVER_IP}" -t 2 -P 4 >/dev/null ||
		die "iperf3 warm-up to ${SERVER_IP} failed"
	retry 15 2 k exec "${CLIENT_POD}" -- iperf3 -c "${SVC_IP}" -t 1 -P 2 >/dev/null 2>&1 ||
		die "iperf3 warm-up via the ClusterIP ${SVC_IP} failed"
	retry 15 2 k exec "${CLIENT_POD}" -- iperf3 -c "${NODEPORT_DUMMY_IP}" -p "${NODEPORT_PORT}" -t 1 -P 2 >/dev/null 2>&1 ||
		die "iperf3 warm-up via the NodePort ${WORKER2_IP}:${NODEPORT_PORT} failed"
}

# parity_check MODE checks that oversized DF packets are handled like with the
# kernel device (outer fragmentation) and that ip mode carries 14 more bytes
# without fragmentation; see the header of this script.
parity_check() {
	local mode="$1" big=$((UNDERLAY_MTU - 32)) exact=$((UNDERLAY_MTU - 36))
	local c_route c_gw c_dev c_mtu_args s_route s_gw s_dev s_mtu_args
	local out_big out_exact f0 f1 delta expect result=pass
	local big_tx big_rx exact_tx exact_rx counts

	c_route="$(k exec "${CLIENT_POD}" -- ip -4 route show default)"
	[[ -n "${c_route}" && "${c_route}" != *$'\n'* ]] || die "${CLIENT_POD}: unexpected IPv4 default routes: ${c_route}"
	c_gw="$(word_after via <<<"${c_route}")"
	c_dev="$(word_after dev <<<"${c_route}")"
	if [[ "$(word_after mtu <<<"${c_route}")" == lock ]]; then
		c_mtu_args="mtu lock $(route_mtu <<<"${c_route}")"
	else
		c_mtu_args="mtu $(route_mtu <<<"${c_route}")"
	fi

	s_route="$(k exec "${SERVER_POD}" -- ip -4 route show default)"
	[[ -n "${s_route}" && "${s_route}" != *$'\n'* ]] || die "${SERVER_POD}: unexpected IPv4 default routes: ${s_route}"
	s_gw="$(word_after via <<<"${s_route}")"
	s_dev="$(word_after dev <<<"${s_route}")"
	if [[ "$(word_after mtu <<<"${s_route}")" == lock ]]; then
		s_mtu_args="mtu lock $(route_mtu <<<"${s_route}")"
	else
		s_mtu_args="mtu $(route_mtu <<<"${s_route}")"
	fi

	# Nothing between raising and restoring the route MTUs may abort the
	# script; the results are checked once the routes are restored. Both
	# pods' route MTUs are raised because Cilium's conntrack rejects
	# fragmented inner ICMP packets (ct_extract_ports4), so the server's
	# echo reply must also be outer-fragmented rather than inner-fragmented.
	k exec "${CLIENT_POD}" -- ip -4 route change default via "${c_gw}" dev "${c_dev}" mtu "${UNDERLAY_MTU}"
	k exec "${CLIENT_POD}" -- ip -4 route flush cache 2>/dev/null || true
	k exec "${SERVER_POD}" -- ip -4 route change default via "${s_gw}" dev "${s_dev}" mtu "${UNDERLAY_MTU}"
	k exec "${SERVER_POD}" -- ip -4 route flush cache 2>/dev/null || true
	out_big="$(k exec "${CLIENT_POD}" -- ping -M "do" -s $((big - 28)) -c 5 -i 0.2 -W 2 "${SERVER_IP}" 2>&1 || true)"
	f0="$(frag_creates "${CP_NODE}" || true)"
	out_exact="$(k exec "${CLIENT_POD}" -- ping -M "do" -s $((exact - 28)) -c 10 -i 0.2 -W 2 "${SERVER_IP}" 2>&1 || true)"
	f1="$(frag_creates "${CP_NODE}" || true)"
	# shellcheck disable=SC2086 # c_mtu_args and s_mtu_args hold several words on purpose.
	k exec "${CLIENT_POD}" -- ip -4 route change default via "${c_gw}" dev "${c_dev}" ${c_mtu_args}
	k exec "${CLIENT_POD}" -- ip -4 route flush cache 2>/dev/null || true
	# shellcheck disable=SC2086
	k exec "${SERVER_POD}" -- ip -4 route change default via "${s_gw}" dev "${s_dev}" ${s_mtu_args}
	k exec "${SERVER_POD}" -- ip -4 route flush cache 2>/dev/null || true
	[[ "$(k exec "${CLIENT_POD}" -- ip -4 route show default)" == "${c_route}" ]] ||
		die "${CLIENT_POD}: could not restore the default route '${c_route}'"
	[[ "$(k exec "${SERVER_POD}" -- ip -4 route show default)" == "${s_route}" ]] ||
		die "${SERVER_POD}: could not restore the default route '${s_route}'"

	counts="$(py pingcount <<<"${out_big}")"
	read -r big_tx big_rx <<<"${counts}"
	counts="$(py pingcount <<<"${out_exact}")"
	read -r exact_tx exact_rx <<<"${counts}"
	[[ "${f0}" =~ ^[0-9]+$ && "${f1}" =~ ^[0-9]+$ ]] || die "cannot read IpFragCreates on ${CP_NODE}"
	delta=$((f1 - f0))
	if [[ "${mode}" == ip ]]; then
		expect="=0"
		((delta == 0)) || result=fail
	else
		expect=">0"
		((delta > 0)) || result=fail
	fi
	if ((big_tx == 0 || big_rx != big_tx || exact_tx == 0 || exact_rx != exact_tx)); then
		result=fail
	fi
	printf 'ITER=%s MODE=%s BIG_L3=%s BIG_TX=%s BIG_RX=%s EXACT_L3=%s EXACT_TX=%s EXACT_RX=%s FRAG_CREATES_DELTA=%s EXPECTED_DELTA=%s RESULT=%s\n' \
		"${CUR_ITER}" "${mode}" "${big}" "${big_tx}" "${big_rx}" "${exact}" "${exact_tx}" "${exact_rx}" \
		"${delta}" "${expect}" "${result}" >>"${WORK_DIR}/parity.txt"
	[[ "${result}" == pass ]] ||
		die "MTU parity check failed in mode ${mode}: ${big}-byte DF ping ${big_rx}/${big_tx} replies, ${exact}-byte DF ping ${exact_rx}/${exact_tx} replies, IpFragCreates increase ${delta} (expected ${expect}); ping output: $(tail -n 2 <<<"${out_big}" | tr '\n' ' ')/ $(tail -n 2 <<<"${out_exact}" | tr '\n' ' ')"
}

# iperf_json WHERE ARGS... runs "iperf3 -J -t IPERF_DURATION ARGS" in the
# cross-node client pod (WHERE=pod), the same-node client pod (WHERE=local), or
# via the NodePort DNAT target in the cross-node client pod (WHERE=ext) and
# prints the JSON report.
iperf_json() {
	local where="$1" pod out
	shift
	case "${where}" in
	local) pod="${LOCAL_CLIENT_POD}" ;;
	*) pod="${CLIENT_POD}" ;;
	esac
	if ! out="$(k exec "${pod}" -- iperf3 -J -t "${IPERF_DURATION}" "$@" 2>"${WORK_DIR}/iperf3.stderr")"; then
		die "iperf3 $* failed: $(jq -r '.error // empty' <<<"${out}" 2>/dev/null || true) $(head -c 300 "${WORK_DIR}/iperf3.stderr")"
	fi
	printf '%s\n' "${out}"
}

# ping_rtt ARGS... sends 500 ICMP echo requests 2 ms apart from the client pod
# to the server pod and prints ping's output (losses are reported, not fatal).
ping_rtt() {
	local out
	out="$(k exec "${CLIENT_POD}" -- ping -i 0.002 -c 500 "$@" "${SERVER_IP}" 2>&1)" || true
	printf '%s\n' "${out}"
}

# run_workloads MODE ITER POS runs the 16 workloads and appends one line of
# KEY=VALUE results to WORK_DIR/bench_MODE.txt.
run_workloads() {
	local mode="$1" iter="$2" pos="$3" line json out s0 s1 size

	line="ITER=${iter} POS=${pos} MODE=${mode}"
	json="$(iperf_json local -c "${SERVER_IP}" -P 4)"
	line+=" $(py tcp TCP_SAME_NODE_P4 <<<"${json}")"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 1)"
	line+=" $(py tcp TCP_P1 <<<"${json}")"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4)"
	line+=" $(py tcp TCP_P4 <<<"${json}")"
	s0="$(hoststat)"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 8)"
	s1="$(hoststat)"
	line+=" $(py tcp TCP_P8 --eff "${s0}" "${s1}" <<<"${json}")"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4 --bidir)"
	line+=" $(py bidir TCP_BIDIR_P4 <<<"${json}")"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4 -l 128 -N)"
	line+=" $(py tcp TCP_128B_P4 <<<"${json}")"
	json="$(iperf_json pod -c "${SVC_IP}" -P 4)"
	line+=" $(py tcp SVC_CLUSTERIP_P4 <<<"${json}")"
	json="$(iperf_json ext -c "${NODEPORT_DUMMY_IP}" -p "${NODEPORT_PORT}" -P 4)"
	line+=" $(py tcp SVC_NODEPORT_P4 <<<"${json}")"
	s0="$(hoststat)"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4 -b 2.5G)"
	s1="$(hoststat)"
	line+=" $(py tcp ISO_TCP_10G "${s0}" "${s1}" <<<"${json}")"
	s0="$(hoststat)"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4 -u -b 6.4M -l 64)"
	s1="$(hoststat)"
	line+=" $(py udp ISO_UDP_50KPPS "${s0}" "${s1}" <<<"${json}")"
	s0="$(hoststat)"
	json="$(iperf_json pod -c "${SERVER_IP}" -P 4 -u -b 0 -l 64)"
	s1="$(hoststat)"
	line+=" $(py udp UDP_64B --eff "${s0}" "${s1}" <<<"${json}")"
	for size in 512 1380 4000; do
		json="$(iperf_json pod -c "${SERVER_IP}" -P 4 -u -b 0 -l "${size}")"
		line+=" $(py udp "UDP_${size}B" <<<"${json}")"
	done
	out="$(ping_rtt -s 56)"
	line+=" $(py rtt RTT_64B <<<"${out}")"
	out="$(ping_rtt -s "${ICMP_BIG_PAYLOAD}")"
	line+=" $(py rtt RTT_1428B <<<"${out}")"

	echo "${line}" >>"${WORK_DIR}/bench_${mode}.txt"
	log "  $(grep -o -E '(TCP_SAME_NODE_P4_GBPS|TCP_P8_GBPS|UDP_64B_RX_KPPS|RTT_64B_MS)=[^ ]+' <<<"${line}" | tr '\n' ' ')"
}

run_benchmark() {
	local iter mode pos order_text
	local -a order
	for ((iter = 1; iter <= ITERATIONS; iter++)); do
		CUR_ITER="${iter}"
		order_text="$(rotated_modes "${iter}")"
		read -r -a order <<<"${order_text}"
		printf 'ITER=%s ORDER=%s\n' "${iter}" "${order_text// /,}" >>"${WORK_DIR}/order.txt"
		pos=0
		for mode in "${order[@]}"; do
			pos=$((pos + 1))
			enter_mode "${mode}"
			log "Iteration ${iter}/${ITERATIONS}, mode ${mode}"
			warmup
			parity_check "${mode}"
			run_workloads "${mode}" "${iter}" "${pos}"
		done
	done
}

# collect_env records the environment of the run in WORK_DIR/env.tsv.
collect_env() {
	local cpu node_kernel node_nproc end_load bpf_stats node_info config
	# shellcheck disable=SC2016 # Expanded by awk in the agent container.
	cpu="$(node_exec "${CP_NODE}" awk -F': ' '/^model name/ { print $2; exit }' /proc/cpuinfo)"
	node_kernel="$(node_exec "${CP_NODE}" uname -r)"
	node_nproc="$(node_exec "${CP_NODE}" nproc)"
	end_load="$(node_exec "${CP_NODE}" cut -d' ' -f1-3 /proc/loadavg)"
	bpf_stats="$(node_exec "${CP_NODE}" cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo unknown)"
	node_info="$(k get node "${CP_NODE}" -o jsonpath='{.status.nodeInfo.kubeletVersion}, {.status.nodeInfo.osImage}, {.status.nodeInfo.containerRuntimeVersion}')"
	config="$(ks get configmap cilium-config -o json | jq -r '.data | [
		"routing-mode=\(.["routing-mode"] // "-")", "tunnel-protocol=\(.["tunnel-protocol"] // "-")",
		"tunnel-port=\(.["tunnel-port"] // "-")", "kube-proxy-replacement=\(.["kube-proxy-replacement"] // "-")",
		"enable-ipv4=\(.["enable-ipv4"] // "-")", "enable-ipv6=\(.["enable-ipv6"] // "-")"] | join(", ")')"
	{
		printf 'Start / end (UTC)\t%s / %s\n' "${START_DATE}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		printf 'Host kernel (uname -r)\t%s\n' "${node_kernel}"
		printf 'Host CPU\t%s, %s CPUs (nproc)\n' "${cpu:-unknown}" "${node_nproc}"
		printf 'Host load average at start / end\t%s / %s\n' "${START_LOAD}" "${end_load}"
		printf 'Host kernel.bpf_stats_enabled (not changed)\t%s\n' "${bpf_stats}"
		if ((USE_KIND)); then
			printf 'Kind\t%s\n' "$(kind version 2>/dev/null || echo unknown)"
			printf 'Kind node image\t%s\n' "$(docker inspect -f '{{.Config.Image}}' "${CP_NODE}" 2>/dev/null || echo unknown)"
		fi
		printf 'Kubernetes, node OS, runtime\t%s\n' "${node_info}"
		printf 'Benchmark nodes\tclient=%s, server=%s, nodeport=%s\n' "${CP_NODE}" "${WORKER_NODE}" "${WORKER2_NODE}"
		printf 'Benchmark image\t%s (%s)\n' "${BENCH_IMAGE}" "$(k get pod "${CLIENT_POD}" -o jsonpath='{.status.containerStatuses[0].imageID}')"
		printf 'iperf3\t%s\n' "$(k exec "${CLIENT_POD}" -- iperf3 --version | head -n1)"
		printf 'ping\t%s\n' "$(k exec "${CLIENT_POD}" -- ping -V 2>&1 | head -n1)"
		printf 'Cilium commit\t%s (%s uncommitted or untracked files)\n' "${GIT_COMMIT}" "${GIT_DIRTY}"
		printf 'cilium-agent sha256\t%s\n' "${AGENT_SHA}"
		printf 'Agent BPF sources\t%s files, manifest sha256 %s\n' "${BPF_FILES}" "${BPF_SHA}"
		printf 'Cilium image (DaemonSet)\t%s\n' "$(ks get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}')"
		printf 'Cilium config\t%s\n' "${config}"
		printf 'Original enable-bpf-geneve / geneve-inner-protocol (restored)\t%s / %s\n' "${ORIG_ENABLE_BPF_GENEVE}" "${ORIG_INNER_PROTO}"
		printf 'Underlay\tIPv4, %s MTU %s\n' "${UNDERLAY_DEV}" "${UNDERLAY_MTU}"
		printf 'Iterations / iperf3 run length\t%s / %s s\n' "${ITERATIONS}" "${IPERF_DURATION}"
		printf 'Modes requested\t%s\n' "${MODES}"
	} >"${WORK_DIR}/env.tsv"
}

# restore_config puts back the enable-bpf-geneve and geneve-inner-protocol
# values found at the start.
restore_config() {
	local since
	if [[ "$(config_value enable-bpf-geneve)" == "${ORIG_ENABLE_BPF_GENEVE}" &&
		"$(config_value geneve-inner-protocol)" == "${ORIG_INNER_PROTO}" ]]; then
		RESTORED=1
		return 0
	fi
	log "Restoring cilium-config (enable-bpf-geneve=${ORIG_ENABLE_BPF_GENEVE}, geneve-inner-protocol=${ORIG_INNER_PROTO})..."
	since="$(node_epoch)"
	patch_cilium_config "${ORIG_ENABLE_BPF_GENEVE}" "${ORIG_INNER_PROTO}"
	RESTORED=1
	ks rollout restart ds/cilium >/dev/null
	ks rollout status ds/cilium --timeout=300s >/dev/null ||
		die "the cilium DaemonSet did not become ready after restoring cilium-config"
	wait_datapath_ready "${since}"
	CURRENT_MODE="$(current_mode)"
	recreate_pods
	PODS_MODE="${CURRENT_MODE}"
}

generate_report() {
	python3 -c "${PY_REPORT}" "${WORK_DIR}" "${OUTPUT_FILE}" "${ITERATIONS}" "${IPERF_DURATION}" \
		"${ICMP_BIG_PAYLOAD}" "${SHARED_KERNEL}" "${CP_NODE}" "${WORKER_NODE}" "${WORKER2_NODE}"
	log "Saved the report to ${OUTPUT_FILE}"
}

on_exit() {
	local rc=$?
	if ((rc == 0)); then
		rm -rf "${WORK_DIR}"
		return
	fi
	if ((CONFIG_TOUCHED)) && ! ((RESTORED)); then
		log "Restoring cilium-config after the failure (best effort)..."
		patch_cilium_config "${ORIG_ENABLE_BPF_GENEVE}" "${ORIG_INNER_PROTO}" || true
		ks rollout restart ds/cilium >/dev/null 2>&1 || true
		ks rollout status ds/cilium --timeout=300s >/dev/null 2>&1 ||
			log "WARNING: the cilium DaemonSet is not ready after restoring cilium-config"
		log "The benchmark pods were left as they are; their route MTU may not match the restored mode."
	fi
	log "Intermediate files are kept in ${WORK_DIR}"
}

main() {
	local out

	check_inputs
	WORK_DIR="$(mktemp -d /tmp/geneve-bench.XXXXXX)"
	trap on_exit EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	START_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

	ensure_cluster
	discover_nodes
	START_LOAD="$(node_exec "${CP_NODE}" cut -d' ' -f1-3 /proc/loadavg)"
	check_cluster_config
	ORIG_ENABLE_BPF_GENEVE="$(config_value enable-bpf-geneve)"
	ORIG_INNER_PROTO="$(config_value geneve-inner-protocol)"
	CURRENT_MODE="$(current_mode)"

	stage_and_install_sources
	precheck_ip_mode

	out="$(underlay_mtu "${CP_NODE}")"
	read -r UNDERLAY_DEV UNDERLAY_MTU <<<"${out}"
	out="$(underlay_mtu "${WORKER_NODE}")"
	[[ "${out##* }" == "${UNDERLAY_MTU}" ]] ||
		die "the underlay MTU of ${WORKER_NODE} (${out##* }) differs from ${CP_NODE} (${UNDERLAY_MTU})"
	if ((UNDERLAY_MTU < 1478)); then
		ICMP_BIG_PAYLOAD=$((UNDERLAY_MTU - 100))
	else
		ICMP_BIG_PAYLOAD=1400
	fi
	prepare_endpoints

	run_benchmark
	collect_env
	restore_config
	generate_report
}

# The script can be sourced to reuse its functions without running it.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi
