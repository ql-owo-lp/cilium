.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_geneve_datapath:

**************************
Native BPF Geneve Datapath
**************************

.. include:: /beta.rst

Overview
========

In tunnel routing mode with Geneve encapsulation, Cilium normally leaves the
outer headers to the kernel: packets to other nodes are redirected to the
``cilium_geneve`` device, which encapsulates them, and Geneve packets from other
nodes are decapsulated by that device before Cilium processes them. The native
BPF Geneve datapath adds and removes the outer headers in eBPF instead, so that
these packets no longer pass through ``cilium_geneve`` and the host network
stack. ``cilium_geneve`` stays configured and handles the packets that the
native datapath leaves to the kernel.

Egress
------

Where the kernel datapath would redirect a packet to ``cilium_geneve``, the
native datapath looks up the route to the remote node with ``bpf_fib_lookup()``,
adds the outer headers and redirects the packet to the device of that route,
where the bandwidth manager applies to it as in native routing mode. The lookup
is done for every packet with the outer UDP flow, as the kernel does, so that
ECMP routes select the same next hop on both paths. The outer headers
are the same as on the kernel path, except where noted:

* Source address: the preferred source address of the route or, on kernels
  without ``BPF_FIB_LOOKUP_SRC`` support, the address of the device that Cilium
  uses for direct routing.
* TTL (hop limit) 64, DSCP 0, and the ECN field of the inner packet with CE sent
  as ECT(0) (RFC 6040).
* IPv4 "Don't Fragment" flag: clear in ``eth`` mode, but set in ``ip`` mode (see
  :ref:`bpf_geneve_mtu`).
* UDP source port: computed from the flow hash of the packet with the formula of
  the kernel's ``udp_flow_src_port()`` within ``tunnel-source-port-range``, so a
  flow normally keeps its source port, and thus its path through the network,
  when a node switches between the two paths. The destination port is ``tunnel-port``.
* UDP checksum: zero, also over IPv6, where the kernel path computes one.
* Geneve header: the VNI carries the source security identity, and Cilium's DSR
  option is added where needed. In ``ip`` mode, the inner Ethernet header is
  omitted and the Geneve protocol type is the EtherType of the inner packet.

On egress, the native datapath never drops a packet that the kernel path would
send. A packet that cannot be encapsulated while it is still unmodified is
redirected to ``cilium_geneve`` unchanged, with the tunnel metadata of the
kernel path, and is handled exactly as without the native datapath. This
happens when:

* the packet would exceed the MTU of the route to the remote node, including
  learned path MTUs. ``cilium_geneve`` then handles it as before, for example
  by fragmenting the outer IPv4 packet;
* the route lookup fails for a reason other than a missing neighbor entry;
* no outer source address is available;
* ``bpf_skb_adjust_room()`` fails without modifying the packet.

Ingress
-------

``cil_from_netdev`` on the native devices recognizes Geneve packets addressed
to the node: UDP packets to the tunnel port for the direct routing address or
another address of the node. It applies the host firewall's ingress policy to
the outer packet, as on the kernel path, validates the Geneve header and
options, removes the outer headers, merges the outer ECN field into the inner
packet (RFC 6040) and continues with the eBPF processing of packets received on
``cilium_geneve``.

The following packets continue on the kernel path instead and are decapsulated
by ``cilium_geneve`` as before:

* In ``eth`` mode, packets that GRO merged on reception, which includes most
  received bulk TCP traffic.
* Fragments, and packets with IPv4 options or IPv6 extension headers.
* Geneve OAM packets, and packets whose inner protocol is not an IP family
  enabled in Cilium, such as ARP.
* Frames sent to the MAC address of another host (received in promiscuous
  mode), which the kernel drops.
* Packets received on native devices without an Ethernet header, and Geneve
  packets that WireGuard decrypted on ``cilium_wg0``.

Requirements
============

* Tunnel routing mode with Geneve encapsulation (``routingMode: tunnel`` and
  ``tunnelProtocol: geneve``).
* Linux 5.13 or newer, and Linux 6.3 or newer in dual-stack clusters, where pod
  traffic of both IP families is carried over an underlay of one family.
* For ``ip`` mode: ``ip`` mode on all nodes, and a path MTU of at least the
  device MTU between them (see :ref:`bpf_geneve_rollout` and
  :ref:`bpf_geneve_mtu`). On kernels with ``bpf_skb_adjust_room()`` support for
  ``BPF_F_ADJ_ROOM_DECAP_L4_UDP`` (bpf-next commit ``ec20dee2f2c4``), the agent
  also clears the outer UDP tunnel GSO state on GRO aggregates.

The agent checks the kernel requirements at startup and refuses to start if
they are not met. Enable the native datapath only once all nodes run a Cilium
version that supports it.

Enabling
========

The native datapath is disabled by default. It is controlled by two Helm
values, whose agent options are given in parentheses:

* ``bpf.geneve.enabled`` (``enable-bpf-geneve``): enables the native datapath.
  Defaults to ``false``.
* ``bpf.geneve.innerProtocol`` (``geneve-inner-protocol``): ``eth`` (default)
  carries the inner Ethernet frame in the Geneve packets, like
  ``cilium_geneve``. ``ip`` carries the inner IPv4 or IPv6 packet without its
  Ethernet header, which saves 14 bytes per packet.

To enable the native datapath in ``eth`` mode on an existing installation that
uses Geneve tunneling, run:

.. cilium-helm-upgrade::
   :namespace: kube-system
   :extra-args: --reuse-values
   :set: bpf.geneve.enabled=true
   :post-commands: kubectl -n kube-system rollout restart ds/cilium

On a node where the native datapath is active, the ``cilium_calls_bpf_overlay``
and ``cilium_geneve_meta`` maps are pinned in ``/sys/fs/bpf/tc/globals``.

.. _bpf_geneve_rollout:

Compatibility and rollout
=========================

``eth`` mode is wire-compatible with the kernel datapath, so the native
datapath can be enabled and disabled node by node. To try it on a few nodes
first, set ``enable-bpf-geneve: "true"`` for them with a ``CiliumNodeConfig``
(see :ref:`per-node-configuration`).

``ip`` mode is not wire-compatible with the kernel datapath or with ``eth``
mode: nodes on the kernel datapath drop its packets, and nodes in ``eth`` mode
drop those that GRO merged. All nodes must therefore use ``ip`` mode, and
switching a cluster to or from ``ip`` mode interrupts traffic between nodes that
use different modes until all nodes have switched.

Over an IPv6 underlay, the outer UDP checksum is zero (RFC 6935, RFC 6936).
Cilium accepts such packets on both paths, but network devices on the path
that drop IPv6 UDP packets with a zero checksum break the native datapath, while
the kernel datapath keeps working.

.. _bpf_geneve_mtu:

MTU
===

Cilium lowers the MTU of pod traffic by the tunnel overhead. With a device MTU
of 1500 bytes, the pod MTU is:

========  =========================  =========================
Underlay  Kernel and ``eth`` mode    ``ip`` mode
========  =========================  =========================
IPv4      1450 (50 bytes overhead)   1464 (36 bytes overhead)
IPv6      1430 (70 bytes overhead)   1444 (56 bytes overhead)
========  =========================  =========================

In ``eth`` mode, a packet that does not fit the MTU of the route, for example
because a router reported a smaller path MTU, is sent through ``cilium_geneve``.

In ``ip`` mode, path MTU discovery does not work for the outer packets, as the
kernel ignores ICMP errors about Geneve packets that do not carry Ethernet
frames. Fragmentation on the path does not help either: the receiving node
hands reassembled packets to ``cilium_geneve``, which drops ``ip`` mode packets.
The outer IPv4 header therefore has the "Don't Fragment" flag set, and the path
MTU between all nodes must be at least the device MTU.

Interaction with the host network stack
=======================================

Netfilter does not see the outer packets of the native datapath in either
direction: iptables and nftables rules that match Geneve packets, for example on
UDP port 6081, and connection tracking of the outer UDP flow do not apply to
them. Cilium's host firewall still applies its policies to them. Packets that
are sent or received through ``cilium_geneve`` are seen by netfilter as before.

Geneve packets are decapsulated by ``cil_from_netdev`` on the native device
they arrive on and are not received again on ``cilium_geneve``. Decapsulated
packets that are passed to the host network stack instead of being redirected
in eBPF therefore enter it on the native device: traffic redirected to the L7
proxy, traffic delivered with legacy host routing, and Geneve DSR traffic
without eBPF host routing. With strict reverse path filtering on that device,
the kernel drops such packets from remote pods, because the route back to their
source goes through ``cilium_host``. Cilium therefore changes
``net.ipv4.conf.<device>.rp_filter`` from strict (``1``) to loose (``2``) on the
native devices, including devices added at runtime, and logs each change. The
values ``0`` and ``2`` are left as they are, and the setting is not restored
when the datapath is disabled. Cilium sets ``net.ipv4.conf.all.rp_filter`` to
``0``, so the value of each device applies. IPv6 has no reverse path filter.

For the same packets, iptables rules that match the input interface (``-i``)
and ``ip rule`` selectors on the input interface (``iif``) see the native device
instead of ``cilium_geneve``.

Limitations
===========

* ``ip`` mode requires the same mode on all nodes and a path MTU of at least
  the device MTU; clearing ``SKB_GSO_UDP_TUNNEL`` on GRO aggregates that are
  later re-segmented uses ``BPF_F_ADJ_ROOM_DECAP_L4_UDP`` when supported by the
  kernel.
* There is no XDP acceleration for Geneve: XDP passes Geneve packets on to TC.
* Multicast packets to remote nodes are always sent through ``cilium_geneve``.
* WireGuard and IPsec encryption of tunnel traffic is expected to work, as it
  is keyed on a packet mark that the native datapath sets like the kernel path,
  but it is not yet covered by end-to-end tests.
* The route lookup ignores policy routing rules that match the packet mark,
  which the kernel path takes into account.

Troubleshooting
===============

The native datapath adds three drop reasons. Hubble reports their names, while
``cilium-dbg monitor --type drop`` and the ``reason`` label of the
``cilium_drop_count_total`` metric show their descriptions:

``DROP_GENEVE_HDR_INVALID`` (208, "Invalid Geneve header")
    A received Geneve packet has a malformed header, for example a wrong UDP
    length.
``DROP_GENEVE_OPT_INVALID`` (209, "Invalid or unsupported critical Geneve option")
    The options of a received Geneve packet are malformed or include a critical
    option other than Cilium's DSR option. RFC 8926 requires dropping such
    packets; the kernel path delivers them.
``DROP_GENEVE_ENCAP_FAILED`` (210, "Geneve encapsulation failed")
    Encapsulation failed after the packet had been modified, so it could not be
    sent through ``cilium_geneve`` instead. This is not expected to happen.

Hubble and ``cilium-dbg monitor`` report natively processed packets with the
same ``to-overlay`` and ``from-overlay`` trace events, and the same
``cilium_geneve`` interface, as packets on the kernel path. As the native
datapath bypasses ``cilium_geneve``, the statistics of that device show how
much traffic still takes the kernel path. ``cilium-bugtool`` includes dumps of
the ``cilium_calls_bpf_overlay`` and ``cilium_geneve_meta`` maps. As ``eth``
mode is wire-compatible, disabling the native datapath on individual nodes
helps to tell whether a problem is related to it.

Performance
===========

``contrib/scripts/benchmark-geneve-bpf.sh`` compares ``Kernel Geneve``
(baseline), ``BPF Geneve (eth)`` and ``BPF Geneve (ip)`` with same-node and
cross-node TCP, UDP, Service (``ClusterIP`` and ``NodePort``) and ICMP
workloads on any Kubernetes cluster (a managed multi-node cluster or a local
Kind cluster). By default, it runs all three modes (``MODES=kernel,eth,ip``),
switching modes by patching ``enable-bpf-geneve`` and ``geneve-inner-protocol``
in the ``cilium-config`` ConfigMap against the same Cilium image and restoring
the original configuration at the end; its header describes the options and
side effects.

.. code-block:: shell-session

    $ contrib/scripts/benchmark-geneve-bpf.sh
