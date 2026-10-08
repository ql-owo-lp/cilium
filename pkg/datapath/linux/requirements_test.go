// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestCheckBPFGeneveRequirements(t *testing.T) {
	supported := func() error { return nil }
	unsupported := func() error { return probes.ErrNotSupported }
	probeFailed := func() error { return assert.AnError }
	mustNotProbe := func() error {
		t.Fatal("probe must not run when the native BPF Geneve datapath is disabled")
		return nil
	}

	tests := []struct {
		name       string
		cfg        tunnel.Config
		enableIPv4 bool
		enableIPv6 bool
		encapL2Eth func() error
		decapL3    func() error
		decapL4UDP func() error
		wantErr    string
	}{
		{
			name:       "kernel geneve does not probe",
			cfg:        tunnel.NewTestConfig(tunnel.Geneve),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: mustNotProbe, decapL3: mustNotProbe, decapL4UDP: mustNotProbe,
		},
		{
			name:       "vxlan does not probe",
			cfg:        tunnel.NewTestConfig(tunnel.VXLAN),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: mustNotProbe, decapL3: mustNotProbe, decapL4UDP: mustNotProbe,
		},
		{
			name:       "bpf geneve, kernel supports both flags",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, no ENCAP_L2_ETH",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: unsupported, decapL3: supported, decapL4UDP: unsupported,
			wantErr: "Linux >= 5.13",
		},
		{
			name:       "bpf geneve, ip inner protocol, no ENCAP_L2_ETH",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoIP),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: unsupported, decapL3: supported, decapL4UDP: supported,
			wantErr: "Linux >= 5.13",
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv4 underlay, ipv4 pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv4 underlay, dual-stack pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
			wantErr: "Linux >= 6.3",
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv4 underlay, ipv6 pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4: false, enableIPv6: true,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
			wantErr: "Linux >= 6.3",
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv6 underlay, ipv6 pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoETH),
			enableIPv4: false, enableIPv6: true,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv6 underlay, ipv4 pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
			wantErr: "Linux >= 6.3",
		},
		{
			name:       "bpf geneve, no DECAP_L3, ipv6 underlay, dual-stack pods",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoETH),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: supported, decapL3: unsupported, decapL4UDP: unsupported,
			wantErr: "Linux >= 6.3",
		},
		{
			name:       "bpf geneve, eth inner protocol does not need DECAP_L4_UDP",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoETH),
			enableIPv4: false, enableIPv6: true,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, ip inner protocol, kernel supports all flags",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoIP),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: supported,
		},
		{
			name:       "bpf geneve, ip inner protocol, ipv4 underlay, no DECAP_L4_UDP",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoIP),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, ip inner protocol, ipv6 underlay, no DECAP_L4_UDP",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoIP),
			enableIPv4: true, enableIPv6: true,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: unsupported,
		},
		{
			name:       "bpf geneve, ip inner protocol, DECAP_L4_UDP probe error",
			cfg:        tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoIP),
			enableIPv4: true, enableIPv6: false,
			encapL2Eth: supported, decapL3: supported, decapL4UDP: probeFailed,
			wantErr: "BPF_F_ADJ_ROOM_DECAP_L4_UDP",
		},
	}

	logger := hivetest.Logger(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkBPFGeneveRequirements(logger, tt.cfg, tt.enableIPv4, tt.enableIPv6,
				tt.encapL2Eth, tt.decapL3, tt.decapL4UDP)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestPrivilegedCheckRequirementsBPFGeneve(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "5.13", "BPF_F_ADJ_ROOM_ENCAP_L2_ETH support in bpf_skb_adjust_room")

	prevIPv4, prevIPv6, prevDryMode := option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.DryMode
	t.Cleanup(func() {
		option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.DryMode = prevIPv4, prevIPv6, prevDryMode
	})
	// IPv4 pods over an IPv4 underlay: BPF_F_ADJ_ROOM_DECAP_L3_* is not
	// needed.
	option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.DryMode = true, false, false
	logger := hivetest.Logger(t)

	// B8, L1-06, L5-03: the agent probes the running kernel for the
	// bpf_skb_adjust_room() flags of the native datapath at startup.
	t.Run("inner protocol eth", func(t *testing.T) {
		require.NoError(t, CheckRequirements(logger,
			tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH)))
	})

	t.Run("inner protocol ip", func(t *testing.T) {
		require.NoError(t, CheckRequirements(logger,
			tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoIP)))
	})
}
