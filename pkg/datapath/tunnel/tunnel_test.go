// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"errors"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
)

var (
	defaultTestConfig = userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange}
	daemonCfgIPv46    = &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true}
	daemonCfgIPv4     = &option.DaemonConfig{EnableIPv4: true, EnableIPv6: false}
)

func TestConfig(t *testing.T) {
	enabler := func(enable bool, opts ...enablerOpt) any {
		return func() EnablerOut { return NewEnabler(enable, opts...) }
	}

	tests := []struct {
		name     string
		ucfg     userCfg
		enablers []any
		dcfg     *option.DaemonConfig

		shallFail      bool
		proto          EncapProtocol
		underlay       UnderlayProtocol
		port           uint16
		deviceName     string
		shouldAdaptMTU bool
		bpfGeneve      bool
		l3Inner        bool
	}{
		{
			name:      "invalid protocol",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: "invalid", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			shallFail: true,
		},
		{
			name:      "invalid underlay",
			ucfg:      userCfg{UnderlayProtocol: "invalid", TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			shallFail: true,
		},
		{
			name:     "tunnel not enabled",
			ucfg:     defaultTestConfig,
			dcfg:     daemonCfgIPv46,
			underlay: IPv4,
			proto:    Disabled,
		},
		{
			name:     "tunnel not enabled, with enablers",
			ucfg:     defaultTestConfig,
			dcfg:     daemonCfgIPv46,
			enablers: []any{enabler(false), enabler(false)},
			underlay: IPv4,
			proto:    Disabled,
		},
		{
			name:      "tunnel enabled, disabled underlay",
			ucfg:      userCfg{UnderlayProtocol: string(IPv6), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv4,
			enablers:  []any{enabler(true), enabler(false)},
			shallFail: true,
		},
		{
			name:           "tunnel enabled, vxlan",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true), enabler(false)},
			underlay:       IPv4,
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, vxlan, custom port",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), TunnelPort: 1234, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(false), enabler(true)},
			underlay:       IPv4,
			proto:          VXLAN,
			port:           1234,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve",
			ucfg:           defaultTestConfig,
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true), enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, vxlan, ipv6 underlay",
			ucfg:           userCfg{UnderlayProtocol: string(IPv6), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true), enabler(true)},
			underlay:       IPv6,
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve, custom port",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), TunnelPort: 1234, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true), enabler(false)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           1234,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name: "tunnel enabled, validation function",
			ucfg: defaultTestConfig,
			dcfg: daemonCfgIPv46,
			enablers: []any{enabler(true, WithValidator(func(proto EncapProtocol) error {
				if proto == Geneve {
					return errors.New("invalid protocol")
				}
				return nil
			}))},
			shallFail: true,
		},
		{
			name:           "tunnel enabled, don't need MTU adaptation, one",
			ucfg:           defaultTestConfig,
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true, WithoutMTUAdaptation()), enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, don't need MTU adaptation, all",
			ucfg:           defaultTestConfig,
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true, WithoutMTUAdaptation()), enabler(false)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: false,
		},
		{
			name:           "tunnel enabled, vxlan, auto underlay",
			ucfg:           userCfg{UnderlayProtocol: string(Auto), TunnelProtocol: string(VXLAN), TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true), enabler(false)},
			underlay:       IPv4,
			proto:          VXLAN,
			port:           defaults.TunnelPortVXLAN,
			deviceName:     defaults.VxlanDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, geneve, defaults",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: defaultConfig.GeneveInnerProtocol, EnableBPFGeneve: defaultConfig.EnableBPFGeneve, TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
			bpfGeneve:      false,
			l3Inner:        false,
		},
		{
			name:           "tunnel enabled, geneve, eth inner protocol",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "eth", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
		},
		{
			name:           "tunnel enabled, bpf geneve, eth inner protocol",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "eth", EnableBPFGeneve: true, TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
			bpfGeneve:      true,
		},
		{
			name:           "tunnel enabled, bpf geneve, ip inner protocol",
			ucfg:           userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "ip", EnableBPFGeneve: true, TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:           daemonCfgIPv46,
			enablers:       []any{enabler(true)},
			underlay:       IPv4,
			proto:          Geneve,
			port:           defaults.TunnelPortGeneve,
			deviceName:     defaults.GeneveDevice,
			shouldAdaptMTU: true,
			bpfGeneve:      true,
			l3Inner:        true,
		},
		{
			name:     "tunnel not enabled, bpf geneve",
			ucfg:     userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "ip", EnableBPFGeneve: true, TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:     daemonCfgIPv46,
			enablers: []any{enabler(false)},
			underlay: IPv4,
			proto:    Disabled,
		},
		{
			name:      "tunnel enabled, geneve, invalid inner protocol",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "invalid", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			enablers:  []any{enabler(true)},
			shallFail: true,
		},
		{
			name:      "tunnel enabled, geneve, ip inner protocol without bpf geneve",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(Geneve), GeneveInnerProtocol: "ip", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			enablers:  []any{enabler(true)},
			shallFail: true,
		},
		{
			name:      "tunnel enabled, vxlan, bpf geneve",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), EnableBPFGeneve: true, TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			enablers:  []any{enabler(true)},
			shallFail: true,
		},
		{
			name:      "tunnel enabled, vxlan, ip inner protocol",
			ucfg:      userCfg{UnderlayProtocol: string(IPv4), TunnelProtocol: string(VXLAN), GeneveInnerProtocol: "ip", TunnelPort: 0, TunnelSourcePortRange: defaults.TunnelSourcePortRange},
			dcfg:      daemonCfgIPv46,
			enablers:  []any{enabler(true)},
			shallFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out Config

			err := hive.New(
				cell.Config(tt.ucfg),
				cell.Provide(newConfig),
				cell.Provide(tt.enablers...),
				cell.Provide(func() *option.DaemonConfig { return tt.dcfg }),
				cell.Invoke(func(tc Config) { out = tc }),
			).Populate(hivetest.Logger(t))

			if tt.shallFail {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.underlay, out.UnderlayProtocol())
			assert.Equal(t, tt.proto, out.EncapProtocol())
			assert.Equal(t, tt.port, out.Port())
			assert.Equal(t, tt.deviceName, out.DeviceName())
			assert.Equal(t, tt.shouldAdaptMTU, out.ShouldAdaptMTU())
			assert.Equal(t, tt.bpfGeneve, out.EnableBPFGeneve())
			assert.Equal(t, tt.l3Inner, out.IsL3InnerProtocol())
		})
	}
}

func TestDefaultConfigBPFGeneveOff(t *testing.T) {
	// The native BPF Geneve datapath is opt-in (beta).
	assert.False(t, defaultConfig.EnableBPFGeneve)
	assert.Equal(t, string(GeneveInnerProtoETH), defaultConfig.GeneveInnerProtocol)
}

func TestBPFGeneveDefines(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		bpfGeneve bool
		l3Inner   bool
		innerDpID string
	}{
		{name: "disabled", cfg: NewTestConfig(Disabled)},
		{name: "vxlan", cfg: NewTestConfig(VXLAN)},
		{name: "geneve, kernel datapath", cfg: NewTestConfig(Geneve)},
		{name: "bpf geneve, eth", cfg: NewTestBPFGeneveConfig(IPv4, GeneveInnerProtoETH), bpfGeneve: true, innerDpID: "1"},
		{name: "bpf geneve, ip", cfg: NewTestBPFGeneveConfig(IPv4, GeneveInnerProtoIP), bpfGeneve: true, l3Inner: true, innerDpID: "2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.bpfGeneve, tt.cfg.EnableBPFGeneve())
			assert.Equal(t, tt.l3Inner, tt.cfg.IsL3InnerProtocol())

			nodeOut, _ := tt.cfg.datapathConfigProvider()
			enable, hasEnable := nodeOut.NodeDefines["ENABLE_BPF_GENEVE"]
			inner, hasInner := nodeOut.NodeDefines["GENEVE_INNER_PROTOCOL"]
			assert.Equal(t, tt.bpfGeneve, hasEnable)
			assert.Equal(t, tt.bpfGeneve, hasInner)
			if tt.bpfGeneve {
				assert.Equal(t, "1", enable)
				assert.Equal(t, tt.innerDpID, inner)
			}
		})
	}
}
