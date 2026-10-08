// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func testPeerPod(ip4, ip6 string) *check.Pod {
	var podIPs []corev1.PodIP
	if ip4 != "" {
		podIPs = append(podIPs, corev1.PodIP{IP: ip4})
	}
	if ip6 != "" {
		podIPs = append(podIPs, corev1.PodIP{IP: ip6})
	}
	return &check.Pod{
		Pod: &corev1.Pod{
			Status: corev1.PodStatus{PodIPs: podIPs},
		},
	}
}

func newEncryptionTestScope(t *testing.T, fs features.Set) (*check.ConnectivityTest, *check.Test) {
	t.Helper()
	ct, err := check.NewConnectivityTest(nil, check.Parameters{
		FlowValidation: check.FlowValidationModeDisabled,
	}, nil, nil, nil)
	require.NoError(t, err)
	ct.Features = fs
	return ct, ct.AddTest(check.NewTest("encryption-test", false, false))
}

func TestIsBPFGeneveEncap(t *testing.T) {
	clientPod := testPeerPod("10.244.0.10", "fd00:10:244::10")
	serverPod := testPeerPod("10.244.1.20", "fd00:10:244:1::20")
	clientHost := testPeerPod("172.18.0.2", "fc00:c111::2")
	serverHost := testPeerPod("172.18.0.3", "fc00:c111::3")

	baseGeneveFeatures := func(bpfGeneve, hostFW bool) features.Set {
		return features.Set{
			features.Tunnel:       {Enabled: true, Mode: "geneve"},
			features.TunnelPort:   {Enabled: false, Mode: "6081"},
			features.BPFGeneve:    {Enabled: bpfGeneve, Mode: "eth"},
			features.HostFirewall: {Enabled: hostFW},
		}
	}

	t.Run("disabled when BPFGeneve is off", func(t *testing.T) {
		_, tst := newEncryptionTestScope(t, baseGeneveFeatures(false, true))
		assert.False(t, isBPFGeneveEncap(tst, clientPod, clientHost, serverPod, serverHost, features.IPFamilyV4))
		assert.False(t, isBPFGeneveEncap(tst, clientHost, clientHost, serverPod, serverHost, features.IPFamilyV4))
		assert.False(t, isBPFGeneveEncap(tst, clientPod, clientHost, serverHost, serverHost, features.IPFamilyV4))
	})

	t.Run("disabled when tunnel mode is vxlan", func(t *testing.T) {
		fs := baseGeneveFeatures(true, true)
		fs[features.Tunnel] = features.Status{Enabled: true, Mode: "vxlan"}
		_, tst := newEncryptionTestScope(t, fs)
		assert.False(t, isBPFGeneveEncap(tst, clientPod, clientHost, serverPod, serverHost, features.IPFamilyV4))
	})

	t.Run("enabled for pod-to-pod and host-to-pod traffic", func(t *testing.T) {
		_, tst := newEncryptionTestScope(t, baseGeneveFeatures(true, false))
		assert.True(t, isBPFGeneveEncap(tst, clientPod, clientHost, serverPod, serverHost, features.IPFamilyV4))
		assert.True(t, isBPFGeneveEncap(tst, clientHost, clientHost, serverPod, serverHost, features.IPFamilyV4))
		assert.True(t, isBPFGeneveEncap(tst, clientHost, clientHost, serverPod, serverHost, features.IPFamilyV6))
	})

	t.Run("pod-to-remote-host depends on HostFirewall", func(t *testing.T) {
		_, tstNoHF := newEncryptionTestScope(t, baseGeneveFeatures(true, false))
		assert.False(t, isBPFGeneveEncap(tstNoHF, clientPod, clientHost, serverHost, serverHost, features.IPFamilyV4))

		_, tstHF := newEncryptionTestScope(t, baseGeneveFeatures(true, true))
		assert.True(t, isBPFGeneveEncap(tstHF, clientPod, clientHost, serverHost, serverHost, features.IPFamilyV4))
		assert.True(t, isBPFGeneveEncap(tstHF, clientPod, clientHost, serverHost, serverHost, features.IPFamilyV6))
	})

	t.Run("disabled for host-to-remote-host even with HostFirewall", func(t *testing.T) {
		_, tst := newEncryptionTestScope(t, baseGeneveFeatures(true, true))
		assert.False(t, isBPFGeneveEncap(tst, clientHost, clientHost, serverHost, serverHost, features.IPFamilyV4))
		assert.False(t, isBPFGeneveEncap(tst, clientHost, clientHost, serverHost, serverHost, features.IPFamilyV6))
	})
}

func TestPodToPodEncryptionV2TunnelFiltersInnerProtocol(t *testing.T) {
	clientPod := testPeerPod("10.244.0.10", "fd00:10:244::10")
	serverPod := testPeerPod("10.244.1.20", "fd00:10:244:1::20")

	newScenario := func(t *testing.T, innerMode string) *podToPodEncryptionV2 {
		ct, _ := newEncryptionTestScope(t, features.Set{
			features.Tunnel:     {Enabled: true, Mode: "geneve"},
			features.TunnelPort: {Enabled: false, Mode: "6081"},
			features.BPFGeneve:  {Enabled: true, Mode: innerMode},
		})
		return &podToPodEncryptionV2{
			ct:                ct,
			client:            clientPod,
			server:            serverPod,
			usesTunnelRouting: true,
		}
	}

	t.Run("eth inner protocol uses L2 offset (+14)", func(t *testing.T) {
		s := newScenario(t, "eth")
		assert.Equal(t, 14, s.tunnelInnerL2Len())

		c4, s4, err := s.tunnelTCPDumpFilters4(t.Context())
		require.NoError(t, err)
		assert.Contains(t, c4, "udp[42:4] == 0x0af4000a and udp[46:4] == 0x0af40114")
		assert.Contains(t, c4, "ip6[82:4] == 0x0af4000a and ip6[86:4] == 0x0af40114")
		assert.Contains(t, s4, "udp[42:4] == 0x0af40114 and udp[46:4] == 0x0af4000a")

		c6, _, err := s.tunnelTCPDumpFilters6(t.Context())
		require.NoError(t, err)
		assert.Contains(t, c6, "udp[38:4] == 0xfd000010")
		assert.Contains(t, c6, "udp[54:4] == 0xfd000010")
		assert.Contains(t, c6, "ip6[78:4] == 0xfd000010")
		assert.Contains(t, c6, "ip6[94:4] == 0xfd000010")
	})

	t.Run("ip inner protocol omits L2 offset (+0)", func(t *testing.T) {
		s := newScenario(t, "ip")
		assert.Equal(t, 0, s.tunnelInnerL2Len())

		c4, s4, err := s.tunnelTCPDumpFilters4(t.Context())
		require.NoError(t, err)
		assert.Contains(t, c4, "udp[28:4] == 0x0af4000a and udp[32:4] == 0x0af40114")
		assert.Contains(t, c4, "ip6[68:4] == 0x0af4000a and ip6[72:4] == 0x0af40114")
		assert.Contains(t, s4, "udp[28:4] == 0x0af40114 and udp[32:4] == 0x0af4000a")

		c6, _, err := s.tunnelTCPDumpFilters6(t.Context())
		require.NoError(t, err)
		assert.Contains(t, c6, "udp[24:4] == 0xfd000010")
		assert.Contains(t, c6, "udp[40:4] == 0xfd000010")
		assert.Contains(t, c6, "ip6[64:4] == 0xfd000010")
		assert.Contains(t, c6, "ip6[80:4] == 0xfd000010")
	})
}
