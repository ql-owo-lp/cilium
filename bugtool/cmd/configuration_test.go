// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBPFMapsPathBPFGeneve(t *testing.T) {
	// T1: the pins of the BPF Geneve datapath (bpfGeneveMaps in
	// pkg/datapath/loader) are dumped, and no stale cilium_geneve_* ones.
	var geneve []string
	for _, path := range bpfMapsPath {
		if strings.HasPrefix(path, "tc/globals/cilium_geneve_") {
			geneve = append(geneve, path)
		}
	}
	require.Equal(t, []string{"tc/globals/cilium_geneve_meta"}, geneve)
	require.Contains(t, bpfMapsPath, "tc/globals/cilium_calls_bpf_overlay")
}
