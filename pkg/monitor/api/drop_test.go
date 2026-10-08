// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestBPFGeneveDropReasons(t *testing.T) {
	// The drop reasons of the BPF Geneve datapath, DROP_GENEVE_* in
	// bpf/lib/drop_reasons.h, have a name in monitor output and in the flow
	// API.
	for _, tt := range []struct {
		code uint8
		name string
		enum flowpb.DropReason
	}{
		{208, "Invalid Geneve header", flowpb.DropReason_DROP_GENEVE_HDR_INVALID},
		{209, "Invalid or unsupported critical Geneve option", flowpb.DropReason_DROP_GENEVE_OPT_INVALID},
		{210, "Geneve encapsulation failed", flowpb.DropReason_DROP_GENEVE_ENCAP_FAILED},
	} {
		t.Run(tt.enum.String(), func(t *testing.T) {
			require.Equal(t, tt.name, DropReason(tt.code))
			require.Equal(t, tt.enum, flowpb.DropReason(tt.code))
		})
	}
}
