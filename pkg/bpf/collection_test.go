// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedUpgradeMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	temp := testutils.TempBPFFS(t)

	// Pin a dummy map in order to test upgrading it.
	_, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       "upgraded_map",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{PinPath: temp})
	require.NoError(t, err)

	spec, err := ebpf.LoadCollectionSpec("testdata/upgrade-map.o")
	require.NoError(t, err)

	// Use LoadAndAssign to make sure commit works through map upgrades. This is a
	// regression test, as [ebpf.Collection.Assign] deletes Map objects from the
	// Collection when successful, causing commit() to fail afterwards if it uses
	// stringly references to Collection.Maps entries.
	obj := struct {
		UpgradedMap *ebpf.Map `ebpf:"upgraded_map"`
	}{}
	commit, err := LoadAndAssign(logger, &obj, spec, &CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: temp},
		},
	})
	require.NoError(t, err)
	require.NoError(t, commit())

	// Check if the map was upgraded correctly.
	assert.True(t, obj.UpgradedMap.IsPinned())
	assert.EqualValues(t, 10, obj.UpgradedMap.MaxEntries())
}

func TestIsEntrypoint(t *testing.T) {
	// L3-05: only programs marked with __section_entry are entry points, not
	// the sections of the BPF unit test harness (bpf/tests/common.h).
	for section, want := range map[string]bool{
		"tc/entry":           true,
		"tc/tail":            false,
		"tc/test/foo/pktgen": false,
		"tc/test/foo/setup":  false,
		"tc/test/foo/check":  false,
	} {
		assert.Equal(t, want, isEntrypoint(&ebpf.ProgramSpec{SectionName: section}), section)
	}
}

func TestResolveTailCalls(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("testdata/external-tailcall.o")
	require.NoError(t, err)

	cpy := spec.Copy()
	require.NoError(t, resolveTailCalls(cpy))

	// Tail calls are inserted into the map named by their annotation.
	assert.ElementsMatch(t, []ebpf.MapKV{
		{Key: uint32(0), Value: "a"},
		{Key: uint32(1), Value: "b"},
		{Key: uint32(2), Value: "c"},
	}, cpy.Maps[callsMap].Contents)
	assert.Equal(t, []ebpf.MapKV{
		{Key: uint32(0), Value: "shared_a"},
	}, cpy.Maps["shared_calls"].Contents)

	// A tail call whose map is missing from the spec is a configuration error
	// rather than something to silently skip.
	cpy = spec.Copy()
	delete(cpy.Maps, "shared_calls")
	err = resolveTailCalls(cpy)
	require.ErrorContains(t, err, "shared_calls")
	require.ErrorContains(t, err, "shared_a")
}

// A shared program array populated by resolveTailCalls is only tail called
// into from other objects, so it is never referenced by an instruction in this
// one. Make sure it is created and populated anyway.
func TestPrivilegedLoadCollectionSharedTailCallMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	spec, err := ebpf.LoadCollectionSpec("testdata/external-tailcall.o")
	require.NoError(t, err)

	coll, commit, err := LoadCollection(logger, spec, &CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: testutils.TempBPFFS(t)},
		},
	})
	require.NoError(t, err)
	defer coll.Close()
	require.NoError(t, commit())

	assert.NotContains(t, coll.Programs, "c")
	require.Contains(t, coll.Programs, "shared_a")
	require.Contains(t, coll.Maps, "shared_calls")

	// shared_calls[0] must hold shared_a.
	want, err := coll.Programs["shared_a"].Info()
	require.NoError(t, err)
	wantID, ok := want.ID()
	require.True(t, ok)

	var gotID ebpf.ProgramID
	require.NoError(t, coll.Maps["shared_calls"].Lookup(uint32(0), &gotID))
	assert.Equal(t, wantID, gotID)
}
