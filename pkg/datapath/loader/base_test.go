// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func rpFilterName(dev string) []string {
	return []string{"net", "ipv4", "conf", dev, "rp_filter"}
}

func TestBPFGeneveRPFilterSettings(t *testing.T) {
	prevEnableIPv4 := option.Config.EnableIPv4
	t.Cleanup(func() {
		option.Config.EnableIPv4 = prevEnableIPv4
	})

	// rp_filter of the devices before the call; "missing" has no sysctl,
	// e.g. because it disappeared in the meantime, and must be skipped.
	initial := map[string]string{"strict": "1", "off": "0", "loose": "2"}
	devices := []string{"strict", "off", "loose", "missing"}

	tests := []struct {
		name         string
		tunnelConfig tunnel.Config
		enableIPv4   bool
		relaxed      bool // whether "strict" must be changed to 2
	}{
		{
			name:         "BPF Geneve, inner eth",
			tunnelConfig: tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			enableIPv4:   true,
			relaxed:      true,
		},
		{
			name:         "BPF Geneve, inner ip, IPv6 underlay",
			tunnelConfig: tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoIP),
			enableIPv4:   true,
			relaxed:      true,
		},
		{
			name:         "BPF Geneve without IPv4",
			tunnelConfig: tunnel.NewTestBPFGeneveConfig(tunnel.IPv6, tunnel.GeneveInnerProtoETH),
			enableIPv4:   false,
		},
		{
			name:         "kernel Geneve",
			tunnelConfig: tunnel.NewTestConfig(tunnel.Geneve),
			enableIPv4:   true,
		},
		{
			name:         "VXLAN",
			tunnelConfig: tunnel.NewTestConfig(tunnel.VXLAN),
			enableIPv4:   true,
		},
		{
			name:         "tunneling disabled",
			tunnelConfig: tunnel.NewTestConfig(tunnel.Disabled),
			enableIPv4:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableIPv4 = tt.enableIPv4
			fs := afero.NewMemMapFs()
			for dev, val := range initial {
				path := filepath.Join(append([]string{"/proc", "sys"}, rpFilterName(dev)...)...)
				require.NoError(t, afero.WriteFile(fs, path, []byte(val+"\n"), 0o644))
			}
			sc := sysctl.NewDirectSysctl(fs, "/proc")

			settings := bpfGeneveRPFilterSettings(hivetest.Logger(t), sc, tt.tunnelConfig, devices)

			want := map[string]string{}
			if tt.relaxed {
				want["net.ipv4.conf.strict.rp_filter"] = "2"
			}
			got := map[string]string{}
			for _, s := range settings {
				got[strings.Join(s.Name, ".")] = s.Val
				require.True(t, s.IgnoreErr, "setting for %v must ignore errors", s.Name)
			}
			require.Equal(t, want, got)

			// Only a strict value is changed; 0 and 2 stay as they are.
			require.NoError(t, sc.ApplySettings(settings))
			for dev, val := range initial {
				if tt.relaxed && dev == "strict" {
					val = "2"
				}
				cur, err := sc.Read(rpFilterName(dev))
				require.NoError(t, err)
				require.Equal(t, val, cur, "rp_filter of %s", dev)
			}
		})
	}
}

func TestPrivilegedBPFGeneveRPFilterSettings(t *testing.T) {
	testutils.PrivilegedTest(t)

	prevEnableIPv4 := option.Config.EnableIPv4
	t.Cleanup(func() {
		option.Config.EnableIPv4 = prevEnableIPv4
	})
	option.Config.EnableIPv4 = true

	sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
	initial := map[string]string{"rpf-strict": "1", "rpf-off": "0", "rpf-loose": "2"}

	tests := []struct {
		name         string
		tunnelConfig tunnel.Config
		want         map[string]string
	}{
		{
			name:         "BPF Geneve",
			tunnelConfig: tunnel.NewTestBPFGeneveConfig(tunnel.IPv4, tunnel.GeneveInnerProtoETH),
			want:         map[string]string{"rpf-strict": "2", "rpf-off": "0", "rpf-loose": "2"},
		},
		{
			name:         "kernel Geneve",
			tunnelConfig: tunnel.NewTestConfig(tunnel.Geneve),
			want:         initial,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				var devices []string
				for dev, val := range initial {
					require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dev}}))
					require.NoError(t, sc.Write(rpFilterName(dev), val))
					devices = append(devices, dev)
				}

				settings := bpfGeneveRPFilterSettings(hivetest.Logger(t), sc, tt.tunnelConfig, devices)
				require.NoError(t, sc.ApplySettings(settings))

				for dev, want := range tt.want {
					cur, err := sc.Read(rpFilterName(dev))
					require.NoError(t, err)
					require.Equal(t, want, cur, "rp_filter of %s", dev)
				}
				return nil
			}))
		})
	}
}

// dirEntries returns the names of the entries of dir.
func dirEntries(tb testing.TB, dir string) []string {
	tb.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(tb, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// pinProgArrays pins a map with each of the given names in dir. The map type
// does not matter to the cleanup, which goes by name.
func pinProgArrays(tb testing.TB, dir string, names ...string) {
	tb.Helper()

	for _, name := range names {
		m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.ProgramArray,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1,
			Pinning:    ebpf.PinByName,
		}, ebpf.MapOptions{PinPath: dir})
		require.NoError(tb, err)
		require.NoError(tb, m.Close())
	}
}

func TestCleanBPFGeneveMaps(t *testing.T) {
	// Pins of other objects, some with similar names.
	unrelated := []string{"cilium_calls_overlay_2", "cilium_calls_hostns_00001", "cilium_geneve_routes"}

	// L1-17: turning the feature off removes the maps it shares between
	// objects, and nothing else.
	t.Run("removes only the BPF Geneve pins", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range append([]string{"cilium_calls_bpf_overlay", "cilium_geneve_meta"}, unrelated...) {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))
		}

		require.NoError(t, cleanBPFGeneveMaps(dir))
		require.ElementsMatch(t, unrelated, dirEntries(t, dir))
	})

	// L1-17: the cleanup runs on every start with the feature off, usually
	// with nothing to remove.
	t.Run("missing pins are not an error", func(t *testing.T) {
		require.NoError(t, cleanBPFGeneveMaps(t.TempDir()))
	})
}

func TestPrivilegedCleanBPFGeneveMaps(t *testing.T) {
	testutils.PrivilegedTest(t)
	require.NoError(t, rlimit.RemoveMemlock())

	// L1-17: TestCleanBPFGeneveMaps with real pins on a bpffs.
	dir := testutils.TempBPFFS(t)
	pinProgArrays(t, dir, "cilium_calls_bpf_overlay", "cilium_geneve_meta", "cilium_calls_overlay_2")

	require.NoError(t, cleanBPFGeneveMaps(dir))
	require.Equal(t, []string{"cilium_calls_overlay_2"}, dirEntries(t, dir))
}

func TestPrivilegedReinitializeOverlayBPFGeneveOff(t *testing.T) {
	testutils.PrivilegedTest(t)
	require.NoError(t, rlimit.RemoveMemlock())
	initBpffs(t)
	setupOverlayDirs(t)

	// L1-17: reinitializeOverlay() removes the BPF Geneve pins whenever the
	// feature is off, also with tunneling disabled, where it returns early.
	globals := bpf.TCGlobalsPath()
	pinProgArrays(t, globals, "cilium_calls_bpf_overlay", "cilium_geneve_meta", "cilium_calls_hostns_00001")

	require.NoError(t, reinitializeOverlay(t.Context(), hivetest.Logger(t), nil, nil,
		&localNodeConfig, tunnel.NewTestConfig(tunnel.Disabled)))
	require.NoFileExists(t, filepath.Join(globals, "cilium_calls_bpf_overlay"))
	require.NoFileExists(t, filepath.Join(globals, "cilium_geneve_meta"))
	require.FileExists(t, filepath.Join(globals, "cilium_calls_hostns_00001"))
}

func TestPrivilegedBPFGeneveMapsMatchObjects(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)

	// Compiles src with the options of one of the BPF Geneve permutations
	// in bpf/Makefile, with or without the feature.
	load := func(src string, bpfGeneve bool) (*ebpf.CollectionSpec, error) {
		opts := []string{"-DENABLE_IPV4", "-DENABLE_IPV6", "-DENCAP_IFINDEX", "-DTUNNEL_MODE", "-DENABLE_NODEPORT"}
		if bpfGeneve {
			opts = append(opts, "-DENABLE_BPF_GENEVE")
		}
		path, err := compile(t.Context(), logger, &progInfo{
			Source:     src,
			Output:     strings.TrimSuffix(src, ".c") + ".o",
			OutputType: outputObject,
			Options:    opts,
		}, getDirs(t))
		if err != nil {
			return nil, err
		}
		return ebpf.LoadCollectionSpec(path)
	}

	// The feature is built into the tc objects.
	progs := []string{endpointProg, hostEndpointProg, overlayProg, wireguardProg}
	on := make([]*ebpf.CollectionSpec, len(progs))
	off := make([]*ebpf.CollectionSpec, len(progs))
	var g errgroup.Group
	for i, src := range progs {
		g.Go(func() (err error) {
			on[i], err = load(src, true)
			return err
		})
		g.Go(func() (err error) {
			off[i], err = load(src, false)
			return err
		})
	}
	require.NoError(t, g.Wait())

	// T1: bpfGeneveMaps, the pins removed when the feature is off, must list
	// every map that the feature adds pinned by name to an object, or a stale
	// pin of it would outlive the feature.
	var added []string
	for i := range progs {
		for name, m := range on[i].Maps {
			if m.Pinning == ebpf.PinByName && off[i].Maps[name] == nil && !slices.Contains(added, name) {
				added = append(added, name)
			}
		}
	}
	require.ElementsMatch(t, bpfGeneveMaps, added)
}
