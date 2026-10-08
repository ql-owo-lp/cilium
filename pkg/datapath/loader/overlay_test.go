// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	fakebigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/fake"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// setupOverlayDirs points the BPF source and state directories at the
// repository and at a temporary directory, and changes into the latter like
// the agent does at startup: replaceOverlayDatapath() loads the object it
// compiled from a path relative to it.
func setupOverlayDirs(tb testing.TB) {
	tb.Helper()

	bpfAbsDir, err := filepath.Abs(bpfDir)
	require.NoError(tb, err)

	prevBpfDir, prevStateDir := option.Config.BpfDir, option.Config.StateDir
	tb.Cleanup(func() {
		option.Config.BpfDir, option.Config.StateDir = prevBpfDir, prevStateDir
	})
	option.Config.BpfDir = bpfAbsDir
	option.Config.StateDir = tb.TempDir()
	tb.Chdir(option.Config.StateDir)
}

// writeNodeConfig writes the node_config.h that compileOverlay() picks up,
// with the defines that the tunnel cell contributes for the given flags, and
// returns the resulting tunnel configuration. ENCAP_IFINDEX is looked up in
// the current network namespace.
//
// The defines are rendered like the agent does, together with the ones it
// adds for an IPv4 node in tunnel routing mode. All other settings come from
// the test defaults in bpf/node_config.h.
func writeNodeConfig(logger *slog.Logger, flags map[string]any) (tunnel.Config, error) {
	var (
		tunnelCfg tunnel.Config
		defines   = dpdef.Map{"ENABLE_IPV4": "1", "TUNNEL_MODE": "1"}
	)
	h := hive.New(
		tunnel.Cell,
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{RoutingMode: option.RoutingModeTunnel, EnableIPv4: true}
		}),
		cell.Invoke(func(in struct {
			cell.In

			Config    tunnel.Config
			Defines   []dpdef.Map `group:"header-node-defines"`
			DefineFns []dpdef.Fn  `group:"header-node-define-fns"`
		}) error {
			tunnelCfg = in.Config
			for _, m := range in.Defines {
				if err := defines.Merge(m); err != nil {
					return err
				}
			}
			for _, fn := range in.DefineFns {
				m, err := fn()
				if err != nil {
					return err
				}
				if err := defines.Merge(m); err != nil {
					return err
				}
			}
			return nil
		}),
	)
	for key, value := range flags {
		h.Viper().Set(key, value)
	}
	if err := h.Populate(logger); err != nil {
		return tunnel.Config{}, err
	}

	var b strings.Builder
	b.WriteString("#include_next <node_config.h>\n")
	for _, key := range slices.Sorted(maps.Keys(defines)) {
		fmt.Fprintf(&b, "#define %s %s\n", key, defines[key])
	}
	path := option.Config.GetNodeConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return tunnel.Config{}, err
	}
	return tunnelCfg, os.WriteFile(path, []byte(b.String()), 0o644)
}

// pinnedMap opens a pinned map and returns it with its ID.
func pinnedMap(tb testing.TB, path string) (*ebpf.Map, ebpf.MapID) {
	tb.Helper()

	m, err := ebpf.LoadPinnedMap(path, nil)
	require.NoError(tb, err)
	tb.Cleanup(func() { m.Close() })

	info, err := m.Info()
	require.NoError(tb, err)
	id, ok := info.ID()
	require.True(tb, ok)
	return m, id
}

// progArray returns the IDs of the programs in the slots of a program array,
// 0 for an empty slot.
func progArray(tb testing.TB, m *ebpf.Map) []ebpf.ProgramID {
	tb.Helper()

	ids := make([]ebpf.ProgramID, m.MaxEntries())
	for slot := range ids {
		var id uint32
		err := m.Lookup(uint32(slot), &id)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		require.NoError(tb, err)
		ids[slot] = ebpf.ProgramID(id)
	}
	return ids
}

func TestPrivilegedReplaceOverlayDatapathBPFGeneve(t *testing.T) {
	testutils.PrivilegedTest(t)
	require.NoError(t, rlimit.RemoveMemlock())
	initBpffs(t)
	setupOverlayDirs(t)

	ctx := t.Context()
	logger := hivetest.Logger(t)
	collLoader := newBPFCollectionLoader(false, "")
	globals := bpf.TCGlobalsPath()

	bpfGeneveFlags := map[string]any{
		"tunnel-protocol":          string(tunnel.Geneve),
		"enable-bpf-geneve":        true,
		"tunnel-source-port-range": "32768-61000",
	}
	kernelGeneveFlags := map[string]any{
		"tunnel-protocol":          string(tunnel.Geneve),
		"tunnel-source-port-range": "32768-61000",
	}

	ns := netns.NewNetNS(t)
	var (
		link      netlink.Link
		tunnelCfg tunnel.Config
	)
	require.NoError(t, ns.Do(func() (err error) {
		sc := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
		if err := setupTunnelDevice(logger, sc, tunnel.Geneve, defaults.TunnelPortGeneve, 0, 0, 1500, &fakebigtcp.Config{}); err != nil {
			return err
		}
		if link, err = safenetlink.LinkByName(defaults.GeneveDevice); err != nil {
			return err
		}
		tunnelCfg, err = writeNodeConfig(logger, bpfGeneveFlags)
		return err
	}))
	require.True(t, tunnelCfg.EnableBPFGeneve())

	// The fields that newLocalNodeConfig() takes from the tunnel config.
	lnc := localNodeConfig
	lnc.TunnelProtocol = tunnelCfg.EncapProtocol().ToDpID()
	lnc.TunnelPort = tunnelCfg.Port()
	lnc.TunnelSrcPortLow = tunnelCfg.SrcPortLow()
	lnc.TunnelSrcPortHigh = tunnelCfg.SrcPortHigh()

	replace := func(cfg tunnel.Config) error {
		return ns.Do(func() error {
			return replaceOverlayDatapath(ctx, logger, nil, collLoader, &lnc, cfg, link)
		})
	}

	// Load the overlay twice, as on an agent restart. Keep the private tail
	// call map of the first load open to inspect it after the second one.
	require.NoError(t, replace(tunnelCfg))
	shared, sharedID := pinnedMap(t, filepath.Join(globals, "cilium_calls_bpf_overlay"))
	firstShared := progArray(t, shared)
	firstCalls, firstCallsID := pinnedMap(t, filepath.Join(globals, "cilium_calls_overlay_2"))
	firstCallsSlots := progArray(t, firstCalls)

	require.NoError(t, replace(tunnelCfg))
	secondCalls, secondCallsID := pinnedMap(t, filepath.Join(globals, "cilium_calls_overlay_2"))
	require.NoError(t, secondCalls.Close())

	// B5: bpf_host enters bpf_overlay through cilium_calls_bpf_overlay, so
	// the map must survive reloads, with its slots updated to the programs
	// of the latest load.
	t.Run("shared program array is kept and updated", func(t *testing.T) {
		_, reopenedID := pinnedMap(t, filepath.Join(globals, "cilium_calls_bpf_overlay"))
		require.Equal(t, sharedID, reopenedID)

		for slot, name := range []string{"tail_geneve_from_overlay", "tail_geneve_to_overlay"} {
			prog, err := ebpf.NewProgramFromID(progArray(t, shared)[slot])
			require.NoError(t, err)
			defer prog.Close()
			info, err := prog.Info()
			require.NoError(t, err)
			require.Equal(t, name, info.Name)

			// The programs of the second load tail call into its own
			// cilium_calls.
			mapIDs, ok := info.MapIDs()
			require.True(t, ok)
			require.Contains(t, mapIDs, secondCallsID, "slot %d", slot)
		}
	})

	// B5: cilium_calls is private to the object and replaced on every load
	// instead of being repopulated slot by slot while the attached programs
	// use it.
	t.Run("private tail call map is replaced", func(t *testing.T) {
		require.NotEqual(t, firstCallsID, secondCallsID)
		require.Equal(t, firstCallsSlots, progArray(t, firstCalls))
	})

	// B5: no stale slot keeps the programs of the first load alive. The
	// loader leaves the objects it does not assign to the garbage collector.
	t.Run("programs of the previous load are released", func(t *testing.T) {
		require.NoError(t, firstCalls.Close())
		stale := slices.DeleteFunc(slices.Concat(firstShared, firstCallsSlots),
			func(id ebpf.ProgramID) bool { return id == 0 })
		require.NotEmpty(t, stale)

		require.Eventually(t, func() bool {
			runtime.GC()
			if m, err := ebpf.NewMapFromID(firstCallsID); !errors.Is(err, os.ErrNotExist) {
				m.Close()
				return false
			}
			for _, id := range stale {
				if prog, err := ebpf.NewProgramFromID(id); !errors.Is(err, os.ErrNotExist) {
					prog.Close()
					return false
				}
			}
			return true
		}, 10*time.Second, 50*time.Millisecond)
	})

	// L1-09: the object gets the range of --tunnel-source-port-range for
	// geneve_src_port().
	t.Run("object gets the tunnel source port range", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(bpfStateDeviceDir(defaults.GeneveDevice), overlayConfig))
		require.NoError(t, err)
		var dump struct {
			Variables map[string][]byte `json:"variables"`
		}
		require.NoError(t, json.Unmarshal(raw, &dump))

		for name, want := range map[string]uint16{
			"__config_tunnel_src_port_low":  32768,
			"__config_tunnel_src_port_high": 61000,
		} {
			require.Len(t, dump.Variables[name], 2, name)
			require.Equal(t, want, binary.NativeEndian.Uint16(dump.Variables[name]), name)
		}
	})

	// L1-17, L1-15, L3-09: turning the feature off, here back to the kernel
	// Geneve device, removes the pins it shares between objects, and the
	// overlay object built without it loads into overlayObjects.
	t.Run("disabling the feature removes its pins", func(t *testing.T) {
		require.NoError(t, ns.Do(func() error {
			cfg, err := writeNodeConfig(logger, kernelGeneveFlags)
			if err != nil {
				return err
			}
			if cfg.EnableBPFGeneve() {
				return errors.New("BPF Geneve enabled")
			}
			return reinitializeOverlay(ctx, logger, nil, collLoader, &lnc, cfg)
		}))
		require.NoFileExists(t, filepath.Join(globals, "cilium_calls_bpf_overlay"))
		require.NoFileExists(t, filepath.Join(globals, "cilium_geneve_meta"))
		require.FileExists(t, filepath.Join(globals, "cilium_calls_overlay_2"))
	})

	// L1-15, L3-09: with the feature on, an overlay object built without it
	// fails to load instead of leaving bpf_host with an empty
	// cilium_calls_bpf_overlay.
	t.Run("object built without the feature fails to load", func(t *testing.T) {
		require.NoError(t, ns.Do(func() error {
			_, err := writeNodeConfig(logger, kernelGeneveFlags)
			return err
		}))
		require.ErrorContains(t, replace(tunnelCfg), "cilium_calls_bpf_overlay")
	})
}
