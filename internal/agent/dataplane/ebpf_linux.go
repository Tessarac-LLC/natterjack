/*
Copyright 2026 Tessarac, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dataplane

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

// steerObject is bpf/steer.c, built by `make bpf`.
//
//go:embed bpf/steer_bpfel.o
var steerObject []byte

// Devices whose presence shows a CNI that moves pod traffic past netfilter.
var bypassDevices = []string{"cilium_host", "bpfin.cali", "bpfout.cali"}

// linkPin names the pinned tcx link of one program on one uplink.
func linkPin(ifname, dir string) string { return "link_" + ifname + "_" + dir }

// mode picks how pod traffic is steered on this node.
func (d *Dataplane) mode() Mode {
	if d.cfg.Mode != ModeAuto {
		return d.cfg.Mode
	}
	for _, name := range bypassDevices {
		if _, err := netlink.LinkByName(name); err == nil {
			return ModeEBPF
		}
	}
	return ModeNFTables
}

// uplinks are the devices pod traffic can leave the node by: the one with
// the node's address and every device a default route uses.
func uplinks(underlay netlink.Link) ([]netlink.Link, error) {
	byIndex := map[int]netlink.Link{underlay.Attrs().Index: underlay}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() != "0.0.0.0/0" {
			continue
		}
		idx := []int{r.LinkIndex}
		for _, nh := range r.MultiPath {
			idx = append(idx, nh.LinkIndex)
		}
		for _, i := range idx {
			if _, ok := byIndex[i]; i == 0 || ok {
				continue
			}
			l, err := netlink.LinkByIndex(i)
			if err != nil {
				continue
			}
			if strings.HasPrefix(l.Attrs().Name, "nj") {
				continue // the agent's own devices
			}
			byIndex[i] = l
		}
	}
	out := make([]netlink.Link, 0, len(byIndex))
	for _, l := range byIndex {
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b netlink.Link) int { return a.Attrs().Index - b.Attrs().Index })
	return out, nil
}

// applyEBPF loads the fast path, puts its programs first on every uplink and
// fills its maps from want.
func (d *Dataplane) applyEBPF(want *agent.Desired, ups []netlink.Link) (uint64, error) {
	if err := ensureBPFFS(d.cfg.BPFDir); err != nil {
		return 0, err
	}
	divert, err := d.ensureDivert(ups[0].Attrs().MTU)
	if err != nil {
		return 0, err
	}
	coll, err := d.loadSteer(divert)
	if err != nil {
		return 0, err
	}
	defer coll.Close()

	keep := map[string]bool{}
	for _, l := range ups {
		for _, at := range []struct {
			dir  string
			prog string
			typ  ebpf.AttachType
		}{
			{"egress", "nj_egress", ebpf.AttachTCXEgress},
			{"ingress", "nj_ingress", ebpf.AttachTCXIngress},
		} {
			pin := linkPin(l.Attrs().Name, at.dir)
			keep[pin] = true
			if err := d.attachFirst(l, at.typ, coll.Programs[at.prog], pin); err != nil {
				return 0, err
			}
		}
	}
	if err := d.removeLinks(keep); err != nil {
		return 0, err
	}
	if err := syncSteered(coll.Maps["nj_steered"], want); err != nil {
		return 0, err
	}
	if err := syncExcluded(coll.Maps["nj_excluded"], want.Excluded); err != nil {
		return 0, err
	}
	return diverted(coll.Maps["nj_diverted"])
}

// ensureBPFFS makes sure dir is on a BPF filesystem, mounting one at its
// parent if none is there. The chart mounts the host's /sys/fs/bpf with
// bidirectional propagation, so a mount made here is the host's.
func ensureBPFFS(dir string) error {
	parent := filepath.Dir(dir)
	var fs unix.Statfs_t
	if err := unix.Statfs(parent, &fs); err != nil {
		return fmt.Errorf("BPF filesystem at %s: %w", parent, err)
	}
	if fs.Type != unix.BPF_FS_MAGIC {
		if err := unix.Mount("bpffs", parent, "bpf", 0, "mode=0700"); err != nil {
			return fmt.Errorf("mount the BPF filesystem at %s: %w", parent, err)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("BPF directory: %w", err)
	}
	return nil
}

// ensureDivert makes the dummy device steered packets re-enter the stack
// through.
func (d *Dataplane) ensureDivert(mtu int) (netlink.Link, error) {
	l, err := netlink.LinkByName(DivertLink)
	switch {
	case isNotFound(err):
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DivertLink, MTU: mtu}}); err != nil {
			return nil, fmt.Errorf("create %s: %w", DivertLink, err)
		}
		if l, err = netlink.LinkByName(DivertLink); err != nil {
			return nil, fmt.Errorf("find %s: %w", DivertLink, err)
		}
	case err != nil:
		return nil, fmt.Errorf("find %s: %w", DivertLink, err)
	case l.Type() != "dummy":
		return nil, fmt.Errorf("%s exists and is not a dummy device but %s", DivertLink, l.Type())
	}
	if l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return nil, fmt.Errorf("set %s MTU %d: %w", DivertLink, mtu, err)
		}
	}
	// Like nj0: an address only so reverse path filtering accepts what
	// arrives on the device.
	addr := &netlink.Addr{IPNet: hostPrefix(d.cfg.TunnelAddr()), Scope: unix.RT_SCOPE_HOST}
	if err := netlink.AddrReplace(l, addr); err != nil {
		return nil, fmt.Errorf("address %s on %s: %w", addr.IPNet, DivertLink, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, fmt.Errorf("set %s up: %w", DivertLink, err)
	}
	if err := writeSysctl("net/ipv4/conf/"+DivertLink+"/rp_filter", "2"); err != nil {
		return nil, err
	}
	return l, nil
}

// loadSteer loads the programs for divert, reusing the pinned maps. Maps
// from an incompatible earlier version are replaced.
func (d *Dataplane) loadSteer(divert netlink.Link) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(steerObject))
	if err != nil {
		return nil, fmt.Errorf("read the eBPF fast path: %w", err)
	}
	mac := divert.Attrs().HardwareAddr
	if len(mac) != 6 {
		return nil, fmt.Errorf("%s has no Ethernet address", DivertLink)
	}
	if err := spec.Variables["divert_ifindex"].Set(uint32(divert.Attrs().Index)); err != nil { // #nosec G115 -- interface indexes are positive 32-bit numbers
		return nil, fmt.Errorf("set divert_ifindex: %w", err)
	}
	if err := spec.Variables["divert_mac"].Set([6]byte(mac)); err != nil {
		return nil, fmt.Errorf("set divert_mac: %w", err)
	}
	opts := ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: d.cfg.BPFDir}}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		d.log.Info("replacing the eBPF fast path's maps from an earlier version")
		for name, m := range spec.Maps {
			if m.Pinning == ebpf.PinByName {
				if err := os.Remove(filepath.Join(d.cfg.BPFDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return nil, fmt.Errorf("remove map %s: %w", name, err)
				}
			}
		}
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
	}
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// The verifier's whole log, not only its last line.
			return nil, fmt.Errorf("load the eBPF fast path: %w\n%s", err, fmt.Sprintf("%+v", ve))
		}
		return nil, fmt.Errorf("load the eBPF fast path: %w", err)
	}
	return coll, nil
}

// attachFirst makes prog the first tcx program of type typ on l, through
// the link pinned at pin. A CNI that attached ahead of it since, or a
// restarted agent, is handled by moving or replacing the link.
func (d *Dataplane) attachFirst(l netlink.Link, typ ebpf.AttachType, prog *ebpf.Program, pin string) error {
	path := filepath.Join(d.cfg.BPFDir, pin)
	name := l.Attrs().Name
	if old, err := link.LoadPinnedLink(path, nil); err == nil {
		first, ferr := firstProgram(l.Attrs().Index, typ)
		info, ierr := old.Info()
		if ferr == nil && ierr == nil && first == info.Program {
			// Still first: swap in this version's program.
			err := old.Update(prog)
			_ = old.Close()
			if err != nil {
				return fmt.Errorf("update the eBPF fast path on %s: %w", name, err)
			}
			return nil
		}
		// Moved down, or the device was recreated: attach anew, then drop
		// the old link.
		_ = old.Unpin()
		defer func() { _ = old.Close() }()
	}
	ln, err := link.AttachTCX(link.TCXOptions{Interface: l.Attrs().Index, Program: prog, Attach: typ, Anchor: link.Head()})
	if errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("attach the eBPF fast path to %s: the kernel has no tcx (Linux 6.6 or later): %w", name, err)
	}
	if err != nil {
		return fmt.Errorf("attach the eBPF fast path to %s: %w", name, err)
	}
	defer func() { _ = ln.Close() }() // the pin keeps it attached
	if err := ln.Pin(path); err != nil {
		_ = ln.Close()
		return fmt.Errorf("pin the eBPF fast path on %s: %w", name, err)
	}
	d.log.Info("eBPF fast path attached", "device", name, "hook", typ.String())
	return nil
}

// firstProgram is the ID of the program that runs first on a hook.
func firstProgram(ifindex int, typ ebpf.AttachType) (ebpf.ProgramID, error) {
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: typ})
	if err != nil {
		return 0, fmt.Errorf("query %s programs: %w", typ, err)
	}
	if len(res.Programs) == 0 {
		return 0, errors.New("no programs")
	}
	return res.Programs[0].ID, nil
}

// removeLinks unpins the agent's links not in keep, which detaches them.
func (d *Dataplane) removeLinks(keep map[string]bool) error {
	entries, err := os.ReadDir(d.cfg.BPFDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", d.cfg.BPFDir, err)
	}
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "link_") || keep[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(d.cfg.BPFDir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("detach %s: %w", e.Name(), err))
			continue
		}
		d.log.Info("eBPF fast path detached", "link", e.Name())
	}
	return errors.Join(errs...)
}

// removeEBPF detaches the fast path and deletes its maps and device.
func (d *Dataplane) removeEBPF() error {
	if d.cfg.BPFDir == "" {
		return nil
	}
	var errs []error
	if err := os.RemoveAll(d.cfg.BPFDir); err != nil {
		errs = append(errs, fmt.Errorf("remove %s: %w", d.cfg.BPFDir, err))
	}
	if l, err := netlink.LinkByName(DivertLink); err == nil {
		if err := netlink.LinkDel(l); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", DivertLink, err))
		}
	}
	return errors.Join(errs...)
}

func be32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

// syncSteered makes the map hold exactly the steered pod addresses.
func syncSteered(m *ebpf.Map, want *agent.Desired) error {
	keys := map[uint32]bool{}
	for _, st := range want.Steers {
		for _, a := range st.Sources {
			if a.Is4() {
				keys[be32(a)] = true
			}
		}
	}
	return syncMap(m, keys)
}

type lpmKey struct {
	Len  uint32
	Addr uint32
}

// syncExcluded makes the map hold exactly the excluded prefixes.
func syncExcluded(m *ebpf.Map, prefixes []netip.Prefix) error {
	keys := map[lpmKey]bool{}
	for _, p := range prefixes {
		if p.Addr().Is4() {
			p = p.Masked()
			keys[lpmKey{Len: uint32(p.Bits()), Addr: be32(p.Addr())}] = true // #nosec G115 -- 0 to 32
		}
	}
	return syncMap(m, keys)
}

func syncMap[K comparable](m *ebpf.Map, want map[K]bool) error {
	var (
		k     K
		v     uint8
		stale []K
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("read map %s: %w", mapName(m), err)
	}
	for _, s := range stale {
		if err := m.Delete(s); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("update map %s: %w", mapName(m), err)
		}
	}
	for w := range want {
		if err := m.Put(w, uint8(1)); err != nil {
			return fmt.Errorf("update map %s: %w", mapName(m), err)
		}
	}
	return nil
}

func mapName(m *ebpf.Map) string {
	if info, err := m.Info(); err == nil {
		return info.Name
	}
	return m.String()
}

// diverted sums the per-CPU count of diverted packets.
func diverted(m *ebpf.Map) (uint64, error) {
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		return 0, fmt.Errorf("read the diverted count: %w", err)
	}
	var n uint64
	for _, c := range per {
		n += c
	}
	return n, nil
}
