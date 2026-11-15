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

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// The fake internet: one host that answers with the caller's address.
const (
	internetHost   = "203.0.113.1"
	internetRouter = "203.0.113.254"
	internetLink   = "njinet"
	internetNS     = "internet"
)

// World is the fake VPC's network, built in the container the fake runs
// in. Each subnet is a bridge holding the subnet's router address; each
// slot is a veth pair whose far end sits on its subnet's bridge and whose
// near end, with the slot's MAC, is moved into the node it is attached
// to. Traffic leaving a subnet for the internet is translated to the
// slot's Elastic IP; node traffic arriving from the kind network leaves
// from the node public address. Nothing comes in unless it answers
// something that went out, as with a slot's security group.
type World struct {
	cfg   *Config
	world netns.NsHandle
	inet  netns.NsHandle
}

// NewWorld builds the network. It must run in the container's own
// network namespace, with the host's process namespace visible.
func NewWorld(ctx context.Context, cfg *Config) (*World, error) {
	self, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("open own namespace: %w", err)
	}
	w := &World{cfg: cfg, world: self}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o600); err != nil {
		return nil, fmt.Errorf("enable forwarding: %w", err)
	}
	for i := range cfg.Subnets {
		if err := w.bridge(i); err != nil {
			return nil, err
		}
	}
	for i := range cfg.Slots {
		if err := w.ensurePair(i); err != nil {
			return nil, err
		}
	}
	if err := w.internet(); err != nil {
		return nil, err
	}
	if err := w.nat(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

func bridgeName(i int) string { return fmt.Sprintf("njbr%d", i) }
func slotName(i int) string   { return fmt.Sprintf("njs%d", i) }
func peerName(i int) string   { return fmt.Sprintf("njw%d", i) }

func (w *World) bridge(i int) error {
	sn := w.cfg.Subnets[i]
	prefix, err := netip.ParsePrefix(sn.CIDR)
	if err != nil {
		return fmt.Errorf("subnet %s: %w", sn.ID, err)
	}
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName(i)}}
	if err := netlink.LinkAdd(br); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("add bridge for %s: %w", sn.ID, err)
	}
	router := prefix.Masked().Addr().Next()
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: router.AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}}
	if err := netlink.AddrReplace(br, addr); err != nil {
		return fmt.Errorf("address bridge for %s: %w", sn.ID, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return fmt.Errorf("bring up bridge for %s: %w", sn.ID, err)
	}
	return nil
}

func (w *World) slotIndex(s *Slot) int {
	for i := range w.cfg.Slots {
		if w.cfg.Slots[i].ID == s.ID {
			return i
		}
	}
	return -1
}

func (w *World) subnetIndex(id string) int {
	for i := range w.cfg.Subnets {
		if w.cfg.Subnets[i].ID == id {
			return i
		}
	}
	return -1
}

// ensurePair creates slot i's veth pair if its near end is not in the
// world. A pair is lost when the node namespace holding it is destroyed,
// as a stopped kind node's is.
func (w *World) ensurePair(i int) error {
	s := w.cfg.Slots[i]
	if _, err := netlink.LinkByName(slotName(i)); err == nil {
		return nil
	}
	if l, err := netlink.LinkByName(peerName(i)); err == nil {
		_ = netlink.LinkDel(l)
	}
	mac, err := net.ParseMAC(s.MAC)
	if err != nil {
		return fmt.Errorf("slot %s: %w", s.ID, err)
	}
	br, err := netlink.LinkByName(bridgeName(w.subnetIndex(s.Subnet)))
	if err != nil {
		return fmt.Errorf("slot %s bridge: %w", s.ID, err)
	}
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: slotName(i), HardwareAddr: mac, MTU: 1500},
		PeerName:  peerName(i),
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("add slot %s: %w", s.ID, err)
	}
	peer, err := netlink.LinkByName(peerName(i))
	if err != nil {
		return fmt.Errorf("slot %s peer: %w", s.ID, err)
	}
	if err := netlink.LinkSetMaster(peer, br); err != nil {
		return fmt.Errorf("slot %s onto its subnet: %w", s.ID, err)
	}
	if err := netlink.LinkSetUp(peer); err != nil {
		return fmt.Errorf("bring up slot %s peer: %w", s.ID, err)
	}
	return nil
}

func (w *World) internet() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, err := netlink.LinkByName(internetLink); err == nil {
		return errors.New("the internet already exists; start the fake in a fresh container")
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: internetLink}, PeerName: "njinet-peer"}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("add internet link: %w", err)
	}
	if err := setAddr(internetLink, internetRouter+"/24"); err != nil {
		return err
	}
	inet, err := netns.NewNamed(internetNS)
	if err != nil {
		return fmt.Errorf("create internet namespace: %w", err)
	}
	// NewNamed moved this thread into the new namespace.
	if err := netns.Set(w.world); err != nil {
		return fmt.Errorf("return to own namespace: %w", err)
	}
	w.inet = inet
	peer, err := netlink.LinkByName("njinet-peer")
	if err != nil {
		return fmt.Errorf("internet peer: %w", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(inet)); err != nil {
		return fmt.Errorf("move internet peer: %w", err)
	}
	h, err := netlink.NewHandleAt(inet)
	if err != nil {
		return fmt.Errorf("open internet namespace: %w", err)
	}
	defer h.Close()
	lo, err := h.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("internet lo: %w", err)
	}
	if err := h.LinkSetUp(lo); err != nil {
		return fmt.Errorf("internet lo: %w", err)
	}
	p, err := h.LinkByName("njinet-peer")
	if err != nil {
		return fmt.Errorf("internet peer: %w", err)
	}
	if err := h.LinkSetName(p, "eth0"); err != nil {
		return fmt.Errorf("name internet link: %w", err)
	}
	ip, _ := netlink.ParseAddr(internetHost + "/24")
	if err := h.AddrAdd(p, ip); err != nil {
		return fmt.Errorf("address internet host: %w", err)
	}
	if err := h.LinkSetUp(p); err != nil {
		return fmt.Errorf("bring up internet host: %w", err)
	}
	if err := h.RouteAdd(&netlink.Route{LinkIndex: p.Attrs().Index, Gw: net.ParseIP(internetRouter)}); err != nil {
		return fmt.Errorf("internet default route: %w", err)
	}
	return nil
}

func setAddr(link, cidr string) error {
	l, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("%s: %w", link, err)
	}
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("%s: %w", cidr, err)
	}
	if err := netlink.AddrReplace(l, a); err != nil {
		return fmt.Errorf("address %s: %w", link, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("bring up %s: %w", link, err)
	}
	return nil
}

// nat installs the address translation and the inbound filter.
func (w *World) nat(ctx context.Context) error {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip fakecloud {\n")
	fmt.Fprintf(&b, "  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	var subnets []string
	for _, sn := range w.cfg.Subnets {
		subnets = append(subnets, sn.CIDR)
	}
	for _, s := range w.cfg.Slots {
		if s.PublicIP != "" {
			fmt.Fprintf(&b, "    oifname %q ip saddr %s snat to %s\n", internetLink, s.PrivateIP, s.PublicIP)
		}
	}
	if w.cfg.NodePublicIP != "" {
		fmt.Fprintf(&b, "    oifname %q ip saddr != { %s } snat to %s\n", internetLink, strings.Join(subnets, ", "), w.cfg.NodePublicIP)
	}
	fmt.Fprintf(&b, "  }\n  chain forward {\n    type filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %q ct state established,related accept\n", internetLink)
	fmt.Fprintf(&b, "    iifname %q drop\n", internetLink)
	// A slot without an Elastic IP has no way out; nor has a subnet
	// whose route table has no internet gateway.
	for _, s := range w.cfg.Slots {
		if s.PublicIP == "" {
			fmt.Fprintf(&b, "    oifname %q ip saddr %s drop\n", internetLink, s.PrivateIP)
		}
	}
	for i, sn := range w.cfg.Subnets {
		if sn.NoInternet {
			fmt.Fprintf(&b, "    iifname %q oifname %q drop\n", bridgeName(i), internetLink)
		}
	}
	fmt.Fprintf(&b, "  }\n}\n")
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s\n%s", err, out, b.String())
	}
	return nil
}

// Attach implements Links: it moves the slot's near end into the node.
func (w *World) Attach(s *Slot, in *Instance) error {
	i := w.slotIndex(s)
	if err := w.reclaim(i); err != nil {
		return err
	}
	pid, err := nodePID(in.Node)
	if err != nil {
		return err
	}
	ns, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("open %s's namespace: %w", in.Node, err)
	}
	defer func() { _ = ns.Close() }()
	l, err := netlink.LinkByName(slotName(i))
	if err != nil {
		return fmt.Errorf("slot %s: %w", s.ID, err)
	}
	if err := netlink.LinkSetDown(l); err != nil {
		return fmt.Errorf("slot %s down: %w", s.ID, err)
	}
	if err := netlink.LinkSetNsFd(l, int(ns)); err != nil {
		return fmt.Errorf("move slot %s into %s: %w", s.ID, in.Node, err)
	}
	return nil
}

// Detach implements Links: it takes the slot's near end back from
// wherever the node put it.
func (w *World) Detach(s *Slot) error {
	return w.reclaim(w.slotIndex(s))
}

// reclaim brings slot i's near end back into the world, or recreates it
// when the namespace that held it is gone.
func (w *World) reclaim(i int) error {
	s := w.cfg.Slots[i]
	if _, err := netlink.LinkByName(slotName(i)); err == nil {
		return nil
	}
	mac, err := net.ParseMAC(s.MAC)
	if err != nil {
		return fmt.Errorf("slot %s: %w", s.ID, err)
	}
	for _, ns := range namespaces() {
		found, err := w.takeBack(ns, mac, i)
		_ = ns.Close()
		if err != nil {
			return fmt.Errorf("slot %s: %w", s.ID, err)
		}
		if found {
			return nil
		}
	}
	return w.ensurePair(i)
}

func (w *World) takeBack(ns netns.NsHandle, mac net.HardwareAddr, i int) (bool, error) {
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return false, nil //nolint:nilerr // a namespace that went away holds nothing
	}
	defer h.Close()
	links, err := h.LinkList()
	if err != nil {
		return false, nil //nolint:nilerr // as above
	}
	for _, l := range links {
		if l.Type() != "veth" || l.Attrs().HardwareAddr.String() != mac.String() {
			continue
		}
		if err := h.LinkSetDown(l); err != nil {
			return false, fmt.Errorf("down: %w", err)
		}
		if err := h.LinkSetNsFd(l, int(w.world)); err != nil {
			return false, fmt.Errorf("move back: %w", err)
		}
		back, err := netlink.LinkByIndex(l.Attrs().Index)
		if err != nil || back.Attrs().HardwareAddr.String() != mac.String() {
			// The index was taken in the world; find it by MAC.
			back = nil
			all, err := netlink.LinkList()
			if err != nil {
				return false, fmt.Errorf("list: %w", err)
			}
			for _, a := range all {
				if a.Attrs().HardwareAddr.String() == mac.String() && a.Type() == "veth" {
					back = a
				}
			}
			if back == nil {
				return false, errors.New("moved back but not found")
			}
		}
		addrs, _ := netlink.AddrList(back, netlink.FAMILY_ALL)
		for i := range addrs {
			_ = netlink.AddrDel(back, &addrs[i])
		}
		if back.Attrs().Name != slotName(i) {
			if err := netlink.LinkSetName(back, slotName(i)); err != nil {
				return false, fmt.Errorf("rename: %w", err)
			}
		}
		return true, nil
	}
	return false, nil
}

// namespaces returns every network namespace on the host other than the
// world's: those of processes and those pinned by bind mounts, which is
// how the agent keeps its gateway namespace.
func namespaces() []netns.NsHandle {
	self, _ := netns.Get()
	seen := map[string]bool{self.UniqueId(): true}
	_ = self.Close()
	var out []netns.NsHandle
	add := func(ns netns.NsHandle, err error) {
		if err != nil {
			return
		}
		if id := ns.UniqueId(); seen[id] {
			_ = ns.Close()
			return
		}
		seen[ns.UniqueId()] = true
		out = append(out, ns)
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		add(netns.GetFromPid(pid))
		if comm, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "comm")); strings.TrimSpace(string(comm)) == "systemd" {
			for _, m := range nsfsMounts(pid) {
				add(netns.GetFromPath(filepath.Join("/proc", p.Name(), "root", m)))
			}
		}
	}
	return out
}

// nsfsMounts lists the namespace bind mounts in pid's mount namespace.
func nsfsMounts(pid int) []string {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "mountinfo"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// id parent major:minor root mountpoint options... - fstype source super
		fields := strings.Fields(sc.Text())
		for j, x := range fields {
			if x == "-" && j+1 < len(fields) && fields[j+1] == "nsfs" && len(fields) > 4 {
				out = append(out, fields[4])
			}
		}
	}
	return out
}

// nodePID finds the init process of the kind node container named node.
func nodePID(node string) (int, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}
	best := 0
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "comm"))
		if strings.TrimSpace(string(comm)) != "systemd" {
			continue
		}
		host, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "root", "etc", "hostname"))
		if strings.TrimSpace(string(host)) == node && (best == 0 || pid < best) {
			best = pid
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("no running node %s; is the fake in the host's process namespace?", node)
	}
	return best, nil
}
