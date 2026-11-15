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
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

// genevePerPacket is the GENEVE over IPv4 overhead: outer IPv4, UDP and
// GENEVE. The tunnel carries IP packets, not Ethernet frames.
const genevePerPacket = 20 + 8 + 8

// geneveMaxMTU is the kernel's limit for a GENEVE device.
const geneveMaxMTU = 65465

// Dataplane owns the agent's kernel objects on one node.
type Dataplane struct {
	cfg   Config
	log   logr.Logger
	shift int
	key   wgtypes.Key

	mu       sync.Mutex
	gw       *GatewayNS
	lastMark map[uint32]netip.Addr
	failed   map[uint32]bool
}

// New checks the configuration; nothing is changed until Apply.
func New(cfg Config, log logr.Logger) (*Dataplane, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	key, err := loadKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	gw, err := openGatewayNS(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Dataplane{
		cfg: cfg, log: log, shift: bits.TrailingZeros32(cfg.MarkMask), gw: gw, key: key,
		failed: map[uint32]bool{},
	}, nil
}

// Config returns the configuration.
func (d *Dataplane) Config() Config { return d.cfg }

// Gateway is the gateway namespace, or nil when this node serves no slot.
func (d *Dataplane) Gateway() *GatewayNS {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gw
}

func (d *Dataplane) table(mark uint32) int {
	return d.cfg.TableBase + 16 + int(mark>>d.shift)
}

func (d *Dataplane) tgw() int  { return d.cfg.TableBase }
func (d *Dataplane) tret() int { return d.cfg.TableBase + 1 }

func (d *Dataplane) ownsTable(t int) bool {
	return t >= d.cfg.TableBase && t <= d.cfg.TableBase+16+int(d.cfg.MarkMask>>d.shift)
}

// Apply makes the node match want. It is idempotent and safe to call on
// every change; each step replaces what is there.
func (d *Dataplane) Apply(want *agent.Desired) (Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !want.NodeIP.IsValid() {
		return Status{}, errors.New("node has no IPv4 address")
	}
	if err := d.checkHost(); err != nil {
		return Status{}, err
	}
	underlay, err := linkWithAddr(want.NodeIP)
	if err != nil {
		return Status{}, err
	}
	tunnel, err := d.ensureTunnel(underlay.Attrs().MTU - genevePerPacket)
	if err != nil {
		return Status{}, err
	}

	var st Status
	serving := false
	if want.Gateway != nil {
		st, err = d.applyGateway(want, underlay.Attrs().MTU)
		if err != nil {
			return st, err
		}
		serving = st.Serving
	} else if err := d.removeGateway(); err != nil {
		return Status{}, err
	}

	wg, wgGateway, err := d.applyWireGuard(want, underlay.Attrs().MTU)
	if err != nil {
		return st, err
	}
	if err := d.applyRoutes(want, tunnels{geneve: tunnel, wireGuard: wg, gateway: wgGateway}, serving); err != nil {
		return st, err
	}
	c, err := nftables.New()
	if err != nil {
		return st, fmt.Errorf("nftables: %w", err)
	}
	gatewayTunnel := ""
	if serving {
		gatewayTunnel = TunnelLink
		if want.Gateway.WireGuard {
			gatewayTunnel = WireGuardLink
		}
	}
	if err := hostRuleset(c, want, d.cfg.MarkMask, d.cfg, gatewayTunnel); err != nil {
		return st, err
	}
	if err := c.Flush(); err != nil {
		return st, fmt.Errorf("apply host nftables: %w", err)
	}
	d.flushStale(want)
	if err := SaveMarks(d.cfg.StateDir, want.Gateways); err != nil {
		return st, err
	}
	return st, nil
}

// checkHost refuses hosts where replies from the tunnel would be dropped by
// strict reverse path filtering on every interface.
func (d *Dataplane) checkHost() error {
	v, err := readSysctl("net/ipv4/conf/all/rp_filter")
	if err != nil {
		return err
	}
	if v == "1" {
		return errors.New("net.ipv4.conf.all.rp_filter is 1 (strict); set it to 0 or 2, as EKS AMIs do")
	}
	if v, err := readSysctl("net/ipv4/ip_forward"); err != nil || v != "1" {
		return errors.New("net.ipv4.ip_forward must be 1 on a Kubernetes node")
	}
	return nil
}

func linkWithAddr(ip netip.Addr) (netlink.Link, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list addresses: %w", err)
	}
	for _, a := range addrs {
		if got, ok := netip.AddrFromSlice(a.IP); ok && got.Unmap() == ip {
			l, err := netlink.LinkByIndex(a.LinkIndex)
			if err != nil {
				return nil, fmt.Errorf("link of %s: %w", ip, err)
			}
			return l, nil
		}
	}
	return nil, fmt.Errorf("no interface has the node address %s", ip)
}

func (d *Dataplane) ensureTunnel(mtu int) (netlink.Link, error) {
	want := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{Name: TunnelLink, MTU: mtu},
		// Routes, not ARP, pick the far end: the device carries IP packets
		// (Linux 5.18 and later) with per-route tunnel metadata.
		FlowBased: true, InnerProtoInherit: true, Dport: d.cfg.TunnelPort,
	}
	l, err := netlink.LinkByName(TunnelLink)
	switch {
	case isNotFound(err):
		l = nil
	case err != nil:
		return nil, fmt.Errorf("find %s: %w", TunnelLink, err)
	default:
		if g, ok := l.(*netlink.Geneve); !ok || !g.FlowBased || !g.InnerProtoInherit || g.Dport != d.cfg.TunnelPort {
			if err := netlink.LinkDel(l); err != nil {
				return nil, fmt.Errorf("replace %s: %w", TunnelLink, err)
			}
			l = nil
		}
	}
	if l == nil {
		if err := netlink.LinkAdd(want); err != nil {
			return nil, fmt.Errorf("create %s: %w", TunnelLink, err)
		}
		if l, err = netlink.LinkByName(TunnelLink); err != nil {
			return nil, fmt.Errorf("find %s: %w", TunnelLink, err)
		}
	}
	// The kernel caps a collect-metadata GENEVE device at the IPv6 overhead;
	// an underlay with 64 KiB frames, such as a loopback, exceeds it.
	mtu = min(mtu, geneveMaxMTU)
	if l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return nil, fmt.Errorf("set %s MTU %d: %w", TunnelLink, mtu, err)
		}
	}
	addr := &netlink.Addr{IPNet: hostPrefix(d.cfg.TunnelAddr()), Scope: unix.RT_SCOPE_HOST}
	if err := netlink.AddrReplace(l, addr); err != nil {
		return nil, fmt.Errorf("address %s on %s: %w", addr.IPNet, TunnelLink, err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return nil, fmt.Errorf("set %s up: %w", TunnelLink, err)
	}
	if err := writeSysctl("net/ipv4/conf/"+TunnelLink+"/rp_filter", "2"); err != nil {
		return nil, err
	}
	return l, nil
}

func isNotFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

// tunnels are the devices traffic to and from gateways uses.
type tunnels struct {
	// geneve is nj0.
	geneve netlink.Link
	// wireGuard are this node's devices to encrypted gateways, by mark.
	wireGuard map[uint32]netlink.Link
	// gateway is njwg when this node serves an encrypted pool.
	gateway netlink.Link
}

// applyRoutes programs one table per gateway mark, the fwmark rules that
// select them and, on a serving gateway, the tunnel to namespace tables.
func (d *Dataplane) applyRoutes(want *agent.Desired, tun tunnels, serving bool) error {
	tunnel := tun.geneve
	routes := map[int][]netlink.Route{}
	var rules []netlink.Rule
	gwAddr := net.IP(d.cfg.GatewayAddr().AsSlice())
	veth := 0
	if serving {
		l, err := netlink.LinkByName(VethHost)
		if err != nil {
			return fmt.Errorf("find %s: %w", VethHost, err)
		}
		veth = l.Attrs().Index
	}
	for m, ip := range want.Gateways {
		t := d.table(m)
		r := netlink.Route{Table: t, Dst: defaultDst(), LinkIndex: tunnel.Attrs().Index, Encap: &tunnelEncap{ID: VNI, Dst: ip}}
		if _, encrypted := want.WireGuard[m]; encrypted && ip != want.NodeIP {
			// An encrypted gateway is reached only through its WireGuard
			// device; until the device exists (no key yet) the table stays
			// empty, never falling back to GENEVE.
			r = netlink.Route{}
			if l, ok := tun.wireGuard[m]; ok {
				r = netlink.Route{Table: t, Dst: defaultDst(), LinkIndex: l.Attrs().Index}
			}
		}
		if ip == want.NodeIP {
			if !serving {
				// This node's own gateway is not up: leave the table empty so
				// the fwmark rule falls through rather than loop the tunnel.
				r = netlink.Route{}
			} else {
				r = netlink.Route{Table: t, Dst: defaultDst(), LinkIndex: veth, Gw: gwAddr}
			}
		}
		if r.Table != 0 {
			// The tunnel looks up its outer packet with the inner packet's
			// mark: send it past this table, or it loops back into nj0.
			routes[t] = append(routes[t], r, netlink.Route{Table: t, Dst: hostPrefix(ip), Type: unix.RTN_THROW})
		}
		rule := netlink.NewRule()
		rule.Priority, rule.Table, rule.Mark = d.cfg.RulePriority+2, t, m
		mask := d.cfg.MarkMask
		rule.Mask = &mask
		rule.Family = unix.AF_INET
		rules = append(rules, *rule)
	}
	if serving {
		routes[d.tgw()] = []netlink.Route{{Table: d.tgw(), Dst: defaultDst(), LinkIndex: veth, Gw: gwAddr}}
		in := TunnelLink
		for _, n := range want.Nodes {
			if n == want.NodeIP {
				continue
			}
			r := netlink.Route{Table: d.tret(), Dst: hostPrefix(n), LinkIndex: tunnel.Attrs().Index, Encap: &tunnelEncap{ID: VNI, Dst: n}}
			if want.Gateway.WireGuard {
				// WireGuard picks the node's peer by its address. A node
				// without a key has no peer and gets no route.
				if _, ok := want.Gateway.Peers[n]; !ok || tun.gateway == nil {
					continue
				}
				r = netlink.Route{Table: d.tret(), Dst: hostPrefix(n), LinkIndex: tun.gateway.Attrs().Index}
			}
			routes[d.tret()] = append(routes[d.tret()], r)
		}
		if want.Gateway.WireGuard {
			in = WireGuardLink
		}
		for i, iif := range []string{in, VethHost} {
			rule := netlink.NewRule()
			rule.Priority, rule.IifName, rule.Family = d.cfg.RulePriority+i, iif, unix.AF_INET
			rule.Table = d.tgw()
			if iif == VethHost {
				rule.Table = d.tret()
			}
			rules = append(rules, *rule)
		}
	}
	for _, rs := range routes {
		for i := range rs {
			if err := netlink.RouteReplace(&rs[i]); err != nil {
				return fmt.Errorf("route %s table %d: %w", rs[i].Dst, rs[i].Table, err)
			}
		}
	}
	if err := d.pruneRoutes(routes); err != nil {
		return err
	}
	return d.syncRules(rules)
}

func defaultDst() *net.IPNet { return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)} }

func hostPrefix(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(32, 32)}
}

func (d *Dataplane) pruneRoutes(want map[int][]netlink.Route) error {
	have, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	for i := range have {
		r := &have[i]
		if !d.ownsTable(r.Table) {
			continue
		}
		keep := slices.ContainsFunc(want[r.Table], func(w netlink.Route) bool {
			return w.Dst.String() == dstString(r.Dst)
		})
		if !keep {
			if err := netlink.RouteDel(r); err != nil && !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("remove route %s table %d: %w", dstString(r.Dst), r.Table, err)
			}
		}
	}
	return nil
}

func dstString(n *net.IPNet) string {
	if n == nil {
		return defaultDst().String()
	}
	return n.String()
}

func ruleKey(r *netlink.Rule) string {
	mask := uint32(0)
	if r.Mask != nil {
		mask = *r.Mask
	}
	return fmt.Sprintf("%d/%d/%x/%x/%s", r.Priority, r.Table, r.Mark, mask, r.IifName)
}

func (d *Dataplane) syncRules(want []netlink.Rule) error {
	have, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	present := map[string]bool{}
	for i := range have {
		r := &have[i]
		if r.Priority < d.cfg.RulePriority || r.Priority > d.cfg.RulePriority+2 || !d.ownsTable(r.Table) {
			continue
		}
		k := ruleKey(r)
		if slices.ContainsFunc(want, func(w netlink.Rule) bool { return ruleKey(&w) == k }) && !present[k] {
			present[k] = true
			continue
		}
		if err := netlink.RuleDel(r); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove rule %s: %w", k, err)
		}
	}
	for i := range want {
		if present[ruleKey(&want[i])] {
			continue
		}
		if err := netlink.RuleAdd(&want[i]); err != nil {
			return fmt.Errorf("add rule %s: %w", ruleKey(&want[i]), err)
		}
	}
	return nil
}

// markFilter matches conntrack entries carrying one of the marks.
type markFilter struct {
	mask  uint32
	marks map[uint32]bool
}

func (f markFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return f.marks[flow.Mark&f.mask]
}

// anyMark matches conntrack entries carrying any of the agent's mark bits.
type anyMark struct{ mask uint32 }

func (f anyMark) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool { return flow.Mark&f.mask != 0 }

// flushStale removes conntrack entries pinned to a gateway that is gone or
// newly down, so the next packet of each flow is steered afresh instead of
// leaving through the node's own route or into a dead tunnel.
func (d *Dataplane) flushStale(want *agent.Desired) {
	stale := map[uint32]bool{}
	for m, ip := range d.lastMark {
		if want.Gateways[m] != ip {
			stale[m] = true
		}
	}
	failed := map[uint32]bool{}
	for _, m := range want.Failed {
		failed[m] = true
		if !d.failed[m] {
			stale[m] = true
		}
	}
	d.lastMark, d.failed = want.Gateways, failed
	if len(stale) == 0 {
		return
	}
	n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, markFilter{mask: d.cfg.MarkMask, marks: stale})
	if err != nil {
		d.log.Error(err, "flush flows of stale gateways")
		return
	}
	d.log.Info("flushed flows of stale gateways", "flows", n, "marks", len(stale))
}

// SetMarks seeds the previous mark table after a restart, so gateways that
// vanished while the agent was down still have their flows flushed.
func (d *Dataplane) SetMarks(m map[uint32]netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastMark = m
}

// applyGateway builds the gateway namespace around the slot interface.
func (d *Dataplane) applyGateway(want *agent.Desired, underlayMTU int) (Status, error) {
	if d.gw == nil {
		gw, err := createGatewayNS(d.cfg.StateDir)
		if err != nil {
			return Status{}, err
		}
		d.gw = gw
	}
	nh, err := netlink.NewHandleAt(d.gw.ns)
	if err != nil {
		return Status{}, fmt.Errorf("netlink in gateway namespace: %w", err)
	}
	defer nh.Close()

	if err := d.gw.Do(func() error {
		for k, v := range map[string]string{
			"net/ipv4/ip_forward":                   "1",
			"net/ipv4/conf/all/rp_filter":           "1",
			"net/ipv4/conf/default/rp_filter":       "1",
			"net/ipv6/conf/all/disable_ipv6":        "1",
			"net/ipv6/conf/default/disable_ipv6":    "1",
			"net/ipv4/conf/all/accept_redirects":    "0",
			"net/ipv4/conf/all/send_redirects":      "0",
			"net/ipv4/conf/all/accept_source_route": "0",
		} {
			if err := writeSysctl(k, v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return Status{}, err
	}
	if err := d.ensureVeth(nh, underlayMTU); err != nil {
		return Status{}, err
	}
	if lo, err := nh.LinkByName("lo"); err == nil {
		_ = nh.LinkSetUp(lo)
	}

	slot, st, err := d.claimSlot(nh, want.Gateway.MAC)
	if err != nil || slot == nil {
		return st, err
	}
	if err := d.configureSlot(nh, slot, want); err != nil {
		return Status{}, err
	}
	c, err := nftables.New(nftables.WithNetNSFd(d.gw.Fd()))
	if err != nil {
		return Status{}, fmt.Errorf("nftables in gateway namespace: %w", err)
	}
	if err := gatewayRuleset(c, want, d.cfg); err != nil {
		return Status{}, err
	}
	if err := c.Flush(); err != nil {
		return Status{}, fmt.Errorf("apply gateway nftables: %w", err)
	}
	return Status{Serving: true}, nil
}

func (d *Dataplane) ensureVeth(nh *netlink.Handle, mtu int) error {
	host, err := netlink.LinkByName(VethHost)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("find %s: %w", VethHost, err)
	}
	if _, perr := nh.LinkByName(VethGateway); host == nil || perr != nil {
		if host != nil {
			_ = netlink.LinkDel(host)
		}
		v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: VethHost, MTU: mtu}, PeerName: VethGateway, PeerNamespace: netlink.NsFd(d.gw.Fd())}
		if err := netlink.LinkAdd(v); err != nil {
			return fmt.Errorf("create %s: %w", VethHost, err)
		}
		if host, err = netlink.LinkByName(VethHost); err != nil {
			return fmt.Errorf("find %s: %w", VethHost, err)
		}
	}
	peer, err := nh.LinkByName(VethGateway)
	if err != nil {
		return fmt.Errorf("find %s: %w", VethGateway, err)
	}
	for _, s := range []struct {
		h    *netlink.Handle
		l    netlink.Link
		addr netip.Addr
	}{{nil, host, d.cfg.HostAddr()}, {nh, peer, d.cfg.GatewayAddr()}} {
		h := s.h
		if h == nil {
			h = &netlink.Handle{}
		}
		if s.l.Attrs().MTU != mtu {
			if err := h.LinkSetMTU(s.l, mtu); err != nil {
				return fmt.Errorf("set %s MTU: %w", s.l.Attrs().Name, err)
			}
		}
		a := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(s.addr.AsSlice()), Mask: net.CIDRMask(d.cfg.Link.Bits(), 32)}}
		if err := h.AddrReplace(s.l, a); err != nil {
			return fmt.Errorf("address %s on %s: %w", a, s.l.Attrs().Name, err)
		}
		if err := h.LinkSetUp(s.l); err != nil {
			return fmt.Errorf("set %s up: %w", s.l.Attrs().Name, err)
		}
	}
	return writeSysctl("net/ipv4/conf/"+VethHost+"/rp_filter", "2")
}

// claimSlot moves the slot interface into the gateway namespace. The cloud
// attaches it to the host, where nothing may use it.
func (d *Dataplane) claimSlot(nh *netlink.Handle, mac string) (netlink.Link, Status, error) {
	if l, err := nh.LinkByName(EgressLink); err == nil {
		if strings.EqualFold(l.Attrs().HardwareAddr.String(), mac) {
			return l, Status{}, nil
		}
		return nil, Status{Reason: fmt.Sprintf("%s in the gateway namespace has MAC %s, want %s", EgressLink, l.Attrs().HardwareAddr, mac)}, nil
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, Status{}, fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		// The MAC is the slot's identity; the cloud assigns it uniquely.
		if !strings.EqualFold(l.Attrs().HardwareAddr.String(), mac) {
			continue
		}
		if err := netlink.LinkSetDown(l); err != nil {
			return nil, Status{}, fmt.Errorf("set slot interface down: %w", err)
		}
		if err := netlink.LinkSetNsFd(l, d.gw.Fd()); err != nil {
			return nil, Status{}, fmt.Errorf("move slot interface into the gateway namespace: %w", err)
		}
		moved, err := nh.LinkByIndex(l.Attrs().Index)
		if err != nil {
			moved, err = findByMAC(nh, mac)
			if err != nil {
				return nil, Status{}, err
			}
		}
		if err := nh.LinkSetName(moved, EgressLink); err != nil {
			return nil, Status{}, fmt.Errorf("rename slot interface: %w", err)
		}
		d.log.Info("slot interface moved into the gateway namespace", "mac", mac, "was", l.Attrs().Name)
		l, err := nh.LinkByName(EgressLink)
		if err != nil {
			return nil, Status{}, fmt.Errorf("find %s: %w", EgressLink, err)
		}
		return l, Status{}, nil
	}
	return nil, Status{Reason: fmt.Sprintf("slot interface %s is not attached to this node yet", mac)}, nil
}

func findByMAC(nh *netlink.Handle, mac string) (netlink.Link, error) {
	links, err := nh.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list gateway links: %w", err)
	}
	for _, l := range links {
		if strings.EqualFold(l.Attrs().HardwareAddr.String(), mac) {
			return l, nil
		}
	}
	return nil, fmt.Errorf("slot interface %s vanished during the move", mac)
}

func (d *Dataplane) configureSlot(nh *netlink.Handle, slot netlink.Link, want *agent.Desired) error {
	g := want.Gateway
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(g.Address.Addr().AsSlice()), Mask: net.CIDRMask(g.Address.Bits(), 32)}}
	if err := nh.AddrReplace(slot, addr); err != nil {
		return fmt.Errorf("address %s on %s: %w", addr, EgressLink, err)
	}
	have, err := nh.AddrList(slot, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list %s addresses: %w", EgressLink, err)
	}
	for i := range have {
		if !have[i].IP.Equal(addr.IP) {
			if err := nh.AddrDel(slot, &have[i]); err != nil {
				return fmt.Errorf("remove stale address from %s: %w", EgressLink, err)
			}
		}
	}
	if err := nh.LinkSetUp(slot); err != nil {
		return fmt.Errorf("set %s up: %w", EgressLink, err)
	}
	if err := d.gw.Do(func() error {
		return writeSysctl("net/ipv4/conf/"+EgressLink+"/rp_filter", "1")
	}); err != nil {
		return err
	}

	peer, err := nh.LinkByName(VethGateway)
	if err != nil {
		return fmt.Errorf("find %s: %w", VethGateway, err)
	}
	host := net.IP(d.cfg.HostAddr().AsSlice())
	want4 := []netlink.Route{{Dst: defaultDst(), LinkIndex: slot.Attrs().Index, Gw: net.IP(g.Router.AsSlice())}}
	for _, n := range want.Nodes {
		want4 = append(want4, netlink.Route{Dst: hostPrefix(n), LinkIndex: peer.Attrs().Index, Gw: host})
	}
	for i := range want4 {
		if err := nh.RouteReplace(&want4[i]); err != nil {
			return fmt.Errorf("gateway route %s: %w", want4[i].Dst, err)
		}
	}
	routes, err := nh.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list gateway routes: %w", err)
	}
	for i := range routes {
		r := &routes[i]
		if r.Gw == nil || r.Protocol == unix.RTPROT_KERNEL {
			continue // connected routes belong to the addresses
		}
		if !slices.ContainsFunc(want4, func(w netlink.Route) bool { return w.Dst.String() == dstString(r.Dst) }) {
			if err := nh.RouteDel(r); err != nil {
				return fmt.Errorf("remove stale gateway route %s: %w", dstString(r.Dst), err)
			}
		}
	}
	return nil
}

// removeGateway undoes the gateway role. The namespace stays while the slot
// interface is still inside it: removing it would hand the interface back to
// the host. The controller detaches the interface first.
func (d *Dataplane) removeGateway() error {
	if l, err := netlink.LinkByName(VethHost); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("remove %s: %w", VethHost, err)
		}
	}
	if d.gw == nil {
		return nil
	}
	nh, err := netlink.NewHandleAt(d.gw.ns)
	if err != nil {
		return fmt.Errorf("netlink in gateway namespace: %w", err)
	}
	defer nh.Close()
	links, err := nh.LinkList()
	if err != nil {
		return fmt.Errorf("list gateway links: %w", err)
	}
	for _, l := range links {
		// Only an Ethernet device with a real address can be the slot; the
		// kernel's fallback tunnel devices (tunl0, gre0, ...) have none.
		if mac := l.Attrs().HardwareAddr; l.Attrs().Name != VethGateway && len(mac) == 6 && !bytes.Equal(mac, make([]byte, 6)) {
			d.log.Info("gateway namespace still holds the slot interface; waiting for it to be detached", "link", l.Attrs().Name)
			return nil
		}
	}
	if err := d.gw.remove(); err != nil {
		return err
	}
	d.gw = nil
	return nil
}

// Teardown removes every kernel object the agent owns except a gateway
// namespace that still holds a slot interface. It is for uninstall.
func (d *Dataplane) Teardown() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var errs []error
	errs = append(errs, d.removeGateway(), d.syncRules(nil), d.pruneRoutes(nil))
	if c, err := nftables.New(); err == nil {
		c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName})
		if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("remove nftables table: %w", err))
		}
	}
	if l, err := netlink.LinkByName(TunnelLink); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", TunnelLink, err))
		}
	}
	errs = append(errs, d.removeWireGuard(nil))
	if err := os.Remove(d.cfg.StateDir + "/" + keyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove WireGuard key: %w", err))
	}
	if _, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, anyMark{d.cfg.MarkMask}); err != nil {
		errs = append(errs, fmt.Errorf("flush steered flows: %w", err))
	}
	if err := os.Remove(d.cfg.StateDir + "/" + marksFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove mark table: %w", err))
	}
	return errors.Join(errs...)
}
